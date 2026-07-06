"""
filesystem_collector.py
========================
Monitors C: drive for file system changes in last 24 hours.

Uses Windows Security Event Log:
  4663 — File accessed / modified / created
  4660 — File deleted
  4656 — File/object handle opened
  4670 — File permissions changed

Also scans common attack locations directly:
  C:\\Temp, C:\\Users\\Public, C:\\Windows\\Temp,
  C:\\ProgramData, Downloads, Desktop folders

Detects:
  - New files created
  - Files deleted
  - Files modified (write access)
  - Files moved/renamed
  - Suspicious file types (.exe, .bat, .ps1, .vbs, .dll)
"""

import os
import subprocess
import pandas as pd
import win32evtlog
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

from app.database.database import get_cursor, update_cursor

try:
    from app.websocket_manager import manager
    def _soc_log(msg):
        print(msg)
        try: manager.send_console(str(msg))
        except: pass
except Exception:
    def _soc_log(msg): print(msg)


# File types worth flagging
SUSPICIOUS_EXTENSIONS = {
    '.exe':  ("Executable created",     "HIGH",     "Execution"),
    '.dll':  ("DLL file created",       "HIGH",     "Defense Evasion"),
    '.bat':  ("Batch script created",   "HIGH",     "Execution"),
    '.ps1':  ("PowerShell script",      "HIGH",     "Execution"),
    '.vbs':  ("VBScript created",       "HIGH",     "Execution"),
    '.js':   ("JavaScript file",        "MEDIUM",   "Execution"),
    '.hta':  ("HTA file created",       "HIGH",     "Execution"),
    '.lnk':  ("Shortcut created",       "MEDIUM",   "Persistence"),
    '.zip':  ("Archive created",        "MEDIUM",   "Collection"),
    '.rar':  ("Archive created",        "MEDIUM",   "Collection"),
    '.7z':   ("Archive created",        "MEDIUM",   "Collection"),
    '.tmp':  ("Temp file created",      "LOW",      "Others"),
}

# Monitored paths for direct filesystem scan
MONITORED_PATHS = [
    r"C:\Temp",
    r"C:\Windows\Temp",
    r"C:\Users\Public",
    r"C:\ProgramData",
]

# Add user-specific paths
try:
    username = os.environ.get("USERNAME", "")
    if username:
        MONITORED_PATHS.extend([
            rf"C:\Users\{username}\Desktop",
            rf"C:\Users\{username}\Downloads",
            rf"C:\Users\{username}\AppData\Local\Temp",
        ])
except Exception:
    pass


def _read_security_file_events(hours=24):
    """Read Security log for file access events (4663, 4660, 4656, 4670)."""
    events = []
    cutoff = datetime.now() - timedelta(hours=hours)

    cursor_data    = get_cursor("filesystem_sec")
    last_record_id = 0
    if cursor_data:
        try:
            last_record_id = int(cursor_data["last_event_record_id"])
        except Exception:
            pass

    FILE_EVENT_IDS = {
        4663: "File accessed",
        4660: "File deleted",
        4656: "File handle opened",
        4670: "File permissions changed",
    }

    try:
        handle = win32evtlog.EvtQuery(
            "Security",
            win32evtlog.EvtQueryReverseDirection,
            "*[System[EventID=4663 or EventID=4660 or EventID=4656 or EventID=4670]]"
        )
        latest_id = last_record_id
        count = 0

        while count < 2000:
            batch = win32evtlog.EvtNext(handle, 50)
            if not batch:
                break
            for event in batch:
                try:
                    xml_str = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                    root    = ET.fromstring(xml_str)
                    system  = root.find("System")
                    if system is None:
                        continue

                    rec_el = system.find("EventRecordID")
                    if rec_el is None:
                        continue
                    rec_id = int(rec_el.text or 0)
                    if rec_id <= last_record_id:
                        continue

                    eid_el = system.find("EventID")
                    if eid_el is None:
                        continue
                    eid = int(eid_el.text or 0)

                    # Time filter
                    time_node = system.find("TimeCreated")
                    ts_str    = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
                    event_time = None
                    if ts_str:
                        try:
                            event_time = datetime.fromisoformat(ts_str.replace("Z","").replace("+00:00",""))
                            if event_time < cutoff:
                                continue
                        except Exception:
                            pass

                    # Extract file path
                    obj_name = ""
                    for data in root.findall(".//Data"):
                        if data.attrib.get("Name") in ("ObjectName", "FileName"):
                            obj_name = data.text or ""
                            break

                    # Skip non-file objects and system noise
                    if not obj_name or "\\Pipe\\" in obj_name or "\\REGISTRY\\" in obj_name:
                        continue
                    if obj_name in ("\\", "C:\\", "C:\\Windows\\"):
                        continue

                    # Extract username
                    subject_user = ""
                    for data in root.findall(".//Data"):
                        if data.attrib.get("Name") == "SubjectUserName":
                            subject_user = data.text or ""
                            break

                    # Extract access mask to determine operation
                    access_mask = ""
                    for data in root.findall(".//Data"):
                        if data.attrib.get("Name") == "AccessMask":
                            access_mask = data.text or ""
                            break

                    # Map event to action
                    if eid == 4660:
                        action   = "File Deleted"
                        severity = "HIGH"
                        category = "Defense Evasion"
                    elif eid == 4670:
                        action   = "File Permissions Changed"
                        severity = "HIGH"
                        category = "Defense Evasion"
                    else:
                        # 4663/4656: check access type
                        if "0x2" in access_mask or "0x40" in access_mask:
                            action   = "File Modified (Write)"
                            severity = "MEDIUM"
                            category = "Collection"
                        else:
                            action   = "File Accessed (Read)"
                            severity = "LOW"
                            category = "Collection"

                    # Escalate for suspicious extensions
                    ext = Path(obj_name).suffix.lower()
                    if ext in SUSPICIOUS_EXTENSIONS:
                        ext_desc, ext_sev, ext_cat = SUSPICIOUS_EXTENSIONS[ext]
                        action   = f"{action} — {ext_desc}"
                        severity = ext_sev
                        category = ext_cat

                    if rec_id > latest_id:
                        latest_id = rec_id

                    ts_display = event_time.strftime("%Y-%m-%d %H:%M:%S") if event_time else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    events.append({
                        "timestamp":   datetime.now().isoformat(),
                        "source":      "FileSystem",
                        "event_id":    eid,
                        "type":        action,
                        "severity":    severity,
                        "category":    category,
                        "log_source":  "HIDS",
                        "description": f"{action} | file={obj_name} | user={subject_user} | time={ts_display}",
                        "log_type":    "HIDS",
                    })
                    count += 1

                except Exception:
                    continue

        if latest_id > last_record_id:
            update_cursor("filesystem_sec", latest_id, datetime.now().isoformat())

    except Exception as e:
        _soc_log(f"[FILESYSTEM] Security log read error: {e}")

    return events


def _scan_monitored_paths(hours=24):
    """Directly scan monitored folders for recently changed files."""
    events = []
    cutoff = datetime.now() - timedelta(hours=hours)

    for folder in MONITORED_PATHS:
        try:
            if not os.path.exists(folder):
                continue
            for root_dir, dirs, files in os.walk(folder):
                # Skip deep recursion
                depth = root_dir.replace(folder, "").count(os.sep)
                if depth > 3:
                    dirs.clear()
                    continue
                for fname in files:
                    try:
                        fpath = os.path.join(root_dir, fname)
                        stat  = os.stat(fpath)
                        mtime = datetime.fromtimestamp(stat.st_mtime)
                        ctime = datetime.fromtimestamp(stat.st_ctime)

                        # Only files modified/created in cutoff window
                        if mtime < cutoff and ctime < cutoff:
                            continue

                        ext = Path(fname).suffix.lower()
                        is_new = ctime >= cutoff

                        if ext in SUSPICIOUS_EXTENSIONS:
                            ext_desc, severity, category = SUSPICIOUS_EXTENSIONS[ext]
                            action = f"{'New' if is_new else 'Modified'} suspicious file — {ext_desc}"
                        else:
                            severity = "LOW" if not is_new else "MEDIUM"
                            category = "Collection"
                            action   = f"{'New file created' if is_new else 'File modified'}"

                        events.append({
                            "timestamp":   datetime.now().isoformat(),
                            "source":      "FileSystem",
                            "event_id":    9001,
                            "type":        action,
                            "severity":    severity,
                            "category":    category,
                            "log_source":  "HIDS",
                            "description": f"{action} | path={fpath} | size={stat.st_size}B | modified={mtime.strftime('%Y-%m-%d %H:%M:%S')}",
                            "log_type":    "HIDS",
                        })
                    except Exception:
                        continue
        except Exception:
            continue

    return events


def read_filesystem_logs(hours=24):
    """Main entry — collect all filesystem change events."""
    all_events = []

    # 1. Security event log (file audit events)
    sec_events = _read_security_file_events(hours=hours)
    all_events.extend(sec_events)

    # 2. Direct folder scan of monitored paths
    path_events = _scan_monitored_paths(hours=hours)
    all_events.extend(path_events)

    # Deduplicate by description prefix
    seen = set()
    unique = []
    for e in all_events:
        key = e["description"][:100]
        if key not in seen:
            seen.add(key)
            unique.append(e)

    _soc_log(f"[FILESYSTEM] {len(unique)} file change events detected")

    if not unique:
        return pd.DataFrame()

    return pd.DataFrame(unique)