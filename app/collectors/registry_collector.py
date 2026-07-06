"""
registry_collector.py
=====================
Monitors Windows Registry for suspicious autorun entries,
service modifications, and security policy changes.
Uses both winreg (live) and Security event log (4657).
"""
import pandas as pd
import winreg
import win32evtlog
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET

from app.engines.normalization_engine import normalize_event
from app.database.database import get_cursor, update_cursor


def _soc_log(msg: str):
    print(msg)
    try:
        from app.websocket_manager import manager
        manager.send_console(str(msg))
    except Exception:
        pass


# High-value registry paths to monitor
MONITORED_KEYS = {
    winreg.HKEY_CURRENT_USER: [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ],
    winreg.HKEY_LOCAL_MACHINE: [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        r"SYSTEM\CurrentControlSet\Services",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    ]
}

HIVE_NAMES = {
    winreg.HKEY_CURRENT_USER:   "HKCU",
    winreg.HKEY_LOCAL_MACHINE:  "HKLM",
}


def read_registry_logs(hours=720):
    logs = []

    # Part 1: Live registry scan of high-value keys
    for hive, paths in MONITORED_KEYS.items():
        hive_name = HIVE_NAMES.get(hive, "HKEY")
        for key_path in paths:
            try:
                key = winreg.OpenKey(hive, key_path)
                i   = 0
                while True:
                    try:
                        name, value, reg_type = winreg.EnumValue(key, i)
                        # Determine severity based on path
                        if "Image File Execution Options" in key_path:
                            severity = "CRITICAL"
                            category = "Defense Evasion"
                            desc     = f"IFEO hijack entry: {name} = {str(value)[:200]}"
                        elif "Winlogon" in key_path:
                            severity = "CRITICAL"
                            category = "Persistence"
                            desc     = f"Winlogon entry: {name} = {str(value)[:200]}"
                        elif "Services" in key_path:
                            severity = "HIGH"
                            category = "Persistence"
                            desc     = f"Service registry: {name} = {str(value)[:200]}"
                        else:
                            severity = "HIGH"
                            category = "Persistence"
                            desc     = f"Autorun entry: {name} = {str(value)[:200]}"

                        logs.append(normalize_event(
                            source      = "Registry",
                            event_id    = 4657,
                            description = desc,
                            raw_log     = f"{hive_name}\\{key_path}\\{name}:{value}",
                            severity    = severity,
                            category    = category,
                            log_type    = "HIDS"
                        ))
                        i += 1
                    except OSError:
                        break
            except Exception:
                pass

    # Part 2: Security event log for registry changes (Event 4657)
    cursor_data    = get_cursor("registry_evt")
    last_record_id = 0
    if cursor_data:
        try:
            last_record_id = int(cursor_data["last_event_record_id"])
        except Exception:
            last_record_id = 0

    cutoff = datetime.now() - timedelta(hours=hours)

    try:
        handle = win32evtlog.EvtQuery(
            "Security",
            win32evtlog.EvtQueryReverseDirection,
            "*[System[EventID=4657]]"
        )
        latest_record_id = last_record_id

        while True:
            events = win32evtlog.EvtNext(handle, 50)
            if not events:
                break

            for event in events:
                try:
                    xml_str   = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                    root      = ET.fromstring(xml_str)
                    system    = root.find("System")
                    if system is None:
                        continue

                    record_id = int((system.find("EventRecordID") or {}).text or 0)
                    if record_id <= last_record_id:
                        continue

                    time_node   = system.find("TimeCreated")
                    system_time = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
                    if system_time:
                        event_time = datetime.fromisoformat(
                            system_time.replace("Z", "+00:00")
                        ).replace(tzinfo=None)
                        if event_time < cutoff:
                            continue

                    if record_id > latest_record_id:
                        latest_record_id = record_id

                    logs.append(normalize_event(
                        source      = "Registry",
                        event_id    = 4657,
                        description = "Registry value modified (Security Audit)",
                        raw_log     = xml_str[:2000],
                        severity    = "HIGH",
                        category    = "Defense Evasion",
                        log_type    = "HIDS"
                    ))
                except Exception:
                    pass

        if latest_record_id > last_record_id:
            update_cursor("registry_evt", latest_record_id, datetime.now().isoformat())

    except Exception:
        pass

    _soc_log(f"[REGISTRY] Entries collected: {len(logs)}")
    return pd.DataFrame(logs)
