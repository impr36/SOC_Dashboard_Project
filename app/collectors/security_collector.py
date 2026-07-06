"""
security_collector.py
=====================
Collects Windows Security event log entries.
Captures: logins, failures, privilege use, account changes,
          file access, process creation, policy changes.
This is the most important log for SOC detection.
"""
import pandas as pd
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


CHANNEL = "Security"

# Comprehensive Windows Security event mapping
SECURITY_EVENTS = {
    # Authentication
    4624: ("Successful logon",                      "LOW",      "Authentication"),
    4625: ("Failed logon attempt",                  "MEDIUM",   "Authentication"),
    4627: ("Group membership queried",              "LOW",      "Discovery"),
    4634: ("Account logged off",                    "LOW",      "Authentication"),
    4647: ("User initiated logoff",                 "LOW",      "Authentication"),
    4648: ("Logon with explicit credentials",       "HIGH",     "Credential Access"),
    4649: ("Replay attack detected",                "CRITICAL", "Credential Access"),
    4672: ("Special privileges assigned to logon",  "HIGH",     "Privilege Escalation"),
    4673: ("Privileged service called",             "MEDIUM",   "Privilege Escalation"),
    4675: ("SIDs filtered",                         "MEDIUM",   "Privilege Escalation"),
    # Account management
    4720: ("User account created",                  "HIGH",     "Persistence"),
    4722: ("User account enabled",                  "MEDIUM",   "Persistence"),
    4723: ("Password change attempted",             "MEDIUM",   "Credential Access"),
    4724: ("Password reset attempted",              "HIGH",     "Credential Access"),
    4725: ("User account disabled",                 "HIGH",     "Defense Evasion"),
    4726: ("User account deleted",                  "HIGH",     "Defense Evasion"),
    4728: ("Member added to security group",        "HIGH",     "Privilege Escalation"),
    4729: ("Member removed from security group",    "MEDIUM",   "Privilege Escalation"),
    4732: ("Member added to local group",           "HIGH",     "Privilege Escalation"),
    4733: ("Member removed from local group",       "MEDIUM",   "Privilege Escalation"),
    4737: ("Security group changed",                "HIGH",     "Privilege Escalation"),
    4738: ("User account changed",                  "MEDIUM",   "Defense Evasion"),
    4740: ("User account locked out",               "HIGH",     "Authentication"),
    4756: ("Member added to universal group",       "HIGH",     "Privilege Escalation"),
    4765: ("SID history added to account",          "CRITICAL", "Privilege Escalation"),
    4767: ("User account unlocked",                 "MEDIUM",   "Authentication"),
    4781: ("Account name changed",                  "HIGH",     "Defense Evasion"),
    # Process
    4688: ("New process created",                   "LOW",      "Execution"),
    4689: ("Process exited",                        "LOW",      "Execution"),
    # Scheduled tasks
    4698: ("Scheduled task created",                "HIGH",     "Persistence"),
    4699: ("Scheduled task deleted",                "HIGH",     "Defense Evasion"),
    4700: ("Scheduled task enabled",                "HIGH",     "Persistence"),
    4701: ("Scheduled task disabled",               "MEDIUM",   "Defense Evasion"),
    4702: ("Scheduled task updated",                "HIGH",     "Persistence"),
    # Services
    4697: ("Service installed",                     "CRITICAL", "Persistence"),
    7045: ("New service installed",                 "CRITICAL", "Persistence"),
    # Policy
    4704: ("User right assigned",                   "HIGH",     "Privilege Escalation"),
    4705: ("User right removed",                    "MEDIUM",   "Privilege Escalation"),
    4706: ("New trust to domain created",           "CRITICAL", "Privilege Escalation"),
    4713: ("Kerberos policy changed",               "HIGH",     "Defense Evasion"),
    4714: ("Encrypted data recovery policy changed","HIGH",     "Defense Evasion"),
    4715: ("Audit policy changed",                  "HIGH",     "Defense Evasion"),
    4716: ("Trusted domain information changed",    "HIGH",     "Defense Evasion"),
    4719: ("System audit policy changed",           "HIGH",     "Defense Evasion"),
    4739: ("Domain policy changed",                 "HIGH",     "Defense Evasion"),
    4817: ("Auditing settings changed on object",   "HIGH",     "Defense Evasion"),
    # Kerberos
    4768: ("Kerberos TGT requested",               "LOW",      "Authentication"),
    4769: ("Kerberos service ticket requested",     "LOW",      "Authentication"),
    4770: ("Kerberos service ticket renewed",       "LOW",      "Authentication"),
    4771: ("Kerberos pre-auth failed",              "HIGH",     "Authentication"),
    4776: ("NTLM authentication attempted",         "LOW",      "Authentication"),
    4777: ("Domain controller could not validate",  "HIGH",     "Authentication"),
    # Object access
    4660: ("Object deleted",                        "MEDIUM",   "Collection"),
    4663: ("Object access attempted",               "LOW",      "Collection"),
    4670: ("Object permissions changed",            "HIGH",     "Defense Evasion"),
    # Network
    4946: ("Firewall rule added",                   "HIGH",     "Defense Evasion"),
    4947: ("Firewall rule modified",                "HIGH",     "Defense Evasion"),
    4948: ("Firewall rule deleted",                 "HIGH",     "Defense Evasion"),
    5140: ("Network share accessed",                "MEDIUM",   "Lateral Movement"),
    5145: ("Network share checked",                 "LOW",      "Discovery"),
    5156: ("Network connection allowed",            "LOW",      "Network"),
    5157: ("Network connection blocked",            "LOW",      "Network"),
    # Logon types
    4778: ("Session reconnected",                   "LOW",      "Authentication"),
    4779: ("Session disconnected",                  "LOW",      "Authentication"),
    # Audit log
    1100: ("Event log service shutdown",            "HIGH",     "Defense Evasion"),
    1102: ("Security audit log cleared",            "CRITICAL", "Defense Evasion"),
    1104: ("Security log is full",                  "HIGH",     "Defense Evasion"),
}


def _extract_field(root, field_name):
    for item in root.findall(".//Data"):
        if item.attrib.get("Name", "") == field_name:
            return item.text or ""
    return ""


def read_security_logs(hours=720):
    logs = []

    cursor_data    = get_cursor("security")
    last_record_id = 0
    if cursor_data:
        try:
            last_record_id = int(cursor_data["last_event_record_id"])
        except Exception:
            last_record_id = 0

    cutoff = datetime.now() - timedelta(hours=hours)

    try:
        handle = win32evtlog.EvtQuery(
            CHANNEL,
            win32evtlog.EvtQueryReverseDirection,
            "*"
        )

        processed        = 0
        max_events       = 50000
        latest_record_id = last_record_id

        while True:
            events = win32evtlog.EvtNext(handle, 100)
            if not events or processed >= max_events:
                break

            for event in events:
                try:
                    xml_str = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                    root    = ET.fromstring(xml_str)
                    system  = root.find("System")
                    if system is None:
                        continue

                    record_id_el = system.find("EventRecordID")
                    if record_id_el is None:
                        continue
                    record_id = int(record_id_el.text or 0)

                    if record_id <= last_record_id:
                        continue

                    event_id_el = system.find("EventID")
                    if event_id_el is None:
                        continue
                    event_id = int(event_id_el.text or 0)

                    # Only process events we care about
                    if event_id not in SECURITY_EVENTS:
                        continue

                    # Time filter
                    time_node   = system.find("TimeCreated")
                    system_time = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
                    if system_time:
                        try:
                            event_time = datetime.fromisoformat(
                                system_time.replace("Z", "+00:00")
                            ).replace(tzinfo=None)
                            if event_time < cutoff:
                                continue
                        except Exception:
                            pass

                    description, severity, category = SECURITY_EVENTS[event_id]

                    # Enrich description with key fields
                    username  = _extract_field(root, "TargetUserName") or _extract_field(root, "SubjectUserName")
                    ip        = _extract_field(root, "IpAddress")
                    proc      = _extract_field(root, "ProcessName")
                    task_name = _extract_field(root, "TaskName")

                    extra = []
                    if username and username not in ("-", ""):
                        extra.append(f"user={username}")
                    if ip and ip not in ("-", "::1", "127.0.0.1", ""):
                        extra.append(f"ip={ip}")
                    if proc and proc not in ("-", ""):
                        extra.append(f"proc={proc.split(chr(92))[-1]}")
                    if task_name:
                        extra.append(f"task={task_name}")

                    full_desc = description
                    if extra:
                        full_desc += " | " + " | ".join(extra)

                    # Escalate severity for high-risk events
                    if event_id == 4625:
                        logon_type = _extract_field(root, "LogonType")
                        if logon_type in ("3", "10"):
                            severity = "HIGH"

                    if record_id > latest_record_id:
                        latest_record_id = record_id

                    logs.append(normalize_event(
                        source      = "Security",
                        event_id    = event_id,
                        description = full_desc,
                        raw_log     = xml_str[:2000],
                        severity    = severity,
                        category    = category,
                        computer    = _extract_field(root, "WorkstationName"),
                        user        = username,
                        process_name= proc,
                        ip_address  = ip,
                        log_type    = "HIDS"
                    ))

                    processed += 1

                except Exception:
                    pass

        if logs and latest_record_id > last_record_id:
            update_cursor("security", latest_record_id, datetime.now().isoformat())

        _soc_log(f"[SECURITY] Logs collected: {len(logs)}")

    except Exception as e:
        _soc_log(f"[SECURITY COLLECTOR ERROR] {e}")

    return pd.DataFrame(logs)
