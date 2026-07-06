import pandas as pd
import win32evtlog
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET

from app.engines.normalization_engine import normalize_event
from app.database.database import get_cursor, update_cursor


# =========================================
# SOC TERMINAL LOGGER
# =========================================
def _soc_log(msg: str):
    print(msg)
    try:
        from app.websocket_manager import manager
        manager.send_console(str(msg))
    except Exception:
        pass


CHANNEL = "Microsoft-Windows-Windows Defender/Operational"

# Defender event IDs and what they mean
DEFENDER_EVENTS = {
    1000: ("Defender scan started",               "LOW",      "Malware"),
    1001: ("Defender scan completed",             "LOW",      "Malware"),
    1002: ("Defender scan cancelled",             "MEDIUM",   "Malware"),
    1006: ("Defender found malware",              "CRITICAL", "Malware"),
    1007: ("Defender took action on malware",     "CRITICAL", "Malware"),
    1008: ("Defender failed to take action",      "HIGH",     "Malware"),
    1013: ("Defender scan history deleted",       "HIGH",     "Defense Evasion"),
    1015: ("Defender suspicious behaviour",       "HIGH",     "Execution"),
    1116: ("Defender detected malware",           "HIGH",     "Malware"),
    1117: ("Defender action on detected malware", "HIGH",     "Malware"),
    1118: ("Defender remediation failed",         "HIGH",     "Malware"),
    1119: ("Defender remediation succeeded",      "LOW",      "Malware"),
    1120: ("Defender quarantine released",        "MEDIUM",   "Malware"),
    2000: ("Defender signature updated",          "LOW",      "System"),
    2001: ("Defender signature update failed",    "MEDIUM",   "System"),
    2002: ("Defender realtime enabled",           "LOW",      "System"),
    2003: ("Defender realtime disabled",          "CRITICAL", "Defense Evasion"),
    2004: ("Defender configuration changed",      "HIGH",     "Defense Evasion"),
    2005: ("Defender platform updated",           "LOW",      "System"),
    3002: ("Defender realtime protection failed", "HIGH",     "Defense Evasion"),
    3004: ("Defender realtime engine failed",     "HIGH",     "Defense Evasion"),
    5001: ("Defender realtime disabled",          "CRITICAL", "Defense Evasion"),
    5004: ("Defender realtime config changed",    "HIGH",     "Defense Evasion"),
    5007: ("Defender configuration changed",      "HIGH",     "Defense Evasion"),
    5010: ("Defender antispyware disabled",       "CRITICAL", "Defense Evasion"),
    5012: ("Defender antivirus disabled",         "CRITICAL", "Defense Evasion"),
}


def read_defender_logs(hours=720):
    logs = []

    # Use cursor to only get NEW events since last scan
    cursor_data     = get_cursor("defender")
    last_record_id  = 0
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

        latest_record_id = last_record_id

        while True:
            events = win32evtlog.EvtNext(handle, 50)
            if not events:
                break

            for event in events:
                try:
                    xml_str = win32evtlog.EvtRender(
                        event,
                        win32evtlog.EvtRenderEventXml
                    )
                    root = ET.fromstring(xml_str)
                    system = root.find("System")
                    if system is None:
                        continue

                    record_id_el = system.find("EventRecordID")
                    if record_id_el is None:
                        continue
                    record_id = int(record_id_el.text or 0)

                    # Skip already-processed events
                    if record_id <= last_record_id:
                        continue

                    event_id_el = system.find("EventID")
                    if event_id_el is None:
                        continue
                    event_id = int(event_id_el.text or 0)

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

                    # Only process meaningful event IDs
                    if event_id not in DEFENDER_EVENTS:
                        continue

                    description, severity, category = DEFENDER_EVENTS[event_id]

                    # Escalate severity for high-value events
                    content = xml_str.lower()
                    if any(x in content for x in ["trojan", "ransomware", "mimikatz", "backdoor", "exploit"]):
                        severity = "CRITICAL"
                    elif any(x in content for x in ["powershell", "suspicious", "obfusc", "bypass"]):
                        severity = "HIGH"

                    if record_id > latest_record_id:
                        latest_record_id = record_id

                    logs.append(normalize_event(
                        source      = "Defender",
                        event_id    = event_id,
                        description = description,
                        raw_log     = xml_str[:2000],
                        severity    = severity,
                        category    = category,
                        log_type    = "HIDS"
                    ))

                except Exception:
                    pass

        if logs and latest_record_id > last_record_id:
            update_cursor("defender", latest_record_id, datetime.now().isoformat())

        _soc_log(f"[DEFENDER] Logs collected: {len(logs)}")

    except Exception as e:
        _soc_log(f"[DEFENDER COLLECTOR ERROR] {e}")

    return pd.DataFrame(logs)
