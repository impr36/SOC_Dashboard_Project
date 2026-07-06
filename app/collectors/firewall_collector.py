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


CHANNEL = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"

# Only meaningful firewall event IDs
FIREWALL_EVENTS = {
    2004: ("Firewall rule added",           "MEDIUM", "Defense Evasion"),
    2005: ("Firewall rule modified",        "MEDIUM", "Defense Evasion"),
    2006: ("Firewall rule deleted",         "HIGH",   "Defense Evasion"),
    2009: ("Firewall failed to load rules", "HIGH",   "Defense Evasion"),
    2010: ("Firewall network changed",      "LOW",    "Discovery"),
    2033: ("Firewall rule blocked",         "LOW",    "Defense Evasion"),
    2034: ("Firewall blocked connection",   "LOW",    "Network"),
    2097: ("Firewall setting changed",      "MEDIUM", "Defense Evasion"),
}


def read_firewall_logs(hours=720):
    logs = []

    cursor_data    = get_cursor("firewall")
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
                    root   = ET.fromstring(xml_str)
                    system = root.find("System")
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

                    # Only collect meaningful firewall events
                    if event_id not in FIREWALL_EVENTS:
                        continue

                    description, severity, category = FIREWALL_EVENTS[event_id]

                    if record_id > latest_record_id:
                        latest_record_id = record_id

                    logs.append(normalize_event(
                        source      = "Firewall",
                        event_id    = event_id,
                        description = description,
                        raw_log     = xml_str[:2000],
                        severity    = severity,
                        category    = category,
                        log_type    = "NIDS"
                    ))

                except Exception:
                    pass

        if logs and latest_record_id > last_record_id:
            update_cursor("firewall", latest_record_id, datetime.now().isoformat())

        _soc_log(f"[FIREWALL] Logs collected: {len(logs)}")

    except Exception as e:
        _soc_log(f"[FIREWALL COLLECTOR ERROR] {e}")

    return pd.DataFrame(logs)
