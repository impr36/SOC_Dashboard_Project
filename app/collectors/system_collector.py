"""
system_collector.py
===================
Collects Windows System event log entries.
Captures: service changes, driver issues, USB insertion,
          unexpected shutdowns, disk errors, boot events.
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


CHANNEL = "System"

SYSTEM_EVENTS = {
    # Services
    7000: ("Service failed to start",          "HIGH",     "Persistence"),
    7001: ("Service dependency failed",         "MEDIUM",   "Persistence"),
    7009: ("Service connection timeout",        "MEDIUM",   "Persistence"),
    7023: ("Service terminated with error",     "HIGH",     "Persistence"),
    7024: ("Service terminated with error",     "HIGH",     "Persistence"),
    7031: ("Service crashed unexpectedly",      "HIGH",     "Persistence"),
    7034: ("Service crashed unexpectedly",      "HIGH",     "Persistence"),
    7036: ("Service started or stopped",        "LOW",      "Persistence"),
    7040: ("Service start type changed",        "HIGH",     "Defense Evasion"),
    7045: ("New service installed",             "CRITICAL", "Persistence"),
    # USB / Devices
    20001: ("USB device driver installed",      "MEDIUM",   "Collection"),
    20003: ("USB device driver removed",        "LOW",      "Collection"),
    # Disk
    7: ("Disk error",                           "HIGH",     "Impact"),
    11: ("Driver detected controller error",    "HIGH",     "Impact"),
    # Boot / Shutdown
    41:   ("Kernel power - unexpected restart", "HIGH",     "Impact"),
    1074: ("System shutdown initiated",         "MEDIUM",   "Impact"),
    6005: ("Event log service started (boot)",  "LOW",      "System"),
    6006: ("Event log service stopped",         "MEDIUM",   "System"),
    6008: ("Previous shutdown unexpected",      "HIGH",     "Impact"),
    # Time change
    4616: ("System time changed",               "HIGH",     "Defense Evasion"),
}


def read_system_logs(hours=720):
    logs = []

    cursor_data    = get_cursor("system_evt")
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
            events = win32evtlog.EvtNext(handle, 100)
            if not events:
                break

            for event in events:
                try:
                    xml_str = win32evtlog.EvtRender(
                        event, win32evtlog.EvtRenderEventXml
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

                    if event_id not in SYSTEM_EVENTS:
                        continue

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

                    description, severity, category = SYSTEM_EVENTS[event_id]

                    if record_id > latest_record_id:
                        latest_record_id = record_id

                    logs.append(normalize_event(
                        source      = "System",
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
            update_cursor("system_evt", latest_record_id, datetime.now().isoformat())

        _soc_log(f"[SYSTEM] Logs collected: {len(logs)}")

    except Exception as e:
        _soc_log(f"[SYSTEM COLLECTOR ERROR] {e}")

    return pd.DataFrame(logs)
