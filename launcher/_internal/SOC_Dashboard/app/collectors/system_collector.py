import pandas as pd

import win32evtlog

from datetime import (
    datetime,
    timedelta
)

import xml.etree.ElementTree as ET

from app.engines.normalization_engine import (
    normalize_event
)

from app.database.database import (

    get_cursor,

    update_cursor
)

# =========================================
# SYSTEM CHANNEL
# =========================================

SYSTEM_CHANNEL = "System"

# =========================================
# IMPORTANT SYSTEM EVENTS
# =========================================

EVENT_MAP = {

    6005:"Event Log Service Started",

    6006:"System Shutdown",

    6008:"Unexpected Shutdown",

    7040:"Service Start Type Changed",

    7045:"New Service Installed",

    7036:"Service State Changed",

    1074:"System Restart",

    1:"Driver Loaded"
}

# =========================================
# SEVERITY
# =========================================

def determine_severity(event_id):

    if event_id in [

        7045,
        6008

    ]:

        return "HIGH"

    if event_id in [

        7040,
        1074

    ]:

        return "MEDIUM"

    return "LOW"

# =========================================
# XML EVENT DATA
# =========================================

def extract_event_data(root):

    data = {}

    for item in root.findall(".//Data"):

        name = item.attrib.get(
            "Name",
            ""
        )

        value = item.text or ""

        data[name] = value

    return data

# =========================================
# READ SYSTEM LOGS
# =========================================

def read_system_logs(hours=720):

    logs = []

    # =====================================
    # CURSOR
    # =====================================

    cursor_data = get_cursor(
        "system"
    )

    last_record_id = 0

    if cursor_data:

        try:

            last_record_id = int(

                cursor_data[
                    "last_event_record_id"
                ]
            )

        except:

            last_record_id = 0

    cutoff = datetime.now() - timedelta(
        hours=hours
    )

    try:

        handle = win32evtlog.EvtQuery(

            SYSTEM_CHANNEL,

            win32evtlog.EvtQueryReverseDirection,

            "*"
        )

        processed = 0

        max_events = 100000

        while True:

            events = win32evtlog.EvtNext(

                handle,

                50
            )

            if not events:

                break

            for event in events:

                try:

                    xml = win32evtlog.EvtRender(

                        event,

                        win32evtlog.EvtRenderEventXml
                    )

                    if not xml:

                        continue

                    root = ET.fromstring(xml)

                    # =====================
                    # SYSTEM
                    # =====================

                    system = root.find("System")

                    if system is None:

                        continue

                    event_id = int(

                        system.find(
                            "EventID"
                        ).text
                    )

                    record_id = int(

                        system.find(
                            "EventRecordID"
                        ).text
                    )

                    # =====================
                    # CURSOR FILTER
                    # =====================

                    if record_id <= last_record_id:

                        continue

                    # =====================
                    # TIMESTAMP
                    # =====================

                    time_node = system.find(
                        "TimeCreated"
                    )

                    system_time = time_node.attrib.get(
                        "SystemTime"
                    )

                    event_time = datetime.fromisoformat(

                        system_time.replace(
                            "Z",
                            "+00:00"
                        )
                    )

                    if event_time.replace(
                        tzinfo=None
                    ) < cutoff:

                        continue

                    # =====================
                    # EVENT DATA
                    # =====================

                    event_data = extract_event_data(
                        root
                    )

                    service_name = event_data.get(
                        "ServiceName",
                        ""
                    )

                    image_path = event_data.get(
                        "ImagePath",
                        ""
                    )

                    computer_name = event_data.get(
                        "ComputerName",
                        ""
                    )

                    description = EVENT_MAP.get(

                        event_id,

                        f"System Event {event_id}"
                    )

                    # =====================
                    # NORMALIZE
                    # =====================

                    logs.append(

                        normalize_event(

                            source="System",

                            event_id=event_id,

                            description=description,

                            raw_log=xml,

                            severity=
                            determine_severity(
                                event_id
                            ),

                            category=
                            "System",

                            computer=
                            computer_name,

                            process_name=
                            service_name,

                            ip_address="",

                            log_type="HIDS"
                        )
                    )

                    processed += 1

                    if processed >= max_events:

                        break

                except Exception as e:

                    print(
                        f"System parse error: {e}"
                    )

        # =====================================
        # UPDATE CURSOR
        # =====================================

        if logs:

            latest_record = record_id

            update_cursor(

                "system",

                latest_record,

                datetime.now().isoformat()
            )

            print(

                f"[SYSTEM] "
                f"Logs collected: {len(logs)}"
            )

        return pd.DataFrame(logs)

    except Exception as e:

        print(
            f"[SYSTEM COLLECTOR ERROR] {e}"
        )

        return pd.DataFrame()