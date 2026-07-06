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
# SECURITY CHANNEL
# =========================================

SECURITY_CHANNEL = "Security"

# =========================================
# IMPORTANT EVENT IDS
# =========================================

EVENT_MAP = {

    4624:"Successful Login",

    4625:"Failed Login",

    4672:"Privilege Escalation",

    4688:"Process Creation",

    4697:"Service Installed",

    4698:"Scheduled Task Created",

    4720:"User Account Created",

    4728:"User Added To Group",

    4740:"Account Locked",

    4768:"Kerberos Authentication",

    4776:"NTLM Authentication",

    7045:"Suspicious Service Installed"
}

# =========================================
# SEVERITY
# =========================================

def determine_severity(event_id):

    if event_id in [

        4672,
        4697,
        4698,
        7045

    ]:

        return "HIGH"

    if event_id in [

        4625,
        4740

    ]:

        return "MEDIUM"

    return "LOW"

# =========================================
# XML FIELD EXTRACTION
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
# READ SECURITY LOGS
# =========================================

def read_security_logs(hours=720):

    logs = []

    # =====================================
    # CURSOR
    # =====================================

    cursor_data = get_cursor(
        "security"
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

            SECURITY_CHANNEL,

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

                    username = event_data.get(
                        "TargetUserName",
                        ""
                    )

                    ip_address = event_data.get(
                        "IpAddress",
                        ""
                    )

                    process_name = event_data.get(
                        "ProcessName",
                        ""
                    )

                    workstation = event_data.get(
                        "WorkstationName",
                        ""
                    )

                    description = EVENT_MAP.get(

                        event_id,

                        f"Security Event {event_id}"
                    )

                    # =====================
                    # NORMALIZE
                    # =====================

                    logs.append(

                        normalize_event(

                            source="Security",

                            event_id=event_id,

                            description=description,

                            raw_log=xml,

                            severity=
                            determine_severity(
                                event_id
                            ),

                            category=EVENT_MAP.get(
                                event_id,
                                "Security"
                            ),

                            computer=workstation,

                            user=username,

                            process_name=process_name,

                            ip_address=ip_address,

                            log_type="HIDS"
                        )
                    )

                    processed += 1

                    if processed >= max_events:

                        break

                except Exception as e:

                    print(
                        f"Security parse error: {e}"
                    )

        # =====================================
        # UPDATE CURSOR
        # =====================================

        if logs:

            latest_record = record_id

            update_cursor(

                "security",

                latest_record,

                datetime.now().isoformat()
            )

            print(

                f"[SECURITY] "
                f"Logs collected: {len(logs)}"
            )

        return pd.DataFrame(logs)

    except Exception as e:

        print(
            f"[SECURITY COLLECTOR ERROR] {e}"
        )

        return pd.DataFrame()