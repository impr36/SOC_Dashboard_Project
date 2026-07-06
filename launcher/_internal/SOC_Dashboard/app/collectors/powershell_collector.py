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

POWERSHELL_CHANNEL = \
"Microsoft-Windows-PowerShell/Operational"

EVENT_MAP = {

    4103:"PowerShell Command",

    4104:"PowerShell Script Block",

    4105:"PowerShell Started",

    4106:"PowerShell Stopped"
}

def determine_severity(event_id):

    if event_id == 4104:

        return "HIGH"

    return "MEDIUM"

def extract_event_data(root):

    data={}

    for item in root.findall(".//Data"):

        name=item.attrib.get(
            "Name",
            ""
        )

        value=item.text or ""

        data[name]=value

    return data

def read_powershell_logs(hours=720):

    logs=[]

    cursor_data=get_cursor(
        "powershell"
    )

    last_record_id=0

    if cursor_data:

        try:

            last_record_id=int(

                cursor_data[
                    "last_event_record_id"
                ]
            )

        except:

            last_record_id=0

    cutoff=datetime.now()-timedelta(
        hours=hours
    )

    try:

        handle=win32evtlog.EvtQuery(

            POWERSHELL_CHANNEL,

            win32evtlog.EvtQueryReverseDirection,

            "*"
        )

        while True:

            events=win32evtlog.EvtNext(
                handle,
                50
            )

            if not events:

                break

            for event in events:

                try:

                    xml=win32evtlog.EvtRender(

                        event,

                        win32evtlog.EvtRenderEventXml
                    )

                    root=ET.fromstring(xml)

                    system = root.find("System")

                    if system is None:
                        continue
                    
                    event_id_node = system.find("EventID")

                    if event_id_node is None:
                        continue
                    
                    event_id = int(event_id_node.text or 0)

                    record_id=int(

                        system.find(
                            "EventRecordID"
                        ).text
                    )

                    if record_id <= \
                    last_record_id:

                        continue

                    time_node = system.find("TimeCreated")

                    if time_node is None:
                        continue
                    
                    system_time = time_node.attrib.get("SystemTime")

                    if not system_time:
                        continue

                    event_time=datetime.fromisoformat(

                        system_time.replace(
                            "Z",
                            "+00:00"
                        )
                    )

                    if event_time.replace(
                        tzinfo=None
                    ) < cutoff:

                        continue

                    event_data=extract_event_data(
                        root
                    )

                    script_text=event_data.get(
                        "ScriptBlockText",
                        ""
                    )

                    description=EVENT_MAP.get(

                        event_id,

                        f"PowerShell Event {event_id}"
                    )

                    logs.append(

                        normalize_event(

                            source="PowerShell",

                            event_id=event_id,

                            description=description,

                            raw_log=script_text
                            or xml,

                            severity=
                            determine_severity(
                                event_id
                            ),

                            category=
                            "Execution",

                            process_name=
                            "powershell.exe",

                            log_type="HIDS"
                        )
                    )

                except Exception as e:

                    print(
                        f"PowerShell parse error: {e}"
                    )

        if logs:

            update_cursor(

                "powershell",

                record_id,

                datetime.now().isoformat()
            )

            print(

                f"[POWERSHELL] "
                f"Logs collected: {len(logs)}"
            )

        return pd.DataFrame(logs)

    except Exception as e:

        print(
            f"[POWERSHELL COLLECTOR ERROR] {e}"
        )

        return pd.DataFrame()