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

APPLICATION_CHANNEL = "Application"

EVENT_MAP = {

    1000:"Application Crash",

    1001:"Application Hang",

    1026:"NET Runtime Error",

    11707:"Application Installed",

    11724:"Application Removed"
}

def determine_severity(event_id):

    if event_id in [

        1000,
        1026

    ]:

        return "HIGH"

    return "LOW"

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

def read_application_logs(hours=720):

    logs=[]

    cursor_data=get_cursor(
        "application"
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

            APPLICATION_CHANNEL,

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

                    record_node = system.find("EventRecordID")

                    if event_id_node is None or record_node is None:
                        continue
                    
                    event_id = int(event_id_node.text or 0)

                    record_id = int(record_node.text or 0)

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

                    description=EVENT_MAP.get(

                        event_id,

                        f"Application Event {event_id}"
                    )

                    logs.append(

                        normalize_event(

                            source="Application",

                            event_id=event_id,

                            description=description,

                            raw_log=xml,

                            severity=
                            determine_severity(
                                event_id
                            ),

                            category="Application",

                            log_type="HIDS"
                        )
                    )

                except Exception as e:

                    print(
                        f"Application parse error: {e}"
                    )

        if logs:

            update_cursor(

                "application",

                record_id,

                datetime.now().isoformat()
            )

            print(

                f"[APPLICATION] "
                f"Logs collected: {len(logs)}"
            )

        return pd.DataFrame(logs)

    except Exception as e:

        print(
            f"[APPLICATION COLLECTOR ERROR] {e}"
        )

        return pd.DataFrame()