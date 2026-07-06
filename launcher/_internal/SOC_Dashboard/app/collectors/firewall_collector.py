import pandas as pd
import win32evtlog
from datetime import datetime
import xml.etree.ElementTree as ET

from app.engines.normalization_engine import (
    normalize_event
)

CHANNEL = \
"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"

def read_firewall_logs(hours=24):

    logs=[]

    try:

        handle=win32evtlog.EvtQuery(

            CHANNEL,

            win32evtlog.EvtQueryReverseDirection,

            "*"
        )

        while True:

            events=win32evtlog.EvtNext(
                handle,
                20
            )

            if not events:

                break

            for event in events:

                try:

                    xml=win32evtlog.EvtRender(

                        event,

                        win32evtlog.EvtRenderEventXml
                    )

                    logs.append(

                        normalize_event(

                            source="Firewall",

                            event_id=2000,

                            description=
                            "Firewall Event",

                            raw_log=xml,

                            severity="MEDIUM",

                            category=
                            "Network",

                            log_type="NIDS"
                        )
                    )

                except:
                    pass

        print(
            f"[FIREWALL] "
            f"Logs collected: {len(logs)}"
        )

    except Exception as e:

        print(
            f"[FIREWALL COLLECTOR ERROR] {e}"
        )

    return pd.DataFrame(logs)