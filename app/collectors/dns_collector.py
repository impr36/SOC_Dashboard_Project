import pandas as pd
import win32evtlog

from app.engines.normalization_engine import (
    normalize_event
)

CHANNEL = \
"Microsoft-Windows-DNS-Client/Operational"

def read_dns_logs(hours=24):

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

                            source="DNS",

                            event_id=3000,

                            description=
                            "DNS Query",

                            raw_log=xml,

                            severity="LOW",

                            category=
                            "Network",

                            log_type="NIDS"
                        )
                    )

                except:
                    pass

        print(
            f"[DNS] "
            f"Logs collected: {len(logs)}"
        )

    except Exception as e:

        print(
            f"[DNS COLLECTOR ERROR] {e}"
        )

    return pd.DataFrame(logs)