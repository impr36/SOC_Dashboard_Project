import pandas as pd
import win32evtlog

from app.engines.normalization_engine import (
    normalize_event
)

CHANNEL = \
"Microsoft-Windows-Windows Defender/Operational"

def read_defender_logs(hours=24):

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

                    severity = "MEDIUM"

                    if any(x in xml.lower() for x in [
                    
                        "trojan",
                        "ransomware",
                        "mimikatz",
                        "backdoor",
                        "credential"

                    ]):

                        severity = "CRITICAL"

                    elif any(x in xml.lower() for x in [
                    
                        "powershell",
                        "suspicious",
                        "malware"

                    ]):

                        severity = "HIGH"

                    logs.append(

                        normalize_event(

                            source="Defender",

                            event_id=1116,

                            description=xml[:2000],

                            raw_log=xml,

                            severity=severity,

                            category=
                            "Malware",

                            log_type="HIDS"
                        )
                    )

                except:
                    pass

        print(
            f"[DEFENDER] "
            f"Logs collected: {len(logs)}"
        )

    except Exception as e:

        print(
            f"[DEFENDER COLLECTOR ERROR] {e}"
        )

    return pd.DataFrame(logs)