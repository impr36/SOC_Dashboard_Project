import pandas as pd
import winreg

from app.engines.normalization_engine import (
    normalize_event
)

RUN_KEYS=[

    r"Software\Microsoft\Windows\CurrentVersion\Run",

    r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
]

def read_registry_logs(hours=24):

    logs=[]

    try:

        for key_path in RUN_KEYS:

            try:

                key=winreg.OpenKey(

                    winreg.HKEY_CURRENT_USER,

                    key_path
                )

                i=0

                while True:

                    try:

                        name,value,_=winreg.EnumValue(
                            key,
                            i
                        )

                        logs.append(

                            normalize_event(

                                source="Registry",

                                event_id=4000,

                                description=
                                "Registry Autorun",

                                raw_log=
                                f"{name}:{value}",

                                severity="HIGH",

                                category=
                                "Persistence",

                                log_type="HIDS"
                            )
                        )

                        i+=1

                    except OSError:
                        break

            except:
                pass

        print(
            f"[REGISTRY] "
            f"Entries collected: {len(logs)}"
        )

    except Exception as e:

        print(
            f"[REGISTRY COLLECTOR ERROR] {e}"
        )

    return pd.DataFrame(logs)