import pandas as pd
import subprocess

from app.engines.normalization_engine import (
    normalize_event
)

def read_wmi_logs(hours=24):

    logs=[]

    try:

        output=subprocess.check_output(

            'powershell "Get-CimInstance Win32_StartupCommand | Select-Object Name, Command"',

            shell=True

        ).decode(
            errors="ignore"
        )

        for line in output.splitlines():

            if line.strip():

                logs.append(

                    normalize_event(

                        source="WMI",

                        event_id=6000,

                        description=
                        "WMI Startup Entry",

                        raw_log=line,

                        severity="MEDIUM",

                        category=
                        "Persistence",

                        log_type="HIDS"
                    )
                )

        print(
            f"[WMI] "
            f"Entries collected: {len(logs)}"
        )

    except Exception as e:

        print(
            f"[WMI COLLECTOR ERROR] {e}"
        )

    return pd.DataFrame(logs)