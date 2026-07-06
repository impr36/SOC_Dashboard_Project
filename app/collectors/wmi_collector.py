import pandas as pd
import subprocess

from app.engines.normalization_engine import (
    normalize_event
)


# =========================================
# SOC TERMINAL LOGGER
# =========================================
def _soc_log(msg: str):
    print(msg)
    try:
        from app.websocket_manager import manager
        manager.send_console(str(msg))
    except Exception:
        pass



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

        _soc_log(
            f"[WMI] "
            f"Entries collected: {len(logs)}"
        )

    except Exception as e:

        _soc_log(
            f"[WMI COLLECTOR ERROR] {e}"
        )

    return pd.DataFrame(logs)