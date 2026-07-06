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



def read_taskscheduler_logs(hours=24):

    logs=[]

    try:

        output=subprocess.check_output(

            "schtasks",

            shell=True

        ).decode(
            errors="ignore"
        )

        for line in output.splitlines():

            if "\\" in line:

                logs.append(

                    normalize_event(

                        source="TaskScheduler",

                        event_id=5000,

                        description=
                        "Scheduled Task",

                        raw_log=line,

                        severity="MEDIUM",

                        category=
                        "Persistence",

                        log_type="HIDS"
                    )
                )

        _soc_log(
            f"[TASKS] "
            f"Tasks collected: {len(logs)}"
        )

    except Exception as e:

        _soc_log(
            f"[TASK COLLECTOR ERROR] {e}"
        )

    return pd.DataFrame(logs)