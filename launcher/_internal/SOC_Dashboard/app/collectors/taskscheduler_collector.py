import pandas as pd
import subprocess

from app.engines.normalization_engine import (
    normalize_event
)

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

        print(
            f"[TASKS] "
            f"Tasks collected: {len(logs)}"
        )

    except Exception as e:

        print(
            f"[TASK COLLECTOR ERROR] {e}"
        )

    return pd.DataFrame(logs)