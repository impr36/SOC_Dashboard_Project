from uuid import uuid4

from datetime import datetime,timedelta

import pandas as pd

# =========================================
# GROUP ALERTS INTO INCIDENT CHAINS
# =========================================

def group_alerts(alerts):

    if not alerts:

        return []

    df = pd.DataFrame(alerts)

    df["timestamp"] = pd.to_datetime(

        df["timestamp"],

        errors="coerce"
    )

    df = df.sort_values("timestamp")

    grouped_alerts = []

    current_group = []

    current_group_id = str(uuid4())[:8]

    TIME_WINDOW = timedelta(minutes=10)

    previous_time = None

    previous_category = None

    for _,alert in df.iterrows():

        current_time = alert["timestamp"]

        current_category = alert.get(
            "category",
            "Other"
        )

        # =====================================
        # START NEW INCIDENT GROUP
        # =====================================

        if (

            previous_time is None

            or

            current_time - previous_time
            > TIME_WINDOW

            or

            current_category
            != previous_category
        ):

            # finalize previous group

            if current_group:

                grouped_alerts.extend(
                    finalize_group(

                        current_group,

                        current_group_id
                    )
                )

            current_group = []

            current_group_id = str(uuid4())[:8]

        current_group.append(
            alert.to_dict()
        )

        previous_time = current_time

        previous_category = current_category

    # =====================================
    # FINAL GROUP
    # =====================================

    if current_group:

        grouped_alerts.extend(

            finalize_group(

                current_group,

                current_group_id
            )
        )

    return grouped_alerts

# =========================================
# FINALIZE GROUP
# =========================================

def finalize_group(

    alerts,

    group_id
):

    severity_rank = {

        "LOW":1,
        "MEDIUM":2,
        "HIGH":3,
        "CRITICAL":4
    }

    highest = max(

        alerts,

        key=lambda x:
        severity_rank.get(
            x.get("severity","LOW"),
            1
        )
    )

    attack_chain = " → ".join(

        list(

            dict.fromkeys([

                a.get("type","Unknown")

                for a in alerts
            ])
        )[:5]
    )

    for alert in alerts:

        alert["group_id"] = group_id

        alert["group_size"] = len(alerts)

        alert["attack_chain"] = attack_chain

        alert["incident_severity"] = \
        highest.get("severity","LOW")

    return alerts