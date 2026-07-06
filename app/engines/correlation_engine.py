from datetime import datetime

import pandas as pd


# =========================================
# BUILD CORRELATED INCIDENTS
# =========================================

def correlate_alerts(alerts_df):

    incidents = []

    if alerts_df.empty:

        return incidents

    alerts_df["timestamp"] = pd.to_datetime(

        alerts_df["timestamp"],

        errors="coerce"
    )

    alerts_df = alerts_df.sort_values(
        "timestamp"
    )

    grouped = alerts_df.groupby([

        "computer",
        "user"

    ])

    for (computer,user),group in grouped:

        if len(group) < 3:

            continue

        tactics = list(

            group["category"]
            .dropna()
            .unique()
        )

        severity = highest_severity(group)

        first_seen = group[
            "timestamp"
        ].min()

        last_seen = group[
            "timestamp"
        ].max()

        duration = (

            last_seen - first_seen

        ).total_seconds()

        # correlate only close attack chains

        if duration > 900:

            continue

        confidence = min(

            100,

            50 + len(group) * 5
        )

        incidents.append({

            "timestamp":
            first_seen.isoformat(),

            "group_id":
            f"INC-{hash(computer+str(user))}",

            "type":
            "Correlated Attack Chain",

            "severity":
            severity,

            "description":

            f"Multi-stage attack activity detected on {computer}.",

            "category":
            "Correlated Incident",

            "log_source":
            "Correlation Engine",

            "status":
            "New",

            "computer":
            computer,

            "user":
            user,

            "confidence":
            confidence,

            "attack_chain":
            tactics
        })

    return incidents


# =========================================
# HIGHEST SEVERITY
# =========================================

def highest_severity(df):

    ranking = {

        "LOW":1,
        "MEDIUM":2,
        "HIGH":3,
        "CRITICAL":4
    }

    highest = "LOW"

    for s in df["severity"]:

        if ranking.get(s,1) > ranking.get(highest,1):

            highest = s

    return highest