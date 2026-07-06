from uuid import uuid4
from datetime import datetime

import pandas as pd


# =========================================
# BUILD INCIDENTS
# =========================================

def build_incidents(alerts_df):

    incidents = []

    if alerts_df.empty:

        return incidents

    # =====================================
    # TIMESTAMP NORMALIZATION
    # =====================================

    alerts_df["timestamp"] = pd.to_datetime(

        alerts_df["timestamp"],

        errors="coerce"
    )

    alerts_df = alerts_df.sort_values(
        "timestamp"
    )

    # =====================================
    # GROUPING
    # =====================================

    grouped = alerts_df.groupby([

        "computer",
        "user",
        "category"

    ])

    for (computer,user,category),group in grouped:

        if len(group) < 3:

            continue

        first_time = group[
            "timestamp"
        ].min()

        last_time = group[
            "timestamp"
        ].max()

        duration = (

            last_time - first_time

        ).total_seconds()

        # only correlate nearby attacks

        if duration > 600:

            continue

        severity = highest_severity(group)

        incident_id = str(uuid4())[:8]

        incidents.append({

            "incident_id":
            incident_id,

            "timestamp":
            first_time.isoformat(),

            "title":
            f"{category} Incident",

            "severity":
            severity,

            "alert_count":
            len(group),

            "category":
            category,

            "computer":
            computer,

            "user":
            user,

            "description":

            f"{len(group)} correlated alerts detected on {computer}.",

            "status":
            "Open"
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