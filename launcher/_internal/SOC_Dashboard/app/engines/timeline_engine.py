import pandas as pd


# =========================================
# ATTACK TIMELINE
# =========================================

def build_attack_timeline(df):

    if df.empty:return []

    df["timestamp"]=pd.to_datetime(

        df["timestamp"],

        format="mixed",

        errors="coerce"
    )

    df=df.sort_values("timestamp")

    return [

        {

            "timestamp":
            r.get("timestamp"),

            "event":
            r.get("type","Unknown"),

            "severity":
            r.get("severity","LOW"),

            "description":
            r.get("description",""),

            "source":
            r.get("log_source","Unknown"),

            "group_id":
            r.get("group_id","")

        }

        for _,r in df.iterrows()
    ]


# =========================================
# ATTACK PROGRESSION
# =========================================

def detect_attack_progression(df):

    if df.empty:

        return []

    tactics = list(

        df["category"]
        .dropna()
        .unique()
    )

    ordered_stages = [

        "Reconnaissance",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Command & Control",
        "Exfiltration",
        "Impact"
    ]

    progression = []

    for stage in ordered_stages:

        if stage in tactics:

            progression.append(stage)

    return progression