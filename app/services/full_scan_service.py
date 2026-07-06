import pandas as pd

from app.collectors.sysmon_collector import (
    read_sysmon_logs
)

from app.collectors.forensic_scanner import (
    scan_filesystem
)

from app.engines.detection_engine import (
    detect_advanced_threats
)

from app.database.database import (
    insert_alert,
    get_connection
)

from app.engines.correlation_engine import (
    correlate_alerts
)

def store_raw_logs(df):

    conn=get_connection()

    cursor=conn.cursor()

    for _,row in df.iterrows():

        cursor.execute("""

        INSERT INTO raw_logs(

            timestamp,
            source,
            event_id,
            computer,
            user,
            process_name,
            severity,
            description,
            raw_data

        )

        VALUES(?,?,?,?,?,?,?,?,?)

        """,(

            row.get("timestamp"),

            row.get("source"),

            row.get("event_id"),

            row.get("computer"),

            row.get("user"),

            row.get("process_name"),

            row.get("severity"),

            row.get("description"),

            row.get("raw_data")
        ))

    conn.commit()

    conn.close()

def run_full_soc_scan():

    print("[SOC] Starting full scan")

    # =====================================
    # SYSLOG COLLECTION
    # =====================================

    logs_df=read_sysmon_logs(hours=24)

    if logs_df.empty:

        return {

            "status":"error",

            "message":"No logs collected"
        }

    # =====================================
    # STORE RAW LOGS
    # =====================================

    store_raw_logs(logs_df)

    # =====================================
    # DETECTION ENGINE
    # =====================================

    alerts=detect_advanced_threats(logs_df)

    # =====================================
    # STORE ALERTS
    # =====================================

    for alert in alerts:

        insert_alert(alert)

    # =====================================
    # CORRELATION ENGINE
    # =====================================

    alerts_df=pd.DataFrame(alerts)

    incidents=correlate_alerts(alerts_df)

    for incident in incidents:

        insert_alert(incident)

    # =====================================
    # FORENSIC SCAN
    # =====================================

    scan_filesystem()

    return {

        "status":"success",

        "raw_logs":len(logs_df),

        "alerts":len(alerts),

        "incidents":len(incidents)
    }