from datetime import datetime

from app.database.database import get_connection
import hashlib
import json

def create_alert(
    alert_type,
    severity,
    category,
    source,
    description
):

    conn = get_connection()

    cursor = conn.cursor()
    
    cursor.execute("""

        INSERT INTO alerts (

            timestamp,
            alert_type,
            severity,
            category,
            source,
            description

        )

        VALUES (?, ?, ?, ?, ?, ?)

    """, (

        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        alert_type,
        severity,
        category,
        source,
        description

    ))

    conn.commit()

    conn.close()


def get_all_alerts():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

        SELECT *
        FROM alerts
        ORDER BY id DESC

    """)

    alerts = cursor.fetchall()

    conn.close()

    return [dict(alert) for alert in alerts]

from app.database.database import (
    get_connection
)


def store_alert(alert):

    try:

        conn = get_connection()

        cursor = conn.cursor()

        safe_alert = {}

        for key, value in alert.items():

            if value is None:

                safe_alert[key]=""

            elif hasattr(value,"isoformat"):
            
                safe_alert[key]=value.isoformat()

            else:
            
                safe_alert[key]=str(value)

        alert_hash = hashlib.md5(

            json.dumps(
                safe_alert,
                sort_keys=True
            ).encode()

        ).hexdigest()

        # =========================================
        # CHECK DUPLICATE ALERT
        # =========================================
        
        cursor.execute("""
        
        SELECT id
        
        FROM alerts
        
        WHERE alert_hash=?
        
        """,(alert_hash,))
        
        existing = cursor.fetchone()
        
        if existing:
        
            conn.close()
        
            return False

        cursor.execute("""

        INSERT INTO alerts(

            timestamp,
            event_id,
            type,
            severity,
            category,
            description,
            explanation,
            raw_log,
            log_source,
            status,
            mitre_technique,
            mitre_tactic,
            incident_id,
            alert_hash

        )

        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)

        """,(

            safe_alert.get("timestamp"),

            safe_alert.get("event_id"),

            safe_alert.get("type"),

            safe_alert.get("severity"),

            safe_alert.get("category"),

            safe_alert.get("description"),

            safe_alert.get("explanation"),

            safe_alert.get("raw_log"),

            safe_alert.get("log_source"),

            safe_alert.get("status"),

            safe_alert.get("mitre_technique"),

            safe_alert.get("mitre_tactic"),

            safe_alert.get(
                "incident_id",
                "INC-0001"
            ),

            alert_hash
        ))

        conn.commit()

        conn.close()

        return True

    except Exception as e:

        print(
            f"[ALERT STORE ERROR] {e}"
        )

        return False