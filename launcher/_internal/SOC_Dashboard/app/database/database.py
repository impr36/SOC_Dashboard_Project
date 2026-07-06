import sqlite3
import glob
from pathlib import Path
from datetime import datetime
import hashlib

# =========================================
# DATABASE PATH — SESSION-BASED
#
# A fresh .db file is created every time the
# app starts, named with the launch timestamp.
# All previous session databases are deleted
# on startup so the dashboard always opens
# clean, with no stale alerts or chart data
# from a prior run.
#
# Example:  soc_20260607_093012.db
#
# Every function calls get_connection() which
# always references DB_PATH. Because DB_PATH
# is set once at import time, the detection
# engine, dashboard API and alert store all
# share the same session DB automatically.
# =========================================

ROOT_DIR = Path(__file__).resolve().parents[2]

DATABASE_DIR = ROOT_DIR / "database"

DATABASE_DIR.mkdir(exist_ok=True)

# ---- Delete all previous session databases ----
for _old_db in DATABASE_DIR.glob("soc_*.db"):
    try:
        _old_db.unlink()
        print(f"[SOC] Cleared old session DB: {_old_db.name}")
    except Exception as _e:
        print(f"[SOC] Could not delete {_old_db.name}: {_e}")

# ---- Create fresh session database ----
_SESSION_TS = datetime.now().strftime("%Y%m%d_%H%M%S")

DB_PATH = DATABASE_DIR / f"soc_{_SESSION_TS}.db"

print(f"[SOC] Active session database: {DB_PATH.name}")


# CONNECTION

def get_connection():

    conn = sqlite3.connect(str(DB_PATH))

    conn.row_factory = sqlite3.Row

    return conn


# INITIALIZE DATABASE

def initialize_database():

    conn = get_connection()

    cursor = conn.cursor()

    # RAW LOGS

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS raw_logs(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        timestamp TEXT,

        source TEXT,

        event_id INTEGER,

        computer TEXT,

        user TEXT,

        process_name TEXT,

        severity TEXT,

        description TEXT,

        raw_data TEXT
    )

    """)

    # ALERTS

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts(
    
        id INTEGER PRIMARY KEY AUTOINCREMENT,
    
        timestamp TEXT,
        event_id TEXT,
        type TEXT,
        severity TEXT,
        category TEXT,
        description TEXT,
        explanation TEXT,
        raw_log TEXT,
        log_source TEXT,
        status TEXT,
        mitre_technique TEXT,
        mitre_tactic TEXT,
        incident_id TEXT,
        alert_hash TEXT
    )
    """)

    # Try to add status column for older databases
    try:
        cursor.execute("ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'New'")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # FORENSIC CASES

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS forensic_cases(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        case_name TEXT,

        created_at TEXT,

        file_path TEXT,

        hash TEXT
    )

    """)

    # CASE REPORTS

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS case_reports(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        ticket_id TEXT UNIQUE,

        severity TEXT,

        status TEXT,

        attack_chain TEXT,

        analyst_notes TEXT,

        timeline TEXT,

        actions_taken TEXT,

        next_steps TEXT,

        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )

    """)

    # FILE SNAPSHOTS

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS file_snapshots(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        file_path TEXT,

        file_hash TEXT,

        extension TEXT,

        scan_time TEXT,

        last_modified TEXT,

        file_size INTEGER,

        created_at TEXT
    )

    """)

    # DETECTION RULES

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS detection_rules(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        rule_type TEXT,

        event_id INTEGER,

        rule_name TEXT,

        threshold INTEGER,

        window_sec INTEGER,

        severity TEXT,

        description TEXT,

        enabled INTEGER DEFAULT 1,

        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )

    """)

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS active_session(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        session_id TEXT,

        started_at TEXT,

        scan_type TEXT
    )

    """)

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS alert_archive(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        session_id TEXT,

        timestamp TEXT,

        type TEXT,

        severity TEXT,

        category TEXT,

        description TEXT,

        source TEXT
    )

    """)

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS incidents(
    
        id INTEGER PRIMARY KEY AUTOINCREMENT,
    
        session_id TEXT,
    
        incident_name TEXT,
    
        severity TEXT,
    
        category TEXT,
    
        created_at TEXT
    )
    
    """)

    # INDEXES

    cursor.execute("""

    CREATE INDEX IF NOT EXISTS idx_raw_timestamp
    ON raw_logs(timestamp)

    """)

    cursor.execute("""

    CREATE INDEX IF NOT EXISTS idx_alert_timestamp
    ON alerts(timestamp)

    """)

    cursor.execute("""

    CREATE INDEX IF NOT EXISTS idx_alert_severity
    ON alerts(severity)

    """)

    conn.commit()

    conn.close()


# INSERT ALERT
def insert_alert(alert):

    conn=get_connection()

    cursor=conn.cursor()

    alert_hash=generate_alert_hash(alert)

    # =====================================
    # DUPLICATE CHECK
    # =====================================

    cursor.execute("""

    SELECT id,timestamp
    FROM alerts
    WHERE alert_hash=?

    """,(alert_hash,))

    existing=cursor.fetchone()

    if existing:

        conn.close()

        return False

    cursor.execute("""

    INSERT INTO alerts(

        timestamp,
        type,
        severity,
        log_source,
        category,
        event_id,
        description,
        alert_hash,
        status

    )

    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

    """, (

        alert.get("timestamp"),

        alert.get("type"),

        alert.get("severity"),

        alert.get("log_source"),

        alert.get("category"),

        alert.get("event_id"),

        alert.get("description"),

        alert_hash,

        alert.get("status","New")

    ))

    conn.commit()

    conn.close()

    return True

# =========================================
# GENERATE ALERT HASH
# =========================================

def generate_alert_hash(alert):

    fingerprint=f"""

    {alert.get('type','')}
    {alert.get('event_id','')}
    {alert.get('description','')}
    {alert.get('log_source','')}
    {alert.get('category','')}
    {alert.get('timestamp','')}

    """

    return hashlib.sha256(

        fingerprint.encode()

    ).hexdigest()



# FETCH RECENT ALERTS

def fetch_recent_alerts(limit=100):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    SELECT *
    FROM alerts

    ORDER BY id DESC

    LIMIT ?

    """, (limit,))

    alerts = cursor.fetchall()

    conn.close()

    return [dict(alert) for alert in alerts]


# FETCH ALERT COUNTS

def fetch_alert_counts():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    SELECT severity, COUNT(*) as count

    FROM alerts

    GROUP BY severity

    """)

    rows = cursor.fetchall()

    conn.close()

    return [dict(row) for row in rows]

# FETCH RULES

def fetch_rules(rule_type):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    SELECT
        event_id,
        rule_name,
        threshold,
        window_sec,
        severity,
        description

    FROM detection_rules

    WHERE rule_type = ?

    ORDER BY id DESC

    """, (rule_type,))

    rules = cursor.fetchall()

    conn.close()

    return [dict(rule) for rule in rules]

# INSERT RULE

def insert_rule(rule):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    INSERT INTO detection_rules(

        rule_type,
        event_id,
        rule_name,
        threshold,
        window_sec,
        severity,
        description

    )

    VALUES (?, ?, ?, ?, ?, ?, ?)

    """, (

        rule.get("rule_type"),

        rule.get("event_id"),

        rule.get("rule_name"),

        rule.get("threshold"),

        rule.get("window_sec"),

        rule.get("severity"),

        rule.get("description")

    ))

    conn.commit()

    conn.close()

# DELETE RULE

def delete_rule(rule_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    DELETE FROM detection_rules

    WHERE id = ?

    """, (rule_id,))

    conn.commit()

    conn.close()

# UPDATE RULE

def update_rule(rule_id, updated_rule):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    UPDATE detection_rules

    SET

        threshold = ?,
        window_sec = ?,
        severity = ?,
        description = ?

    WHERE id = ?

    """, (

        updated_rule.get("threshold"),

        updated_rule.get("window_sec"),

        updated_rule.get("severity"),

        updated_rule.get("description"),

        rule_id

    ))

    conn.commit()

    conn.close()



# UPDATE ALERT STATUS

def update_alert_status(alert_id: int, status: str):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    UPDATE alerts

    SET status = ?

    WHERE id = ?

    """, (status, alert_id))

    conn.commit()

    conn.close()


# INSERT CASE REPORT

def insert_case_report(report):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    INSERT OR REPLACE INTO case_reports(

        ticket_id,
        severity,
        status,
        attack_chain,
        analyst_notes,
        timeline,
        actions_taken,
        next_steps

    )

    VALUES (?, ?, ?, ?, ?, ?, ?, ?)

    """, (

        report.get("ticket_id"),

        report.get("severity"),

        report.get("status"),

        report.get("attack_chain"),

        report.get("analyst_notes"),

        report.get("timeline"),

        report.get("actions_taken"),

        report.get("next_steps")

    ))

    conn.commit()

    conn.close()


# FETCH CASE REPORTS

def fetch_case_reports():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    SELECT *

    FROM case_reports

    ORDER BY id DESC

    """)

    rows = cursor.fetchall()

    conn.close()

    return [dict(row) for row in rows]


# INSERT FORENSIC CASE

def insert_forensic_case(case_name, file_path, file_hash):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    INSERT INTO forensic_cases(

        case_name,
        created_at,
        file_path,
        hash

    )

    VALUES (?, datetime('now', 'localtime'), ?, ?)

    """, (case_name, file_path, file_hash))

    conn.commit()

    conn.close()


# FETCH FORENSIC CASES

def fetch_forensic_cases():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    SELECT *

    FROM forensic_cases

    ORDER BY id DESC

    """)

    rows = cursor.fetchall()

    conn.close()

    return [dict(row) for row in rows]


# =========================================
# CURSOR TABLE
# =========================================

def create_cursor_table():

    conn=get_connection()

    cursor=conn.cursor()

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS scan_cursors(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        source TEXT UNIQUE,

        last_event_record_id INTEGER,

        last_timestamp TEXT,

        updated_at TEXT
    )

    """)

    conn.commit()

    conn.close()


# =========================================
# GET CURSOR
# =========================================

def get_cursor(source):

    conn=get_connection()

    cursor=conn.cursor()

    cursor.execute("""

    SELECT *
    FROM scan_cursors
    WHERE source=?

    """,(source,))

    row=cursor.fetchone()

    conn.close()

    return dict(row) if row else None


# =========================================
# UPDATE CURSOR
# =========================================

def update_cursor(

    source,

    event_record_id,

    timestamp
):

    conn=get_connection()

    cursor=conn.cursor()

    cursor.execute("""

    INSERT INTO scan_cursors(

        source,
        last_event_record_id,
        last_timestamp,
        updated_at

    )

    VALUES(?,?,?,?)

    ON CONFLICT(source)
    DO UPDATE SET

        last_event_record_id=
        excluded.last_event_record_id,

        last_timestamp=
        excluded.last_timestamp,

        updated_at=
        excluded.updated_at

    """,(

        source,

        event_record_id,

        timestamp,

        datetime.now().isoformat()
    ))

    conn.commit()

    conn.close()


# INITIALIZE DATABASE ON IMPORT
initialize_database()
create_cursor_table()