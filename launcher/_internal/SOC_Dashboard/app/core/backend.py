# backend.py
"""
Backend Logic for SOC Simulator - Fixed Database Schema
"""

from database import get_connection
import sqlite3
import hashlib
import json
import os
import random
import pandas as pd
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import win32evtlog
from config import DB_NAME, KEY_FILE, RULES_FILE, LOGS_DIR
import subprocess
from rules import WINDOWS_EVENT_RULES
from engines.correlation_engine import correlate_alerts
from engines.timeline_engine import (
    build_attack_timeline,
    detect_attack_progression
)
import queue
import threading

stop_event = threading.Event()

alert_queue=queue.Queue()

def get_last_raw_log_timestamp():

    conn=get_connection()
    cursor=conn.cursor()

    cursor.execute("""
    SELECT MAX(timestamp)
    FROM raw_logs
    """)

    result=cursor.fetchone()

    conn.close()

    if result and result[0]:
        return result[0]

    return None

def store_raw_logs(df):

    if df.empty:
        return

    conn=get_connection()
    cursor=conn.cursor()

    inserted=0

    for _,row in df.iterrows():

        try:

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
                str(row.get('timestamp','')),
                str(row.get('source','Windows')),
                int(row.get('event_id',0)),
                str(row.get('computer','')),
                str(row.get('user','')),
                str(row.get('process_name','')),
                str(row.get('severity','MEDIUM')),
                str(row.get('description','')),
                str(row.to_dict())
            ))

            inserted+=1

        except Exception as e:
            print("Raw log insert error:",e)

    conn.commit()
    conn.close()

    # ================= SAVE RAW JSON EVIDENCE =================

    os.makedirs("raw_events", exist_ok=True)

    timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")

    raw_file=f"raw_events/security_logs_{timestamp}.json"

    try:

        df.to_json(
            raw_file,
            orient="records",
            indent=4
        )

        print(f"Raw logs saved to: {raw_file}")

    except Exception as e:

        print("Raw JSON save error:",e)

   # print(f"Stored {inserted} raw logs")


def background_db_writer():
    conn=sqlite3.connect(
        DB_NAME,
        check_same_thread=False
    )

    cursor=conn.cursor()

    batch=[]

    while not stop_event.is_set():

        try:

            alert=alert_queue.get(timeout=1)

            batch.append((
                alert.get("timestamp"),
                alert.get("type"),
                alert.get("severity"),
                alert.get("log_source"),
                alert.get("event_id",0),
                alert.get("description")
            ))

            # batch insert
            if len(batch)>=100:

                cursor.executemany("""

                    INSERT INTO alerts(
                        timestamp,
                        type,
                        severity,
                        log_source,
                        event_id,
                        description
                    )

                    VALUES(?,?,?,?,?,?)

                """,batch)

                conn.commit()

                batch.clear()

        except queue.Empty:

            if batch:

                cursor.executemany("""

                    INSERT INTO alerts(
                        timestamp,
                        type,
                        severity,
                        log_source,
                        event_id,
                        description
                    )

                    VALUES(?,?,?,?,?,?)

                """,batch)

                conn.commit()

                batch.clear()

def enable_audit_policies():
    commands = [
        ['auditpol', '/set', '/subcategory:Logon', '/success:enable', '/failure:enable'],
        ['auditpol', '/set', '/subcategory:Process Creation', '/success:enable'],
        ['auditpol', '/set', '/subcategory:Sensitive Privilege Use', '/success:enable', '/failure:enable'],
        ['auditpol', '/set', '/subcategory:File System', '/success:enable', '/failure:enable']
    ]

    for cmd in commands:
        try:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except Exception as e:
            print("Audit policy error:", e)

# def enable_folder_audit(path="C:\\"):
#     cmd = f'icacls "{path}" /setaudit *(OI)(CI)F'
#     try:
#         subprocess.run(cmd, shell=True)
#     except Exception as e:
#         print("Folder audit error:", e)
# ====================== Detection Engine Function ======================
def load_raw_logs(time_range="24h", limit=10000):

    try:

        conn=sqlite3.connect(DB_NAME)

        hours=int(time_range.replace("h",""))

        cutoff=(
            datetime.now()-timedelta(hours=hours)
        ).isoformat()

        query=f"""
        SELECT *
        FROM raw_logs
        WHERE timestamp>=?
        ORDER BY timestamp DESC
        LIMIT {limit}
        """

        df=pd.read_sql_query(
            query,
            conn,
            params=(cutoff,)
        )

        conn.close()

        return df

    except Exception as e:

        print(f"load_raw_logs error: {e}")

        return pd.DataFrame()

def detect_hids_events(df):
    rules = RULES.get(
    "hids_rules",
    {}
)
    for rule_name, rule in rules.items():
        generated_alerts=set()
    
    alerts=[]

    if df.empty:
        print("No logs found to analyze")
        return alerts

    df['timestamp']=pd.to_datetime(
        df['timestamp'],
        format='mixed',
        errors='coerce'
    )

    df=df.sort_values(
        'timestamp'
    ).reset_index(drop=True)

    # ================= EVENT ID BASED RULES =================

    for _,row in df.iterrows():

        try:

            event_id=int(row.get("event_id",0))

            if event_id in WINDOWS_EVENT_RULES:

                rule=WINDOWS_EVENT_RULES[event_id]

                alert_type=rule.get(
                    "description",
                    rule_name
                )

                alert_severity=rule.get(
                    "severity",
                    "MEDIUM"
                )

                alert_key=f"{alert_type}_{alert_severity}"

                if alert_key in generated_alerts:
                    continue
                
                generated_alerts.add(alert_key)

                alerts.append({
                    "timestamp":row['timestamp'].isoformat(),
                    "event_id":event_id,
                    "type":rule["name"],
                    "severity":rule["severity"],
                    "description":rule["description"],
                    "explanation":f"Windows Event ID {event_id} triggered detection rule.",
                    "log_source":"HIDS",
                    "status":"New"
                })

        except Exception as e:
            print("Rule processing error:",e)

    # ================= BRUTE FORCE DETECTION =================

    failed_logins=df[
        df['event_id']==4625
    ]

    if len(failed_logins)>=5:

        alerts.append({

            "timestamp":datetime.now().isoformat(),

            "event_id":4625,

            "type":"Brute Force Login Attempt",

            "severity":"HIGH",

            "description":"Multiple failed login attempts detected in short timeframe.",

            "explanation":"5 or more failed authentication events detected.",

            "log_source":"HIDS",

            "status":"New"
        })

    # ================= RAPID PROCESS SPAWN =================

    process_events=df[
        df['event_id']==4688
    ]

    if len(process_events)>=20:

        alerts.append({

            "timestamp":datetime.now().isoformat(),

            "event_id":4688,

            "type":"Rapid Process Spawn Activity",

            "severity":"MEDIUM",

            "description":"Large number of processes created within short duration.",

            "explanation":"Potential malware execution or scripting activity.",

            "log_source":"HIDS",

            "status":"New"
        })

    # ================= SECURITY LOG CLEARED =================

    log_clear=df[
        df['event_id']==1102
    ]

    if not log_clear.empty:

        alerts.append({

            "timestamp":datetime.now().isoformat(),

            "event_id":1102,

            "type":"Security Log Clearing Detected",

            "severity":"HIGH",

            "description":"Windows Security logs were cleared.",

            "explanation":"Possible anti-forensics activity detected.",

            "log_source":"HIDS",

            "status":"New"
        })

    # ================= MULTIPLE ADMIN EVENTS =================

    admin_events=df[
        df['event_id']==4672
    ]

    if len(admin_events)>=3:

        alerts.append({

            "timestamp":datetime.now().isoformat(),

            "event_id":4672,

            "type":"Repeated Administrative Privilege Assignment",

            "severity":"HIGH",

            "description":"Multiple administrative privilege assignment events detected.",

            "explanation":"Potential privilege escalation behavior.",

            "log_source":"HIDS",

            "status":"New"
        })

        # ================= CORRELATION ENGINE =================

    correlation_df=pd.DataFrame(alerts)

    correlated_incidents=correlate_alerts(correlation_df)

    if correlated_incidents:

        print(
            f"Correlated incidents detected: "
            f"{len(correlated_incidents)}"
        )

        alerts.extend(correlated_incidents)
    print(f"Total alerts generated from detection engine: {len(alerts)}")
    return alerts

# ====================== Encryption ======================
def get_encryption_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key

cipher_suite = Fernet(get_encryption_key())

# ====================== FIXED Database Initialization ======================
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            type TEXT,
            severity TEXT,
            description TEXT,
            explanation TEXT,
            hash TEXT,
            encrypted_data BLOB,
            log_source TEXT DEFAULT 'Simulated',
            status TEXT DEFAULT 'New',
            event_id INTEGER DEFAULT 0
        )
        ''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS incidents
                 (id INTEGER PRIMARY KEY, incident_id TEXT, alerts_count INTEGER, 
                  status TEXT, start_time TEXT)''')
    c.execute("""
    CREATE TABLE IF NOT EXISTS file_snapshots(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT,
        file_hash TEXT,
        last_modified TEXT,
        file_size INTEGER,
        created_at TEXT
    )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_type ON alerts(type)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)")
    
    conn.commit()
    conn.close()

init_db()

# ====================== Rules ======================
def load_rules():
    default_rules = {
        "hids_rules": {
            "auth_failure": {"threshold": 5, "window_min": 5, "severity": "HIGH", "desc": "Brute force attempt"},
            "privilege_escalation": {"threshold": 1, "window_min": 1, "severity": "HIGH", "desc": "Privilege escalation detected"},
            "suspicious_process": {"threshold": 3, "window_min": 10, "severity": "MEDIUM", "desc": "Suspicious process activity"}
        },
        "nids_rules": {
            "port_scan": {"threshold": 10, "window_sec": 60, "severity": "HIGH", "desc": "Port scanning detected"},
            "syn_flood": {"threshold": 100, "window_sec": 30, "severity": "HIGH", "desc": "SYN flood attack"},
            "reconnaissance": {"threshold": 5, "window_sec": 300, "severity": "MEDIUM", "desc": "Reconnaissance activity"}
        }
    }
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r') as f:
            return json.load(f)
    else:
        with open(RULES_FILE, 'w') as f:
            json.dump(default_rules, f, indent=4)
        return default_rules

RULES = load_rules()

# ====================== Real Windows Security Logs ======================
max_events=10000
def read_windows_security_logs(start_time=None,hours=24):

    try:

        hand=win32evtlog.OpenEventLog(None,"Security")

        flags=(
            win32evtlog.EVENTLOG_BACKWARDS_READ |
            win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        # ================= DETERMINE CUTOFF =================

        if start_time:

            if isinstance(start_time,str):
                cutoff=datetime.fromisoformat(start_time)
            else:
                cutoff=start_time

        else:
            cutoff=datetime.now()-timedelta(hours=hours)

        log_data=[]
        count=0

        # ================= READ WINDOWS EVENTS =================
        max_events=150000
        while True:

            # ================= STOP IF LIMIT REACHED =================

            if count >= max_events:
                break
            
            events = win32evtlog.ReadEventLog(hand, flags, 0)

            if not events:
                break
            
            for event in events:
            
                # ================= STOP AGAIN INSIDE LOOP =================

                if count >= max_events:
                    break
                
                try:
                
                    event_time = event.TimeGenerated

                    # ================= SKIP OLD EVENTS =================

                    if event_time < cutoff:
                        continue
                    
                    event_id = event.EventID & 0xFFFF

                    entry = {
                    
                        "timestamp": event_time.isoformat(),

                        "event_id": event_id,

                        "source": event.SourceName,

                        "log_source": "Security",

                        "computer": str(event.ComputerName),

                        "user": "",

                        "process_name": "",

                        "type": "raw_event",

                        "severity": "INFO",

                        "description": f"Event ID {event_id} from {event.SourceName}"

                    }

                    log_data.append(entry)

                    count += 1

                except Exception as e:
                
                    print("Event parsing error:", e)

        win32evtlog.CloseEventLog(hand)

        print(f"Total Windows Security logs collected: {count}")

        # ================= DATAFRAME =================

        df=pd.DataFrame(log_data)

        if df.empty:
            print("No logs collected")
            return df

        # ================= STORE RAW LOGS =================

        store_raw_logs(df)

        print(f"Stored {len(df)} raw logs")

        # ================= DETECTION ENGINE =================

        print("Running detection engine...")

        alerts=detect_hids_events(df)

        print(f"Alerts generated: {len(alerts)}")

        # ================= STORE ALERTS =================

        for alert in alerts:
            store_alert(alert)

        print(f"Successfully stored {len(alerts)} alerts")

        return df

    except Exception as e:

        print(f"HIDS ERROR: {e}")

        import traceback
        traceback.print_exc()

        return pd.DataFrame()

# ====================== Simulation ======================
def simulate_hids_data(num_events=25):
    events = []
    types = ['auth_failure', 'privilege_escalation', 'suspicious_process']
    for _ in range(num_events):
        t = random.choice(types)
        entry = {
            'timestamp': (datetime.now() - timedelta(minutes=random.randint(1, 720))).isoformat(),
            'type': t,
            'severity': 'HIGH' if t == 'auth_failure' else 'MEDIUM',
            'description': f"Simulated {t.replace('_', ' ').title()}",
            'log_source': 'Simulated'
        }
        events.append(entry)
    return pd.DataFrame(events)

def simulate_nids_data(num=30):
    packets = []
    types = ['port_scan', 'syn_flood', 'reconnaissance']
    for _ in range(num):
        t = random.choice(types)
        entry = {
            'timestamp': (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat(),
            'type': t,
            'severity': 'HIGH',
            'description': f"Simulated {t.replace('_', ' ')}",
            'log_source': 'Simulated'
        }
        packets.append(entry)
    return pd.DataFrame(packets)

# ====================== gropuing alerts ======================
def group_alerts(alerts_df, time_bucket_minutes=20):
    if alerts_df.empty:
        return pd.DataFrame()

    df = alerts_df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='mixed', errors='coerce')

    freq = f'{time_bucket_minutes}min'
    df['time_bucket'] = df['timestamp'].dt.floor(freq)

    grouped = df.groupby(
        ['type', 'severity', 'log_source', 'time_bucket'],
        as_index=False
    ).agg(
        count=('id', 'count'),
        last_seen=('timestamp', 'max'),
        first_seen=('timestamp', 'min')
    )

    grouped = grouped.sort_values(by='last_seen', ascending=False)

    return grouped

# ====================== Storage ======================
def store_alert(alert_data):

    conn=sqlite3.connect(DB_NAME)

    cursor=conn.cursor()

    cursor.execute("""

        INSERT INTO alerts(

            timestamp,
            type,
            severity,
            log_source,
            event_id,
            description

        )

        VALUES(?,?,?,?,?,?)

    """,(

        alert_data.get("timestamp"),

        alert_data.get("type"),

        alert_data.get("severity"),

        alert_data.get("log_source"),

        alert_data.get("event_id",0),

        alert_data.get("description")

    ))

    conn.commit()
    conn.close()

def mark_alert(alert_id: int, status: str):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    conn.commit()
    conn.close()

def generate_explanation(alert_type: str, description: str) -> str:
    return f"{description} (Rule-based detection)"

def load_alerts(time_range="24h", search_term="", limit=5000):

    conn=sqlite3.connect(DB_NAME)

    query="""
        SELECT * FROM alerts
    """

    conditions=[]
    params=[]

    if time_range!="All":

        hours_map={
            "1h":1,
            "6h":6,
            "12h":12,
            "24h":24,
            "3d":72,
            "7d":168,
            "15d":360,
            "30d":720
        }

        hours=hours_map.get(
            time_range,
            24
        )

        cutoff=(
            datetime.now()
            - timedelta(hours=hours)
        ).isoformat()

        conditions.append(
            "timestamp>=?"
        )

        params.append(cutoff)

    if search_term:

        conditions.append("""
            (
                type LIKE ?
                OR severity LIKE ?
                OR description LIKE ?
                OR log_source LIKE ?
            )
        """)

        term=f"%{search_term}%"

        params.extend([
            term,
            term,
            term,
            term
        ])

    if conditions:

        query += " WHERE " + " AND ".join(conditions)

    query += f"""
        ORDER BY timestamp DESC
        LIMIT {limit}
    """

    try:

        df=pd.read_sql_query(
            query,
            conn,
            params=params
        )

    except Exception as e:

        print("load_alerts error:",e)

        df=pd.DataFrame()

    conn.close()

    return df

def generate_forensic_timeline(time_range="24h"):

    alerts_df=load_alerts(
        time_range=time_range
    )

    if alerts_df.empty:

        return {
            "timeline":[],
            "attack_chain":[]
        }

    timeline=build_attack_timeline(
        alerts_df
    )

    attack_chain=detect_attack_progression(
        alerts_df
    )

    return {

        "timeline":timeline,

        "attack_chain":attack_chain
    }

ALERT_CATEGORY_MAP={

    "Authentication":[
        "login",
        "brute force",
        "rdp",
        "lockout",
        "authentication"
    ],

    "Privilege Escalation":[
        "privilege",
        "uac",
        "token",
        "admin"
    ],

    "Persistence":[
        "scheduled task",
        "service",
        "startup",
        "registry",
        "wmi"
    ],

    "Credential Access":[
        "mimikatz",
        "lsass",
        "credential",
        "samdump"
    ],

    "Lateral Movement":[
        "psexec",
        "smb",
        "wmic",
        "remote desktop"
    ],

    "Defense Evasion":[
        "defender",
        "amsi",
        "tampering",
        "sysmon"
    ],

    "Execution":[
        "powershell",
        "script",
        "macro",
        "cmd",
        "lolbin"
    ],

    "Reconnaissance":[
        "enumeration",
        "bloodhound",
        "scan",
        "whoami",
        "systeminfo"
    ],

    "Command and Control":[
        "beacon",
        "reverse shell",
        "dns tunnel",
        "c2"
    ],

    "Data Exfiltration":[
        "upload",
        "dropbox",
        "mega",
        "exfiltration"
    ],

    "Ransomware":[
        "encrypted",
        "ransomware",
        "shadowcopy",
        ".locked"
    ],

    "Network Scanning":[
        "port scan",
        "network scan",
        "smb enumeration"
    ],

    "System Tampering":[
        "log cleared",
        "firewall",
        "boot",
        "service tampering"
    ]
}

def calculate_alert_categories(df):

    category_counts={

        "Authentication":0,
        "Privilege Escalation":0,
        "Persistence":0,
        "Credential Access":0,
        "Lateral Movement":0,
        "Defense Evasion":0,
        "Execution":0,
        "Reconnaissance":0,
        "Command & Control":0,
        "Data Exfiltration":0,
        "Ransomware":0,
        "Network Scanning":0,
        "System Tampering":0,
        "Others":0
    }

    if df.empty:
        return category_counts

    for _,row in df.iterrows():

        text=" ".join([

            str(row.get("type","")),
            str(row.get("description",""))

        ]).lower()

        matched=False

        for category,keywords in ALERT_CATEGORY_MAP.items():

            if any(k.lower() in text for k in keywords):

                category_counts[category]+=1

                matched=True
                break

        if not matched:
            category_counts["Others"]+=1

    return category_counts

def get_last_alert_timestamp():
    """Get the timestamp of the most recent alert"""
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT MAX(timestamp) as last_ts FROM alerts", conn)
    conn.close()
    
    if df.empty or df.iloc[0]['last_ts'] is None:
        return datetime.now() - timedelta(hours=24)
    
    return pd.to_datetime(df.iloc[0]['last_ts'])

def load_incidents():
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM incidents", conn)
    conn.close()
    return df

def create_logs_folder_and_save(df: pd.DataFrame, data_type="alerts", encrypt=True):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = f"{LOGS_DIR}_{timestamp}"
    os.makedirs(folder_name, exist_ok=True)

    json_path = os.path.join(folder_name, f"{data_type}.json")
    csv_path = os.path.join(folder_name, f"{data_type}.csv")

    df.to_json(json_path, orient="records", indent=4)
    df.to_csv(csv_path, index=False)

    # Save rules snapshot
    with open(os.path.join(folder_name, "rules.json"), 'w') as f:
        json.dump(RULES, f, indent=4)

    # 🔐 Encrypt files
    if encrypt:
        for file_path in [json_path, csv_path]:
            with open(file_path, "rb") as f:
                encrypted = cipher_suite.encrypt(f.read())

            enc_path = file_path + ".enc"
            with open(enc_path, "wb") as f:
                f.write(encrypted)

            os.remove(file_path)  # remove plain file

    return folder_name
      
def decrypt_file(file_path):
    with open(file_path, "rb") as f:
        decrypted = cipher_suite.decrypt(f.read())

    output_path = file_path.replace(".enc", "_decrypted.json")

    with open(output_path, "wb") as f:
        f.write(decrypted)

    return output_path