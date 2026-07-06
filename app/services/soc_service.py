from datetime import datetime
import pandas as pd
import os
import json
import csv

from app.collectors.collector_manager import (
    collect_all_logs
)

from app.collectors.forensic_scanner import (
    scan_filesystem
)

from app.engines.detection_engine import (
    detect_advanced_threats
)

from app.engines.correlation_engine import (
    correlate_alerts
)

from app.database.database import (
    fetch_recent_alerts,
    get_connection
)

from app.engines.incident_engine import (
    build_incidents
)

from app.core.session_manager import (

    create_new_session

)

from app.alerts.alert_manager import store_alert



class SOCService:

    def __init__(self):

        self.scan_running=False

        self.last_scan_time=None

        self.last_scan_type="NONE"

    # =========================================
    # RESET LIVE DASHBOARD
    # =========================================

    def reset_live_dashboard(self):

        conn = get_connection()

        cursor = conn.cursor()

        cursor.execute("""

        DELETE FROM alerts

        WHERE timestamp IS NULL

        """)

        conn.commit()

        conn.close()

        self.last_scan_time = None

        self.last_scan_type = "NONE"

        print(
            "[SOC] Live dashboard reset"
        )

    def run_incremental_refresh(self):

        print("\n==============================")
        print("SOC REFRESH STARTED")
        print("==============================")

        logs=collect_all_logs(hours=24)

        print(f"[+] New logs collected: {len(logs)}")

        alerts=detect_advanced_threats(logs)

        print(f"[+] New alerts generated: {len(alerts)}")

        for a in alerts:

            store_alert(a)

        self.last_scan_type="REFRESH"

        self.last_scan_time=datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        return {

            "status":"success",
            "alerts":len(alerts)
        }
    # =========================================
    # STORE RAW LOGS
    # =========================================

    def store_raw_logs(self,df):

        if df.empty:
            return

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

    # =========================================
    # FULL SCAN
    # =========================================

    def run_full_scan(self):

        session_id = create_new_session(
            "FULL_SCAN"
        )

        print(
            f"[SOC] Session Created: {session_id}"
        )

        if self.scan_running:

            return {

                "status":"already_running"
            }

        self.scan_running=True
        self.last_scan_type="FULL SCAN"

        self.last_scan_time=datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        try:

            # =====================================
            # COLLECT SYSLOGS
            # =====================================

            print("\n==============================")
            print("[SOC] FULL SCAN STARTED")
            print("==============================")

            print("\n[1] Collecting System Logs...")

            logs_df=collect_all_logs(hours=24)

            print(f"[+] Total logs collected: {len(logs_df)}")

            if logs_df.empty:

                return {

                    "status":"error",

                    "message":"No logs collected"
                }

            # =====================================
            # STORE RAW LOGS
            # =====================================
            print("\n[2] Storing Raw Logs...")
            self.store_raw_logs(logs_df)
            print("[+] Raw logs stored successfully")

            # =====================================
            # DETECTION ENGINE
            # =====================================
            print("\n[3] Running Detection Engine...")
            detected_alerts= detect_advanced_threats(logs_df)
            if not detected_alerts:

                print("[SOC] No threats detected.")

                self.scan_running=False

                return {
                
                    "status":"success",

                    "raw_logs":len(logs_df),

                    "alerts_generated":0,

                    "incidents":0,

                    "last_scan":self.last_scan_time
                }
            # detected_alerts=group_alerts(detected_alerts)
            print(f"[+] Alerts generated: {len(detected_alerts)}")

            # =====================================
            # SEVERITY DISTRIBUTION
            # =====================================

            severity_counts = {}

            for alert in detected_alerts:
            
                sev = alert.get(
                    "severity",
                    "LOW"
                )

                severity_counts[sev] = \
                severity_counts.get(sev,0)+1

            print(
                f"[SOC] Severity Distribution: "
                f"{severity_counts}"
            )

            # =====================================
            # STORE ALERTS
            # =====================================

            print("\n[4] Storing Alerts...")

            stored_count = 0

            for alert in detected_alerts:
            
                try:
                   
                    timestamp_value = alert.get(
                        "timestamp",
                        datetime.now()
                    )
                    if hasattr(
                        timestamp_value,
                        "isoformat"
                    ):
                        timestamp_value = (
                            timestamp_value.isoformat()
                        )
                    # Use scan time (now) as the alert timestamp.
                    # Log events may be hours/days old; using their
                    # original timestamp means time filters like
                    # "Last 1hr" would find zero alerts from old logs.
                    # Scan time = when the threat was detected, which
                    # is the operationally correct value for filtering.
                    scan_timestamp = datetime.now().isoformat()

                    clean_alert = {

                        "timestamp":   scan_timestamp,

                        "type":
                        alert.get(
                            "type",
                            alert.get("name", "Unknown")
                        ),

                        "severity":
                        alert.get(
                            "severity",
                            "LOW"
                        ),

                        "log_source":
                        alert.get(
                            "log_source",
                            "SYSTEM"
                        ),

                        "category":
                        alert.get(
                            "category",
                            "Others"
                        ),

                        "event_id":
                        alert.get(
                            "event_id",
                            0
                        ),

                        "description":
                        alert.get(
                            "description",
                            "No Description"
                        ),

                        # Pass MITRE fields through so they
                        # appear in the Alert Queue MITRE column
                        "mitre_tactic":
                        alert.get("mitre_tactic", ""),

                        "mitre_technique":
                        alert.get("mitre_technique", ""),

                        "status":     "New",
                        "session_id": session_id
                    }

                    success = store_alert(
                        clean_alert
                    )

                    if success:
                    
                        stored_count += 1

                        self.archive_alert(
                        
                            alert=clean_alert,

                            session_id=session_id
                        )

                except Exception as e:
                
                    print(
                        f"[STORE ALERT ERROR] {e}"
                    )

            print(
                f"[+] Alerts stored: {stored_count}"
            )
            conn = get_connection()

            cursor = conn.cursor()

            cursor.execute(
                "SELECT COUNT(*) FROM alerts"
            )

            total = cursor.fetchone()[0]

            conn.close()

            print(
                f"[DATABASE] Total alerts in DB: {total}"
            )

            # =====================================
            # CORRELATION ENGINE
            # =====================================

            alerts_df=pd.DataFrame(detected_alerts)
            if alerts_df.empty:

                incidents=[]

            else:
            
                incidents=build_incidents(alerts_df)

            incidents=build_incidents(alerts_df)

            print(
                f"[+] Incidents created: "
                f"{len(incidents)}")
            
            print("\n[5] Running Correlation Engine...")
            incidents= correlate_alerts(alerts_df)
            print(f"[+] Incidents grouped: {len(incidents)}")

            # for incident in incidents:

            #     store_alert(incident)

            # =====================================
            # FORENSIC SCAN
            # =====================================
            print("\n[6] Running Forensic Scan...")
            scan_filesystem()
            print("[+] Forensic scan completed")

            # =====================================
            # LAST SCAN
            # =====================================
            print("\n==============================")
            print("[SOC] FULL SCAN COMPLETED")
            print("==============================")
            self.last_scan_time= datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.last_scan_type="FULL_SCAN"

            return {

                "status":"success",

                "raw_logs":
                len(logs_df),

                "alerts_generated":
                len(detected_alerts),

                "incidents":
                len(incidents),

                "last_scan":
                self.last_scan_time
            }

        except Exception as error:

            return {

                "status":"error",

                "message":str(error)
            }

        finally:

            self.scan_running=False

    # =========================================
    # EXPORT FORENSIC EVIDENCE
    # =========================================

    def export_forensics(self):

        export_dir = "forensics_exports"

        os.makedirs(

            export_dir,

            exist_ok=True
        )

        timestamp = datetime.now().strftime(

            "%Y%m%d_%H%M%S"
        )

        conn = get_connection()

        cursor = conn.cursor()

        # =====================================
        # EXPORT ALERTS
        # =====================================
    
        cursor.execute("""
    
            SELECT
                timestamp,
                type,
                severity,
                category,
                description
    
            FROM alerts
    
            ORDER BY id DESC
    
        """)
    
        alerts = cursor.fetchall()
    
        alerts_file = os.path.join(
        
            export_dir,
    
            f"alerts_{timestamp}.csv"
        )
    
        with open(
        
            alerts_file,
    
            "w",
    
            newline="",
    
            encoding="utf-8"
        ) as file:
    
            writer = csv.writer(file)
    
            writer.writerow([
            
                "Timestamp",
                "Type",
                "Severity",
                "Category",
                "Description"
            ])
    
            writer.writerows(alerts)
    
        # =====================================
        # EXPORT INCIDENTS
        # =====================================
    
        cursor.execute("""
    
            SELECT
                group_id,
                type,
                severity,
                description
    
            FROM alerts
    
            WHERE group_id IS NOT NULL
    
        """)
    
        incidents = cursor.fetchall()
    
        incidents_file = os.path.join(
        
            export_dir,
    
            f"incidents_{timestamp}.json"
        )
    
        incident_data = []
    
        for row in incidents:
        
            incident_data.append({
            
                "group_id":
                row[0],
    
                "type":
                row[1],
    
                "severity":
                row[2],
    
                "description":
                row[3]
            })
    
        with open(
        
            incidents_file,
    
            "w",
    
            encoding="utf-8"
        ) as file:
    
            json.dump(
            
                incident_data,
    
                file,
    
                indent=4
            )
    
        # =====================================
        # EXPORT SNAPSHOT
        # =====================================
    
        snapshot_file = os.path.join(
        
            export_dir,
    
            f"snapshot_{timestamp}.txt"
        )
    
        with open(
        
            snapshot_file,
    
            "w",
    
            encoding="utf-8"
        ) as file:
    
            file.write(
            
                "SOC FORENSIC SNAPSHOT\n"
            )
    
            file.write(
            
                f"Generated: {datetime.now()}\n\n"
            )
    
            file.write(
            
                f"Total Alerts: {len(alerts)}\n"
            )
    
            file.write(
            
                f"Total Incidents: {len(incident_data)}\n"
            )
    
        conn.close()
    
        print(
            f"[+] Forensics exported: {timestamp}"
        )
    
        return {
        
            "status":"success",
    
            "timestamp":timestamp
        }        

    # =========================================
    # REFRESH ALERTS
    # =========================================

    def refresh_alerts(self):

        print("\n==============================")
        print("[SOC] REFRESH STARTED")
        print("==============================")

        manager.send_console("SOC REFRESH STARTED")
        manager.send_console("[1] Collecting new events since last scan...")

        # Collect only last 1 hour of new events
        # Collectors use cursors so they only return events
        # newer than the last scan's cursor position
        logs_df = collect_all_logs(hours=24)

        print(f"[+] New logs collected: {len(logs_df)}")
        manager.send_console(f"[+] New logs collected: {len(logs_df)}")

        if logs_df.empty:
            self.last_scan_type = "REFRESH"
            self.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return {"status": "success", "new_alerts": 0}

        self.store_raw_logs(logs_df)

        manager.send_console("[2] Running Detection Engine...")
        alerts = detect_advanced_threats(logs_df)

        print(f"[+] New alerts generated: {len(alerts)}")
        manager.send_console(f"[+] Detection engine found: {len(alerts)} potential alerts")

        new_count = 0
        scan_ts   = datetime.now().isoformat()

        for alert in alerts:
            # Build clean_alert the SAME way run_full_scan does
            # so the hash is computed consistently
            clean_alert = {
                "timestamp":       scan_ts,
                "type":            alert.get("type", alert.get("name", "Unknown")),
                "severity":        alert.get("severity", "LOW"),
                "log_source":      alert.get("log_source", "SYSTEM"),
                "category":        alert.get("category", "Others"),
                "event_id":        alert.get("event_id", 0),
                "description":     alert.get("description", "No Description"),
                "mitre_tactic":    alert.get("mitre_tactic", ""),
                "mitre_technique": alert.get("mitre_technique", ""),
                "status":          "New",
            }
            inserted = store_alert(clean_alert)
            if inserted:
                new_count += 1

        self.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.last_scan_type = "REFRESH"

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total = cursor.fetchone()[0]
        conn.close()

        print(f"[+] {new_count} genuinely new alerts stored (total: {total})")
        manager.send_console(f"[+] {new_count} new alerts added (total: {total})")
        manager.send_scan_end(total_alerts=total)

        print("==============================")

        return {
            "status":    "success",
            "new_alerts": new_count,
            "total":      total,
            "last_scan":  self.last_scan_time
        }

    # =========================================
    # RECENT ALERTS
    # =========================================

    def get_recent_alerts(self):

        return fetch_recent_alerts(
            limit=500
        )

    # =========================================
    # STATUS
    # =========================================

    def get_scan_status(self):

        return {

            "running":
            self.scan_running,
        
            "last_scan":
            self.last_scan_time,
        
            "scan_type":
            self.last_scan_type
        }
    
    # =========================================
    # ARCHIVE ALERT
    # =========================================

    def archive_alert(

        self,

        alert,

        session_id
    ):

        conn = get_connection()

        cursor = conn.cursor()

        cursor.execute("""

        INSERT INTO alert_archive(

            session_id,
            timestamp,
            type,
            severity,
            category,
            description,
            source

        )

        VALUES(?,?,?,?,?,?,?)

        """,(

            session_id,

            alert.get("timestamp"),

            alert.get("type"),

            alert.get("severity"),

            alert.get("category"),

            alert.get("description"),

            alert.get("log_source")
        ))

        conn.commit()

        conn.close()

soc_service=SOCService()