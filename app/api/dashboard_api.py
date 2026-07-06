from collections import Counter
from fastapi import APIRouter, BackgroundTasks, Form
from pydantic import BaseModel
import os
import json
import pandas as pd
from datetime import datetime, timezone, timedelta
import hashlib
from pathlib import Path
from fastapi.responses import JSONResponse

from app.services.soc_service import soc_service
from app.database.database import (
    get_connection,
    update_alert_status,
    insert_case_report,
    fetch_case_reports,
    insert_forensic_case,
    fetch_forensic_cases
)
from app.engines.timeline_engine import (
    build_attack_timeline,
    detect_attack_progression
)
from app.engines.threat_hunting_engine import (
    hunt
)
from app.collectors.system_info import (
    get_system_info
)


router = APIRouter()


@router.get("/api/system-info")
async def system_info():
    return get_system_info()


# =========================================
# HUNT
# =========================================

@router.get("/api/hunt")
async def hunt_logs(query: str = ""):
    alerts = soc_service.get_recent_alerts()
    df = pd.DataFrame(alerts)
    return {"results": hunt(df, query)}


# =========================================
# RUN FULL SOC SCAN
# =========================================

# =========================================
# SCAN STATE (in-memory, process-scoped)
# =========================================
_scan_state = {"running": False, "completed_at": None, "total_alerts": 0, "scan_type": "NONE"}


def _run_scan_background():
    """Run full scan in background so the HTTP response returns immediately."""
    global _scan_state
    _scan_state["running"]      = True
    _scan_state["completed_at"] = None
    _scan_state["phase"]        = "Initialising scan..."

    print("\n==============================")
    print("SOC FULL SCAN STARTED")
    print("==============================")

    start_time = datetime.now()

    _scan_state["phase"] = "Collecting system logs..."
    soc_service.run_full_scan()
    _scan_state["phase"] = "Processing detections..."

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]
    conn.close()

    completed_at = datetime.now().isoformat()
    duration = (datetime.now() - start_time).total_seconds()
    print(f"\nTOTAL ALERTS : {total_alerts}")
    print(f"SCAN COMPLETED IN {duration:.2f} sec")
    print("==============================\n")

    _scan_state["phase"]        = f"Complete — {total_alerts} alerts"
    _scan_state["running"]      = False
    _scan_state["completed_at"] = completed_at
    _scan_state["total_alerts"] = total_alerts
    _scan_state["scan_type"]    = "FULL SCAN"


@router.post("/api/run-scan")
async def run_scan(background_tasks: BackgroundTasks):
    if _scan_state["running"]:
        return {"status": "already_running"}
    background_tasks.add_task(_run_scan_background)
    return {"status": "started", "message": "Scan started in background"}


@router.get("/api/scan-status")
async def scan_status():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total = cursor.fetchone()[0]
    conn.close()
    return {
        "running":      _scan_state["running"],
        "completed_at": _scan_state["completed_at"],
        "total_alerts": total,
        "scan_type":    _scan_state.get("scan_type", "NONE"),
        "phase":        _scan_state.get("phase", "")
    }


# =========================================
# TIMELINE
# =========================================

@router.get("/api/timeline")
async def timeline():
    alerts = soc_service.get_recent_alerts()
    df = pd.DataFrame(alerts)
    return {
        "timeline": build_attack_timeline(df),
        "attack_chain": detect_attack_progression(df)
    }


# =========================================
# REFRESH DASHBOARD (APPEND ONLY)
# =========================================

@router.post("/api/refresh")
async def refresh_dashboard():
    global _scan_state

    # Mark as running so JS poll can track it
    _scan_state["running"]   = True
    _scan_state["scan_type"] = "REFRESH"
    _scan_state["phase"]     = "Collecting new events..."

    print("\n==============================")
    print("SOC REFRESH STARTED")
    print("==============================")

    result = soc_service.refresh_alerts()

    # Get updated total
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total = cursor.fetchone()[0]
    conn.close()

    completed = datetime.now().isoformat()
    new_count = result.get("new_alerts", 0)

    print(f"[+] Refresh complete — {new_count} new alerts, {total} total")
    print("==============================\n")

    # Update state AFTER completion so JS poll sees it
    _scan_state["running"]      = False
    _scan_state["completed_at"] = completed
    _scan_state["total_alerts"] = total
    _scan_state["scan_type"]    = "REFRESH"
    _scan_state["phase"]        = f"Refresh complete — {new_count} new alerts"

    return {
        "status":     "success",
        "scan_type":  "REFRESH",
        "new_alerts": new_count,
        "total":      total,
        "message":    "Dashboard refreshed"
    }


# =========================================
# FETCH RECENT ALERTS (MAIN QUEUE)
# =========================================


# =========================================
# RESET DASHBOARD
# =========================================

@router.post("/api/reset")
async def reset_dashboard():
    global _scan_state

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM raw_logs")
    cursor.execute("DELETE FROM scan_cursors")
    conn.commit()
    conn.close()

    _scan_state.update({
        "running": False, "completed_at": None,
        "total_alerts": 0, "phase": "", "scan_type": "NONE"
    })
    soc_service.last_scan_time = None
    soc_service.last_scan_type = "NONE"

    try:
        from app.database.database import clear_persistent_seen
        clear_persistent_seen()
    except Exception:
        pass

    print("[SOC] Dashboard reset complete")
    return {"status": "success", "message": "Dashboard reset."}


@router.get("/api/alerts")
async def get_alerts():
    alerts = soc_service.get_recent_alerts()
    return alerts


@router.get("/api/live-alerts")
async def live_alerts():
    alerts = soc_service.get_recent_alerts()
    return {"alerts": alerts[-25:]}


# =========================================
# FETCH CHART AND VISUALIZATION DATA
# =========================================
# FIX: The original code used datetime.now() (naive local time) to compare
# against alert timestamps that are stored as UTC ISO strings, e.g.
# "2026-06-07T04:08:35.408Z". On Python <3.11, fromisoformat() cannot parse
# the trailing "Z", so the bare except silently dropped every alert, leaving
# the dashboard showing 0/stale counts even after a successful scan storing
# 131 alerts. Fix: strip the Z suffix and treat all timestamps as UTC, then
# compare against utcnow() so the math is always consistent regardless of
# the server's local timezone.
# =========================================

def _parse_timestamp_utc(ts_str: str):
    """
    Parse an ISO timestamp string into a UTC-aware datetime.
    Handles:
      - "2026-06-07T04:08:35.408Z"   (Sysmon / Windows Event Log)
      - "2026-06-07T04:08:35.408407" (no timezone suffix)
      - "2026-06-07 04:08:35"        (space separator)
    Returns None if the string cannot be parsed.
    """
    if not ts_str:
        return None

    s = str(ts_str).strip()

    # Replace space separator with T
    s = s.replace(" ", "T")

    # Strip trailing Z — treat as UTC
    if s.endswith("Z"):
        s = s[:-1]

    # Strip +00:00 or any explicit offset so fromisoformat works on 3.10
    if "+" in s[10:]:
        s = s[:s.rfind("+")]

    try:
        # Parse as naive, then attach UTC
        dt = datetime.fromisoformat(s)
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


@router.get("/api/chart-data")
async def chart_data(range: str = "7d"):

    alerts = soc_service.get_recent_alerts()

    # =====================================
    # FILTER HOURS
    # =====================================

    hours_map = {
        "1h":   1,
        "3h":   3,
        "6h":   6,
        "12h":  12,
        "24h":  24,
        "3d":   24,   # capped at 24h — collectors only reliable for 24h
        "7d":   24,
        "15d":  24,
        "30d":  24
    }

    selected_hours = hours_map.get(range, 24)

    # Use UTC now so it matches the Z-suffixed Sysmon timestamps
    now_utc = datetime.now(timezone.utc)
    cutoff  = now_utc - timedelta(hours=selected_hours)

    filtered = []

    for alert in alerts:

        ts = _parse_timestamp_utc(alert.get("timestamp", ""))

        if ts is None:
            # Unparseable timestamp — include rather than silently drop
            filtered.append(alert)
            continue

        try:
            if ts >= cutoff:
                filtered.append(alert)
        except TypeError:
            ts_cmp = ts.replace(tzinfo=None) if ts.tzinfo else ts
            cut_cmp = cutoff.replace(tzinfo=None) if cutoff.tzinfo else cutoff
            if ts_cmp >= cut_cmp:
                filtered.append(alert)

    # =====================================
    # COUNTERS — query DB directly so the
    # severity totals reflect ALL alerts,
    # not just the 500-row fetch slice.
    # =====================================

    conn_sev = get_connection()
    cur_sev  = conn_sev.cursor()
    cur_sev.execute("""
        SELECT severity, COUNT(*) as c
        FROM alerts
        GROUP BY severity
    """)
    severity_counter = Counter({r[0]: r[1] for r in cur_sev.fetchall()})

    cur_sev.execute("""
        SELECT
            COALESCE(NULLIF(TRIM(category), ''), 'Others') as cat,
            COUNT(*) as c
        FROM alerts
        GROUP BY cat
    """)
    # Build counter with string keys only — None/empty → "Others"
    category_counter = Counter()
    for row in cur_sev.fetchall():
        key = str(row[0]) if row[0] else "Others"
        category_counter[key] += row[1]
    conn_sev.close()

    # If time filter returned nothing, fall back to latest 500 from DB
    if not filtered:
        conn_fb = get_connection()
        cur_fb = conn_fb.cursor()
        cur_fb.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 500")
        rows = cur_fb.fetchall()
        conn_fb.close()
        filtered = [dict(r) for r in rows]

    # filtered is still used for the alert table rows
    _ = filtered  # keep reference

    return {

        "severity": {
            "LOW":      severity_counter["LOW"],
            "MEDIUM":   severity_counter["MEDIUM"],
            "HIGH":     severity_counter["HIGH"],
            "CRITICAL": severity_counter["CRITICAL"]
        },

        "categories": dict(category_counter),

        "total_alerts": (
            severity_counter["LOW"] +
            severity_counter["MEDIUM"] +
            severity_counter["HIGH"] +
            severity_counter["CRITICAL"]
        ),

        "alerts": filtered[:500],

        "last_scan": soc_service.get_scan_status()["last_scan"],

        "scan_type": soc_service.get_scan_status()["scan_type"]
    }


# =========================================
# GET SCANNER ENGINE STATUS
# =========================================

@router.get("/api/status")
async def get_status():
    return soc_service.get_scan_status()


# =========================================
# UPDATE ALERT STATUS (ANALYST WORKFLOW)
# =========================================

class StatusUpdate(BaseModel):
    status: str

@router.post("/api/alerts/update-status/{alert_id}")
async def update_status(alert_id: int, payload: StatusUpdate):
    update_alert_status(alert_id, payload.status)
    return {"status": "success", "message": "Alert status updated successfully"}


class GroupStatusUpdate(BaseModel):
    alert_ids: list
    status: str

@router.post("/api/alerts/update-group-status")
async def update_group_status(payload: GroupStatusUpdate):
    """Update status for all alerts in an incident group."""
    conn = get_connection()
    cursor = conn.cursor()
    for aid in payload.alert_ids:
        try:
            cursor.execute("UPDATE alerts SET status=? WHERE id=?", (payload.status, int(aid)))
        except Exception:
            pass
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"Group status updated to {payload.status}"}


# =========================================
# HIDS INCIDENTS GROUPING
# =========================================

@router.get("/api/hids-incidents")
async def get_hids_incidents():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM alerts
    WHERE category NOT IN (
        'Network Scanning',
        'DNS',
        'Firewall',
        'SMB',
        'RDP',
        'Network'
    )
    ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    alerts = [dict(row) for row in rows]
    return group_hids_alerts_into_incidents(alerts)


# =========================================
# NIDS INCIDENTS GROUPING
# =========================================

@router.get("/api/nids-incidents")
async def get_nids_incidents():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM alerts
    WHERE category IN (
        'Network',
        'Network Scanning',
        'DNS',
        'Firewall',
        'SMB',
        'RDP'
    )
    ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    alerts = [dict(row) for row in rows]
    return group_nids_alerts_into_incidents(alerts)


# =========================================
# SAVE INCIDENT INVESTIGATION REPORT
# =========================================

class ReportSavePayload(BaseModel):
    ticket_id: str
    severity: str
    status: str
    attack_chain: str
    analyst_notes: str
    timeline: str
    actions_taken: str
    next_steps: str

@router.post("/api/reports/save")
async def save_report(payload: ReportSavePayload):
    insert_case_report(payload.dict())
    return {"status": "success", "message": "Analyst report saved successfully"}


# =========================================
# FETCH SAVED INCIDENT REPORTS
# FIX: Two routes were defined for /api/reports. The second one (line ~536
# in the original) tried to query a non-existent `group_id` column in
# alerts and would return an empty list. Removed the duplicate entirely;
# kept only the correct fetch_case_reports() version.
# =========================================

@router.get("/api/reports")
async def get_reports():
    return fetch_case_reports()


# =========================================
# EXPORT DATABASE TELEMETRY TO FORENSICS
# =========================================

@router.post("/api/forensics/export")
async def export_forensics():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
    alerts_rows = cursor.fetchall()
    conn.close()

    alerts_list = [dict(row) for row in alerts_rows]

    root_dir = Path(__file__).resolve().parents[2]
    export_dir = root_dir / "Forensic_Logs"
    export_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"forensic_alerts_{timestamp}.json"
    filepath = export_dir / filename

    with open(filepath, "w") as f:
        json.dump(alerts_list, f, indent=4)

    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    file_hash = sha256.hexdigest()

    insert_forensic_case(filename, str(filepath), file_hash)

    return {
        "status": "success",
        "filename": filename,
        "hash": file_hash,
        "filepath": str(filepath)
    }


# =========================================
# GET LIST OF EXPORTED FORENSIC CASES
# =========================================

@router.get("/api/forensics/files")
async def get_forensics_files():
    return fetch_forensic_cases()


# =========================================
# GET SAVED FILES
# =========================================

# =========================================
# SAVED FILES — scans ALL export folders
# =========================================

_EXPORT_FOLDERS = [
    "forensics_exports",
    "Forensic_Logs",
    "reports",
]

def _human_size(b: int) -> str:
    if b < 1024:        return f"{b} B"
    if b < 1024**2:     return f"{b/1024:.1f} KB"
    if b < 1024**3:     return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"


@router.get("/api/saved-files")
async def get_saved_files():
    root = Path(__file__).resolve().parents[2]
    files = []
    seen = set()

    for folder_name in _EXPORT_FOLDERS:
        folder = root / folder_name
        folder.mkdir(exist_ok=True)
        for path in sorted(folder.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not path.is_file():
                continue
            if path.name in seen:
                continue
            seen.add(path.name)
            ext = path.suffix.lstrip(".").upper() or "FILE"
            stat = path.stat()
            files.append({
                "filename": path.name,
                "folder":   folder_name,
                "filepath": str(path),
                "size":     _human_size(stat.st_size),
                "saved":    datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                "type":     ext,
            })

    # Sort newest first
    files.sort(key=lambda f: f["saved"], reverse=True)
    return JSONResponse(files)


@router.get("/api/files/download/{folder}/{filename}")
async def download_file(folder: str, filename: str):
    """Stream a saved file to the browser."""
    from fastapi.responses import FileResponse
    root = Path(__file__).resolve().parents[2]
    # security: only allow known folders
    if folder not in _EXPORT_FOLDERS:
        return JSONResponse({"error": "Folder not allowed"}, status_code=403)
    path = root / folder / filename
    if not path.is_file():
        return JSONResponse({"error": "File not found"}, status_code=404)
    return FileResponse(str(path), filename=filename)


@router.post("/api/files/open-folder/{folder}")
async def open_folder(folder: str):
    """Open the export folder in the OS file manager (Windows/macOS/Linux)."""
    import subprocess, sys
    root = Path(__file__).resolve().parents[2]
    if folder not in _EXPORT_FOLDERS:
        return JSONResponse({"error": "Folder not allowed"}, status_code=403)
    target = root / folder
    target.mkdir(exist_ok=True)
    try:
        if sys.platform == "win32":
            subprocess.Popen(["explorer", str(target)])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(target)])
        else:
            subprocess.Popen(["xdg-open", str(target)])
        return {"status": "success", "path": str(target)}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# =========================================
# EXPORT FORENSICS (legacy endpoint)
# =========================================

@router.post("/api/export-forensics")
async def export_forensics_legacy():
    """
    Full forensic export: JSON alerts + CSV summary + dashboard report.
    Called by the Save to Forensics button on the dashboard.
    """
    from app.database.database import get_connection
    import csv

    root = Path(__file__).resolve().parents[2]
    export_dir = root / "forensics_exports"
    export_dir.mkdir(exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 1. JSON export of all alerts
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    alerts_list = [dict(r) for r in rows]

    json_path = export_dir / f"forensic_alerts_{ts}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(alerts_list, f, indent=4, default=str)

    # 2. CSV summary
    csv_path = export_dir / f"alert_summary_{ts}.csv"
    csv_fields = ["id","timestamp","type","severity","category","description","log_source","status"]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(alerts_list)

    # 3. Severity summary report (text)
    from collections import Counter
    sev_counts  = Counter(a.get("severity","?") for a in alerts_list)
    cat_counts  = Counter(a.get("category","?")  for a in alerts_list)
    report_path = export_dir / f"dashboard_report_{ts}.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"SOC DASHBOARD FORENSIC REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Alerts: {len(alerts_list)}\n\n")
        f.write("SEVERITY BREAKDOWN\n")
        for k,v in sorted(sev_counts.items()): f.write(f"  {k}: {v}\n")
        f.write("\nTOP CATEGORIES\n")
        for k,v in cat_counts.most_common(10): f.write(f"  {k}: {v}\n")

    # Hash the JSON for integrity
    sha256 = hashlib.sha256()
    with open(json_path, "rb") as f:
        while chunk := f.read(4096): sha256.update(chunk)
    file_hash = sha256.hexdigest()

    insert_forensic_case(f"forensic_alerts_{ts}.json", str(json_path), file_hash)

    return JSONResponse({
        "status":    "success",
        "timestamp": ts,
        "filename":  f"forensic_alerts_{ts}.json",
        "csv":       f"alert_summary_{ts}.csv",
        "report":    f"dashboard_report_{ts}.txt",
        "hash":      file_hash,
        "total":     len(alerts_list)
    })




# =========================================
# GROUPED SAVED FILES — by timestamp bundle
# =========================================

@router.get("/api/saved-files/grouped")
async def get_saved_files_grouped():
    """
    Returns files grouped by their timestamp prefix.
    Each group = one 'Save to Forensics' operation.
    """
    root = Path(__file__).resolve().parents[2]
    groups = {}

    for folder_name in _EXPORT_FOLDERS:
        folder = root / folder_name
        folder.mkdir(exist_ok=True)
        for path in sorted(folder.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not path.is_file():
                continue
            # Extract timestamp from filename e.g. forensic_alerts_20260621_022939.json
            import re
            m = re.search(r'(\d{8}_\d{6})', path.name)
            ts_key = m.group(1) if m else "other"

            # Format timestamp nicely
            try:
                from datetime import datetime
                dt = datetime.strptime(ts_key, "%Y%m%d_%H%M%S")
                ts_label = dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                ts_label = ts_key

            if ts_key not in groups:
                groups[ts_key] = {
                    "bundle_id":  ts_key,
                    "timestamp":  ts_label,
                    "folder":     folder_name,
                    "files":      [],
                    "total_size": 0,
                }

            stat = path.stat()
            size_bytes = stat.st_size
            groups[ts_key]["files"].append({
                "filename": path.name,
                "folder":   folder_name,
                "filepath": str(path),
                "size":     _human_size(size_bytes),
                "type":     path.suffix.lstrip(".").upper() or "FILE",
                "saved":    datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
            })
            groups[ts_key]["total_size"] += size_bytes

    # Convert to list, sort newest first
    result = list(groups.values())
    for g in result:
        g["total_size_label"] = _human_size(g["total_size"])
    result.sort(key=lambda x: x["bundle_id"], reverse=True)
    return JSONResponse(result)


# =========================================
# ZIP DOWNLOAD — entire bundle
# =========================================

@router.get("/api/files/download-bundle/{bundle_id}")
async def download_bundle(bundle_id: str):
    """Download all files from a timestamp bundle as a ZIP."""
    import zipfile, io, re
    from fastapi.responses import StreamingResponse

    # Validate bundle_id (must be YYYYMMDD_HHMMSS)
    if not re.match(r'^\d{8}_\d{6}$', bundle_id):
        return JSONResponse({"error": "Invalid bundle ID"}, status_code=400)

    root = Path(__file__).resolve().parents[2]
    matched_files = []

    for folder_name in _EXPORT_FOLDERS:
        folder = root / folder_name
        if not folder.exists():
            continue
        for path in folder.iterdir():
            if path.is_file() and bundle_id in path.name:
                matched_files.append(path)

    if not matched_files:
        return JSONResponse({"error": "No files found for this bundle"}, status_code=404)

    # Create in-memory ZIP
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for fp in matched_files:
            zf.write(fp, fp.name)
    zip_buffer.seek(0)

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=soc_forensics_{bundle_id}.zip"
        }
    )

# =========================================
# INCIDENT GROUPING HELPERS
# =========================================

def _extract_process(raw_log: str) -> str:
    """Pull the Image/process name from the raw_log description string."""
    if not raw_log:
        return "-"
    for part in str(raw_log).split("|"):
        part = part.strip()
        if part.upper().startswith("IMAGE="):
            image = part[6:].strip()
            return image.split("\\")[-1] if image else "-"
    return "-"


def _extract_parent(raw_log: str) -> str:
    """Pull the ParentImage from the raw_log description string."""
    if not raw_log:
        return "-"
    for part in str(raw_log).split("|"):
        part = part.strip()
        if part.upper().startswith("PARENT="):
            parent = part[7:].strip()
            return parent.split("\\")[-1] if parent else "-"
    return "-"


def _confidence_from_severity(severity: str) -> str:
    """Derive a real confidence tier from alert severity."""
    sev = str(severity).upper()
    if sev == "CRITICAL":
        return "CRITICAL"
    if sev == "HIGH":
        return "HIGH"
    if sev == "MEDIUM":
        return "MEDIUM"
    return "LOW"


def _calc_window(timestamps: list) -> str:
    """Return human-readable time span between first and last timestamp."""
    if len(timestamps) < 2:
        return "< 1 min"
    try:
        from datetime import datetime as _dt
        def _p(ts):
            s = str(ts).strip().replace(" ", "T")
            if s.endswith("Z"): s = s[:-1]
            return _dt.fromisoformat(s)
        times = sorted([_p(t) for t in timestamps if t and t != "-"])
        if len(times) < 2:
            return "< 1 min"
        delta = int((times[-1] - times[0]).total_seconds())
        if delta < 60:   return f"{delta}s"
        if delta < 3600: return f"{delta//60} min"
        return f"{delta//3600}h {(delta%3600)//60}m"
    except Exception:
        return "-"


def _confidence_pct(severity: str, events: int) -> str:
    """Derive a confidence percentage from severity + event count."""
    base = {"CRITICAL": 90, "HIGH": 75, "MEDIUM": 55, "LOW": 35}
    b = base.get(str(severity).upper(), 50)
    bonus = min(events * 2, 10)
    return f"{min(b + bonus, 99)}%"


def group_hids_alerts_into_incidents(alerts):
    """
    Group HIDS alerts by rule name (type field).
    All displayed values come from the real alert rows — no hardcoding.
    """
    incidents = []
    groups = {}

    for alert in alerts:
        t = alert.get("type") or "Unknown"
        groups.setdefault(t, []).append(alert)

    for name, grp_alerts in groups.items():
        primary = grp_alerts[0]

        timestamps = [
            a.get("timestamp", "") for a in grp_alerts
            if a.get("timestamp")
        ]
        first_seen = min(timestamps) if timestamps else "-"
        last_seen  = max(timestamps) if timestamps else "-"
        sev = primary.get("severity", "LOW")
        evt_count = len(grp_alerts)

        incidents.append({
            "group_id":        f"GRP-{primary['id']}",
            "severity":        sev,
            "attack_chain":    str(name),
            "category":        primary.get("category", "-"),
            "events":          evt_count,
            "window":          _calc_window(timestamps),
            "confidence":      _confidence_pct(sev, evt_count),
            "first_seen":      first_seen,
            "last_seen":       last_seen,
            "status":          primary.get("status", "New"),
            "alert_ids":       [a.get("id") for a in grp_alerts if a.get("id")],
            "mitre_tactic":    primary.get("mitre_tactic", "-"),
            "mitre_technique": primary.get("mitre_technique", "-"),
            "event_chain": [
                {
                    "timestamp":   str(a.get("timestamp", "-")),
                    "process":     _extract_process(a.get("description", "")),
                    "parent":      _extract_parent(a.get("description", "")),
                    "user":        a.get("user") or "-",
                    "mitre":       a.get("mitre_technique") or a.get("mitre_tactic") or "-",
                    "severity":    a.get("severity", "LOW"),
                    "description": a.get("description", "-"),
                    "log_source":  a.get("log_source", "-"),
                }
                for a in grp_alerts
            ]
        })

    # Sort: CRITICAL first, then HIGH, MEDIUM, LOW
    sev_order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}
    incidents.sort(key=lambda x: sev_order.get(x["severity"].upper(), 0), reverse=True)
    return incidents


def group_nids_alerts_into_incidents(alerts):
    """
    Group NIDS alerts by rule name (type field).
    All displayed values come from the real alert rows — no hardcoding.
    """
    incidents = []
    groups = {}

    for alert in alerts:
        t = alert.get("type") or "Unknown"
        groups.setdefault(t, []).append(alert)

    for name, grp_alerts in groups.items():
        primary = grp_alerts[0]

        timestamps = [
            a.get("timestamp", "") for a in grp_alerts
            if a.get("timestamp")
        ]
        first_seen = min(timestamps) if timestamps else "-"
        last_seen  = max(timestamps) if timestamps else "-"
        sev = primary.get("severity", "LOW")
        evt_count = len(grp_alerts)

        incidents.append({
            "group_id":        f"NET-{primary['id']}",
            "severity":        sev,
            "attack_flow":     str(name),
            "category":        primary.get("category", "-"),
            "events":          evt_count,
            "packets":         evt_count,        # event count doubles as packet count
            "window":          _calc_window(timestamps),
            "confidence":      _confidence_pct(sev, evt_count),
            "first_seen":      first_seen,
            "last_seen":       last_seen,
            "status":          primary.get("status", "New"),
            "alert_ids":       [a.get("id") for a in grp_alerts if a.get("id")],
            "mitre_tactic":    primary.get("mitre_tactic", "-"),
            "mitre_technique": primary.get("mitre_technique", "-"),
            "event_chain": [
                {
                    "timestamp":   str(a.get("timestamp", "-")),
                    "src_ip":      a.get("source_ip") or a.get("ip_address") or "-",
                    "dst_ip":      a.get("destination_ip") or "-",
                    "protocol":    a.get("protocol") or "-",
                    "mitre":       a.get("mitre_technique") or a.get("mitre_tactic") or "-",
                    "severity":    a.get("severity", "LOW"),
                    "description": a.get("description", "-"),
                    "log_source":  a.get("log_source", "-"),
                }
                for a in grp_alerts
            ]
        })

    sev_order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}
    incidents.sort(key=lambda x: sev_order.get(x["severity"].upper(), 0), reverse=True)
    return incidents

# =========================================
# SAVE INCIDENT REPORT (HIDS/NIDS)
# =========================================

class IncidentReportPayload(BaseModel):
    group_id: str
    source_type: str   # "HIDS" or "NIDS"
    severity: str
    attack_chain: str
    status: str
    analyst_notes: str
    alert_ids: list = []
    mitre_tactic: str = "-"
    mitre_technique: str = "-"

@router.post("/api/reports/incident")
async def save_incident_report(payload: IncidentReportPayload):
    """Save a structured incident report and update alert statuses."""
    from datetime import datetime as _dt
    now = _dt.now()
    ticket_id = f"CASE-{payload.source_type}-{payload.group_id.replace('GRP-','').replace('NET-','')}"

    report = {
        "ticket_id":    ticket_id,
        "severity":     payload.severity,
        "status":       payload.status,
        "attack_chain": payload.attack_chain,
        "analyst_notes": payload.analyst_notes,
        "timeline":     f"{payload.source_type} incident detected — {payload.attack_chain}",
        "actions_taken": f"Status set to: {payload.status}",
        "next_steps":   "Continue investigation or close case."
    }
    insert_case_report(report)

    # Also update all grouped alerts to the chosen status
    if payload.alert_ids:
        conn = get_connection()
        cursor = conn.cursor()
        for aid in payload.alert_ids:
            try:
                cursor.execute("UPDATE alerts SET status=? WHERE id=?", (payload.status, int(aid)))
            except Exception:
                pass
        conn.commit()
        conn.close()

    return {
        "status":    "success",
        "ticket_id": ticket_id,
        "message":   f"Report {ticket_id} saved successfully"
    }