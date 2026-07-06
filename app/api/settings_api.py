"""
app/api/settings_api.py
-----------------------
Settings API — persists all settings to SQLite settings table.

AUTH REMOVED: Authentication is handled entirely by the Tkinter
launcher before the browser opens. All routes on this local
server are open — no JWT tokens, no Authorization headers.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
import json

from app.database.database import get_connection

router = APIRouter()

# ─── default settings ─────────────────────────────────────

DEFAULT_SETTINGS: Dict[str, Any] = {
    "detection.realtime":          True,
    "detection.behavioral":        True,
    "detection.auto_escalation":   False,
    "detection.sensitivity":       78,
    "dashboard.theme":             "dark",
    "dashboard.refresh_interval":  15,
    "dashboard.compact_mode":      False,
    "hids.process_monitoring":     True,
    "hids.registry_monitoring":    True,
    "hids.powershell_detection":   True,
    "nids.packet_inspection":      True,
    "nids.dns_tunneling":          True,
    "nids.exfiltration":           True,
    "reporting.analyst_signature": "",
    "reporting.retention_days":    30,
    "reporting.pdf_export":        True,
    "storage.alert_retention":     30,
    "storage.auto_cleanup":        False,
}

# ─── helpers ──────────────────────────────────────────────

def _init_settings_table():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _get_setting(key: str, default=None):
    _init_settings_table()
    conn = get_connection()
    row = conn.execute(
        "SELECT value FROM settings WHERE key = ?", (key,)
    ).fetchone()
    conn.close()
    if row:
        try:
            return json.loads(row[0])
        except Exception:
            return row[0]
    return default


def _set_setting(key: str, value):
    _init_settings_table()
    conn = get_connection()
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, json.dumps(value))
    )
    conn.commit()
    conn.close()


# ─── GET all settings ─────────────────────────────────────

@router.get("/api/settings")
def get_settings():
    result = {}
    for key, default in DEFAULT_SETTINGS.items():
        result[key] = _get_setting(key, default)
    return result


# ─── SAVE settings ────────────────────────────────────────

class SettingsPayload(BaseModel):
    settings: Dict[str, Any]


@router.post("/api/settings")
def save_settings(payload: SettingsPayload):
    saved, rejected = [], []
    for key, value in payload.settings.items():
        if key in DEFAULT_SETTINGS:
            _set_setting(key, value)
            saved.append(key)
        else:
            rejected.append(key)
    return {"status": "ok", "saved": saved, "rejected": rejected}


# ─── RESET to defaults ────────────────────────────────────

@router.post("/api/settings/reset")
def reset_settings():
    for key, value in DEFAULT_SETTINGS.items():
        _set_setting(key, value)
    return {"status": "ok", "message": "All settings reset to defaults"}


# ─── TOGGLE user active status ────────────────────────────

class ToggleUserPayload(BaseModel):
    username: str
    active: bool


@router.post("/api/settings/users/toggle")
def toggle_user(payload: ToggleUserPayload):
    conn = get_connection()
    row = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (payload.username,)
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    conn.execute(
        "UPDATE users SET is_active = ? WHERE username = ?",
        (1 if payload.active else 0, payload.username)
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


# ─── PLATFORM STATS ───────────────────────────────────────

@router.get("/api/settings/platform-stats")
def platform_stats():
    conn = get_connection()

    alert_count = conn.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0]

    rule_count = 0
    try:
        rule_count = conn.execute(
            "SELECT COUNT(*) FROM detection_rules WHERE enabled = 1"
        ).fetchone()[0]
    except Exception:
        pass

    user_count = 0
    try:
        user_count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE is_active = 1"
        ).fetchone()[0]
    except Exception:
        pass

    report_count = 0
    try:
        report_count = conn.execute(
            "SELECT COUNT(*) FROM case_reports"
        ).fetchone()[0]
    except Exception:
        pass

    conn.close()
    return {
        "total_alerts":  alert_count,
        "active_rules":  rule_count,
        "active_users":  user_count,
        "total_reports": report_count,
    }