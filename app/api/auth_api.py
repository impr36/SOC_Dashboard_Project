"""
app/api/auth_api.py
-------------------
Auth helpers kept for compatibility.
All web-facing routes have auth guards removed.
Authentication is handled by the Tkinter launcher.
"""

from fastapi import APIRouter, Header, HTTPException, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
from pathlib import Path
from datetime import datetime, timezone, timedelta
import hashlib, hmac, secrets, os, jwt

from app.database.database import get_connection
import sqlite3 as _sqlite3

# =========================================
# PERSISTENT USER DATABASE
# Separate from the session DB so users
# survive server restarts and DB resets.
# Stored at: database/soc_users.db
# =========================================

_USERS_DB_PATH = Path(__file__).resolve().parents[2] / "database" / "soc_users.db"
_USERS_DB_PATH.parent.mkdir(exist_ok=True)

def _get_users_conn():
    """Always returns a connection to the persistent users DB."""
    conn = _sqlite3.connect(str(_USERS_DB_PATH))
    conn.row_factory = _sqlite3.Row
    return conn

router = APIRouter()

_ENV_FILE   = Path(__file__).resolve().parents[2] / ".soc_env"
_SECRET_KEY = ""
_ALGORITHM  = "HS256"
_TOKEN_HOURS = 8


def _load_or_create_secret() -> str:
    global _SECRET_KEY
    if _SECRET_KEY:
        return _SECRET_KEY
    if _ENV_FILE.exists():
        for line in _ENV_FILE.read_text().splitlines():
            if line.startswith("JWT_SECRET="):
                _SECRET_KEY = line.split("=", 1)[1].strip()
                return _SECRET_KEY
    _SECRET_KEY = secrets.token_hex(48)
    with open(_ENV_FILE, "a") as f:
        f.write(f"\nJWT_SECRET={_SECRET_KEY}\n")
    return _SECRET_KEY


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"pbkdf2:sha256:260000:{salt}:{dk.hex()}"


def _verify_password(stored_hash: str, password: str) -> bool:
    try:
        parts = stored_hash.split(":")
        if len(parts) != 5:
            return False
        _, _, iters, salt, expected = parts
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iters))
        return hmac.compare_digest(dk.hex(), expected)
    except Exception:
        return False


def _create_token(username: str, role: str) -> str:
    secret = _load_or_create_secret()
    payload = {
        "sub":  username,
        "role": role,
        "iat":  datetime.now(timezone.utc),
        "exp":  datetime.now(timezone.utc) + timedelta(hours=_TOKEN_HOURS),
    }
    return jwt.encode(payload, secret, algorithm=_ALGORITHM)


def _decode_token(token: str) -> dict:
    secret = _load_or_create_secret()
    try:
        return jwt.decode(token, secret, algorithms=[_ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


# Kept as helpers for any internal use — NOT called by web routes anymore
def _get_current_user(authorization: Optional[str]) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return _decode_token(authorization.split(" ", 1)[1])


def _require_admin(authorization: Optional[str]) -> dict:
    user = _get_current_user(authorization)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


def _read_env_var(key: str, default: str = "") -> str:
    val = os.environ.get(key, "")
    if val:
        return val
    if _ENV_FILE.exists():
        for line in _ENV_FILE.read_text().splitlines():
            if line.startswith(f"{key}="):
                return line.split("=", 1)[1].strip()
    return default


def _init_users_table():
    conn = _get_users_conn()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'analyst',
            display_name  TEXT,
            created_at    TEXT    DEFAULT CURRENT_TIMESTAMP,
            last_login    TEXT,
            is_active     INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    cursor.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    if cursor.fetchone()[0] == 0:
        admin_user = _read_env_var("DEFAULT_ADMIN_USERNAME", "admin")
        admin_pass = _read_env_var("DEFAULT_ADMIN_PASSWORD", "admin123")
        if not admin_pass:
            admin_pass = "admin123"
            admin_user = "admin"
            with open(_ENV_FILE, "a") as f:
                f.write(f"DEFAULT_ADMIN_USERNAME={admin_user}\n")
                f.write(f"DEFAULT_ADMIN_PASSWORD={admin_pass}\n")
        cursor.execute("""
            INSERT INTO users (username, password_hash, role, display_name)
            VALUES (?, ?, 'admin', 'Super Admin')
        """, (admin_user, _hash_password(admin_pass)))
        conn.commit()
        print("[SOC AUTH] Admin seeded: admin / admin123")
    conn.close()


_load_or_create_secret()
_init_users_table()


# ── Models ────────────────────────────────────────────────

class LoginPayload(BaseModel):
    username: str
    password: str

class CreateUserPayload(BaseModel):
    username: str
    password: str
    role: str = "analyst"
    display_name: Optional[str] = None

class UpdateUserPayload(BaseModel):
    role: Optional[str] = None
    display_name: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[int] = None

class ChangePasswordPayload(BaseModel):
    current_password: str
    new_password: str

VALID_ROLES = {"admin", "analyst", "viewer"}


# ── LOGIN ─────────────────────────────────────────────────

@router.post("/api/auth/login")
def login(payload: LoginPayload):
    conn = _get_users_conn()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, password_hash, role, display_name, is_active
        FROM users WHERE username = ?
    """, (payload.username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")
    user = dict(user)
    if not user["is_active"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Account is disabled")
    if not _verify_password(user["password_hash"], payload.password):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")
    cursor.execute("UPDATE users SET last_login=? WHERE id=?",
                   (datetime.now(timezone.utc).isoformat(), user["id"]))
    conn.commit()
    conn.close()
    token = _create_token(user["username"], user["role"])
    return {
        "status": "success", "token": token,
        "username": user["username"],
        "display_name": user["display_name"] or user["username"],
        "role": user["role"], "expires_in": _TOKEN_HOURS * 3600,
    }


# ── GET CURRENT USER ──────────────────────────────────────

@router.get("/api/auth/me")
def get_me(authorization: Optional[str] = Header(None)):
    # Try JWT token first
    try:
        if authorization and authorization.startswith("Bearer "):
            user_data = _get_current_user(authorization)
            username = user_data["sub"]
            # Look up display_name from persistent DB
            conn = _get_users_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT display_name, role FROM users WHERE username=?", (username,))
            row = cursor.fetchone()
            conn.close()
            display = dict(row)["display_name"] if row else username
            role    = dict(row)["role"]         if row else user_data["role"]
            return {"username": username, "display_name": display,
                    "role": role, "token_valid": True}
    except Exception:
        pass
    # No token — return admin (Tkinter-launched session)
    return {"username": "admin", "display_name": "Super Admin",
            "role": "admin", "token_valid": True}


# ── LIST USERS — auth guard removed ───────────────────────

@router.get("/api/auth/users")
def list_users():
    conn = _get_users_conn()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, role, display_name, created_at, last_login, is_active
        FROM users ORDER BY id
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# ── CREATE USER — auth guard removed ──────────────────────

@router.post("/api/auth/users")
def create_user(payload: CreateUserPayload):
    if payload.role not in VALID_ROLES:
        raise HTTPException(status_code=422, detail=f"Role must be one of: {', '.join(VALID_ROLES)}")
    if len(payload.password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters")
    conn = _get_users_conn()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash, role, display_name)
            VALUES (?, ?, ?, ?)
        """, (payload.username, _hash_password(payload.password),
              payload.role, payload.display_name or payload.username))
        conn.commit()
        new_id = cursor.lastrowid
    except Exception as e:
        conn.close()
        if "UNIQUE" in str(e):
            raise HTTPException(status_code=409, detail=f"Username already exists")
        raise HTTPException(status_code=500, detail=str(e))
    conn.close()
    return {"status": "success", "id": new_id, "username": payload.username, "role": payload.role}


# ── UPDATE USER — auth guard removed ──────────────────────

@router.put("/api/auth/users/{user_id}")
def update_user(user_id: int, payload: UpdateUserPayload):
    conn = _get_users_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE id=?", (user_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    updates, params = [], []
    if payload.role:         updates.append("role=?");          params.append(payload.role)
    if payload.display_name: updates.append("display_name=?");  params.append(payload.display_name)
    if payload.is_active is not None: updates.append("is_active=?"); params.append(payload.is_active)
    if payload.password:
        updates.append("password_hash=?"); params.append(_hash_password(payload.password))
    if updates:
        params.append(user_id)
        cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id=?", params)
        conn.commit()
    conn.close()
    return {"status": "success", "message": "User updated"}


# ── DELETE USER — auth guard removed ──────────────────────

@router.delete("/api/auth/users/{user_id}")
def delete_user(user_id: int):
    conn = _get_users_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id=?", (user_id,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"User deleted"}


# ── CHANGE PASSWORD — auth guard removed ──────────────────

@router.post("/api/auth/change-password")
def change_password(payload: ChangePasswordPayload):
    # Without a token we use the admin account by default
    conn = _get_users_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE role='admin' LIMIT 1")
    row = cursor.fetchone()
    if not row or not _verify_password(row[0], payload.current_password):
        conn.close()
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if len(payload.new_password) < 8:
        conn.close()
        raise HTTPException(status_code=422, detail="New password must be at least 8 characters")
    cursor.execute("UPDATE users SET password_hash=? WHERE role='admin'",
                   (_hash_password(payload.new_password),))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Password changed"}




# ── LOGOUT — signals Tkinter to restart login window ─────

@router.post("/api/auth/logout")
def logout():
    """
    Sets SOC_LOGOUT_REQUESTED env var.
    The Tkinter launcher polls this every second.
    When detected, it stops the server and shows the login window again.
    """
    import os
    os.environ["SOC_LOGOUT_REQUESTED"] = "1"
    return {"status": "success", "message": "Logged out — login window will reappear"}


# ── LOGOUT — signals launcher to show login window again ──

@router.post("/api/auth/logout")
def logout():
    """
    Sets SOC_LOGOUT_REQUESTED env var.
    The launcher polls this every second and shows login window again.
    The server process is terminated and restarted for the next user.
    """
    import os
    os.environ["SOC_LOGOUT_REQUESTED"] = "1"
    # Clear session info
    os.environ.pop("SOC_LOGGED_USER",    None)
    os.environ.pop("SOC_LOGGED_ROLE",    None)
    os.environ.pop("SOC_LOGGED_DISPLAY", None)
    return {"status": "success", "message": "Logged out"}

# ── VALIDATE TOKEN ────────────────────────────────────────

@router.get("/api/auth/validate")
def validate_token(authorization: Optional[str] = Header(None)):
    # Always returns valid — no web login exists anymore
    return {"valid": True, "username": "admin", "role": "admin"}