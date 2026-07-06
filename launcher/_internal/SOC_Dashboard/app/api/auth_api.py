"""
app/api/auth_api.py
-------------------
Complete authentication system for the SOC Dashboard.

- Users stored in SQLite (users table), passwords hashed with PBKDF2-SHA256
- JWT tokens (PyJWT 2.7.0) carry username + role, signed with a random
  SECRET_KEY generated once on first launch and persisted in a .env file
  so tokens survive server restarts
- Default admin account seeded on first run from environment / .env file —
  NO credentials hardcoded in source code
- Role hierarchy: admin > analyst > viewer
- Admin-only operations: create/update/delete users, manage roles
"""

from fastapi import APIRouter, Header, HTTPException, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
from pathlib import Path
from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import secrets
import os
import jwt   # PyJWT 2.7.0

from app.database.database import get_connection

router = APIRouter()

# =========================================
# SECRET KEY — persisted across restarts
# =========================================

_ENV_FILE = Path(__file__).resolve().parents[2] / ".soc_env"
_SECRET_KEY: str = ""


def _load_or_create_secret() -> str:
    global _SECRET_KEY
    if _SECRET_KEY:
        return _SECRET_KEY

    # Try reading from .soc_env
    if _ENV_FILE.exists():
        for line in _ENV_FILE.read_text().splitlines():
            if line.startswith("JWT_SECRET="):
                _SECRET_KEY = line.split("=", 1)[1].strip()
                return _SECRET_KEY

    # Generate a new secret and persist it
    _SECRET_KEY = secrets.token_hex(48)
    existing = _ENV_FILE.read_text() if _ENV_FILE.exists() else ""
    with open(_ENV_FILE, "a") as f:
        f.write(f"\nJWT_SECRET={_SECRET_KEY}\n")
    return _SECRET_KEY


# =========================================
# PASSWORD HASHING  (PBKDF2-SHA256)
# No external library required — stdlib only
# =========================================

def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"pbkdf2:sha256:260000:{salt}:{dk.hex()}"


def _verify_password(stored_hash: str, password: str) -> bool:
    try:
        parts = stored_hash.split(":")
        # format: pbkdf2:sha256:iterations:salt:hash
        if len(parts) != 5:
            return False
        _, _, iters, salt, expected = parts
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iters))
        return hmac.compare_digest(dk.hex(), expected)
    except Exception:
        return False


# =========================================
# JWT HELPERS
# =========================================

_ALGORITHM   = "HS256"
_TOKEN_HOURS = 8   # tokens expire after 8 hours


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
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired — please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def _get_current_user(authorization: Optional[str]) -> dict:
    """Extract user dict from Bearer token header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    return _decode_token(token)


def _require_admin(authorization: Optional[str]) -> dict:
    user = _get_current_user(authorization)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


# =========================================
# DATABASE HELPERS
# =========================================

def _init_users_table():
    """Create users table if it doesn't exist and seed default admin."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT    UNIQUE NOT NULL,
            password_hash TEXT   NOT NULL,
            role         TEXT    NOT NULL DEFAULT 'analyst',
            display_name TEXT,
            created_at   TEXT    DEFAULT CURRENT_TIMESTAMP,
            last_login   TEXT,
            is_active    INTEGER DEFAULT 1
        )
    """)
    conn.commit()

    # Seed default admin from env (or .soc_env) — never from hardcoded source
    cursor.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    admin_count = cursor.fetchone()[0]

    if admin_count == 0:
        # Read from environment or .soc_env file
        admin_user = _read_env_var("DEFAULT_ADMIN_USERNAME", "admin")
        admin_pass = _read_env_var("DEFAULT_ADMIN_PASSWORD", "")

        if not admin_pass:
            # Generate a secure random password and write it to .soc_env
            admin_pass = secrets.token_urlsafe(16)
            with open(_ENV_FILE, "a") as f:
                f.write(f"DEFAULT_ADMIN_USERNAME={admin_user}\n")
                f.write(f"DEFAULT_ADMIN_PASSWORD={admin_pass}\n")
            print(f"\n{'='*50}")
            print(f"[SOC AUTH] First-run admin account created")
            print(f"  Username: {admin_user}")
            print(f"  Password: {admin_pass}")
            print(f"  Saved to: {_ENV_FILE}")
            print(f"{'='*50}\n")

        cursor.execute("""
            INSERT INTO users (username, password_hash, role, display_name)
            VALUES (?, ?, 'admin', 'Super Admin')
        """, (admin_user, _hash_password(admin_pass)))
        conn.commit()

    conn.close()


def _read_env_var(key: str, default: str = "") -> str:
    """Read from OS env first, then .soc_env file."""
    val = os.environ.get(key, "")
    if val:
        return val
    if _ENV_FILE.exists():
        for line in _ENV_FILE.read_text().splitlines():
            if line.startswith(f"{key}="):
                return line.split("=", 1)[1].strip()
    return default


# =========================================
# INITIALISE ON IMPORT
# =========================================

_load_or_create_secret()
_init_users_table()


# =========================================
# MODELS
# =========================================

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


VALID_ROLES = {"admin", "analyst", "viewer"}


# =========================================
# LOGIN
# =========================================

@router.post("/api/auth/login")
def login(payload: LoginPayload):
    conn = get_connection()
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

    # Update last_login
    cursor.execute(
        "UPDATE users SET last_login=? WHERE id=?",
        (datetime.now(timezone.utc).isoformat(), user["id"])
    )
    conn.commit()
    conn.close()

    token = _create_token(user["username"], user["role"])

    return {
        "status":       "success",
        "token":        token,
        "username":     user["username"],
        "display_name": user["display_name"] or user["username"],
        "role":         user["role"],
        "expires_in":   _TOKEN_HOURS * 3600,
    }


# =========================================
# GET CURRENT USER (token check)
# =========================================

@router.get("/api/auth/me")
def get_me(authorization: Optional[str] = Header(None)):
    user_data = _get_current_user(authorization)
    return {
        "username":     user_data["sub"],
        "role":         user_data["role"],
        "token_valid":  True,
    }


# =========================================
# LIST USERS  (admin only)
# =========================================

@router.get("/api/auth/users")
def list_users(authorization: Optional[str] = Header(None)):
    _require_admin(authorization)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, role, display_name, created_at, last_login, is_active
        FROM users ORDER BY id
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# =========================================
# CREATE USER  (admin only)
# =========================================

@router.post("/api/auth/users")
def create_user(
    payload: CreateUserPayload,
    authorization: Optional[str] = Header(None)
):
    _require_admin(authorization)

    if payload.role not in VALID_ROLES:
        raise HTTPException(
            status_code=422,
            detail=f"Role must be one of: {', '.join(VALID_ROLES)}"
        )

    if len(payload.password) < 8:
        raise HTTPException(
            status_code=422,
            detail="Password must be at least 8 characters"
        )

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash, role, display_name)
            VALUES (?, ?, ?, ?)
        """, (
            payload.username,
            _hash_password(payload.password),
            payload.role,
            payload.display_name or payload.username
        ))
        conn.commit()
        new_id = cursor.lastrowid
    except Exception as e:
        conn.close()
        if "UNIQUE" in str(e):
            raise HTTPException(status_code=409, detail=f"Username '{payload.username}' already exists")
        raise HTTPException(status_code=500, detail=str(e))
    conn.close()

    return {
        "status":   "success",
        "id":       new_id,
        "username": payload.username,
        "role":     payload.role,
        "message":  f"User '{payload.username}' created successfully"
    }


# =========================================
# UPDATE USER  (admin only)
# =========================================

@router.put("/api/auth/users/{user_id}")
def update_user(
    user_id: int,
    payload: UpdateUserPayload,
    authorization: Optional[str] = Header(None)
):
    _require_admin(authorization)

    if payload.role and payload.role not in VALID_ROLES:
        raise HTTPException(
            status_code=422,
            detail=f"Role must be one of: {', '.join(VALID_ROLES)}"
        )

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id=?", (user_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    updates, params = [], []
    if payload.role        is not None: updates.append("role=?");          params.append(payload.role)
    if payload.display_name is not None: updates.append("display_name=?"); params.append(payload.display_name)
    if payload.is_active   is not None: updates.append("is_active=?");     params.append(payload.is_active)
    if payload.password:
        if len(payload.password) < 8:
            conn.close()
            raise HTTPException(status_code=422, detail="Password must be at least 8 characters")
        updates.append("password_hash=?")
        params.append(_hash_password(payload.password))

    if updates:
        params.append(user_id)
        cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id=?", params)
        conn.commit()

    conn.close()
    return {"status": "success", "message": "User updated"}


# =========================================
# DELETE USER  (admin only; can't delete self)
# =========================================

@router.delete("/api/auth/users/{user_id}")
def delete_user(
    user_id: int,
    authorization: Optional[str] = Header(None)
):
    admin = _require_admin(authorization)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    target = dict(target)
    if target["username"] == admin["sub"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"User '{target['username']}' deleted"}


# =========================================
# CHANGE OWN PASSWORD
# =========================================

class ChangePasswordPayload(BaseModel):
    current_password: str
    new_password: str

@router.post("/api/auth/change-password")
def change_password(
    payload: ChangePasswordPayload,
    authorization: Optional[str] = Header(None)
):
    user_data = _get_current_user(authorization)
    username  = user_data["sub"]

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    if not row or not _verify_password(row[0], payload.current_password):
        conn.close()
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    if len(payload.new_password) < 8:
        conn.close()
        raise HTTPException(status_code=422, detail="New password must be at least 8 characters")

    cursor.execute(
        "UPDATE users SET password_hash=? WHERE username=?",
        (_hash_password(payload.new_password), username)
    )
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Password changed successfully"}


# =========================================
# VALIDATE TOKEN  (for page-load check)
# =========================================

@router.get("/api/auth/validate")
def validate_token(authorization: Optional[str] = Header(None)):
    """Quick token validity check — used on dashboard page load."""
    try:
        user_data = _get_current_user(authorization)
        return {"valid": True, "username": user_data["sub"], "role": user_data["role"]}
    except HTTPException:
        return {"valid": False}