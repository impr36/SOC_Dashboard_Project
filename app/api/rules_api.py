from fastapi import APIRouter, Body, Header, HTTPException
from typing import Optional
from app.database.database import (
    fetch_rules,
    insert_rule,
    delete_rule,
    update_rule,
    get_connection
)
from app.api.auth_api import _require_admin as _jwt_require_admin

router = APIRouter()

# =========================================
# ADMIN GUARD — delegates to JWT auth
# =========================================

def _require_admin(authorization: Optional[str] = None):
    """Raise 403 if Bearer token is missing or not admin."""
    _jwt_require_admin(authorization)


# =========================================
# FETCH RULES  (read — any authenticated user)
# =========================================

@router.get("/api/rules/{rule_type}")
def get_rules(rule_type: str):
    """Return all rules for HIDS or NIDS, including the row id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            id,
            event_id,
            rule_name,
            rule_type,
            threshold,
            window_sec,
            severity,
            description,
            enabled,
            created_at
        FROM detection_rules
        WHERE rule_type = ?
        ORDER BY id DESC
    """, (rule_type.upper(),))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# =========================================
# RULE COUNT
# =========================================

@router.get("/api/rules/count/{rule_type}")
def get_rule_count(rule_type: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM detection_rules WHERE rule_type = ?",
        (rule_type.upper(),)
    )
    count = cursor.fetchone()[0]
    conn.close()
    return {"count": count, "rule_type": rule_type.upper()}


# =========================================
# ADD RULE  (admin only)
# =========================================

@router.post("/api/rules/add")
def add_rule(
    rule: dict = Body(...),
    authorization: Optional[str] = Header(None)
):
    _require_admin(authorization)

    # Validate required fields
    required = ["rule_type", "rule_name", "threshold", "window_sec", "severity"]
    missing = [f for f in required if not rule.get(f)]
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"Missing required fields: {', '.join(missing)}"
        )

    # Validate severity
    valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    if str(rule.get("severity","")).upper() not in valid_severities:
        raise HTTPException(
            status_code=422,
            detail=f"Severity must be one of: {', '.join(valid_severities)}"
        )

    # Validate rule_type
    if str(rule.get("rule_type","")).upper() not in {"HIDS", "NIDS"}:
        raise HTTPException(
            status_code=422,
            detail="rule_type must be HIDS or NIDS"
        )

    # Sanitise numeric fields
    try:
        rule["threshold"]  = int(rule["threshold"])
        rule["window_sec"] = int(rule["window_sec"])
        if rule.get("event_id"):
            rule["event_id"] = int(rule["event_id"])
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=422,
            detail="threshold and window_sec must be integers"
        )

    rule["severity"] = str(rule["severity"]).upper()
    rule["rule_type"] = str(rule["rule_type"]).upper()

    insert_rule(rule)
    return {"status": "success", "message": "Rule added successfully"}


# =========================================
# UPDATE RULE  (admin only)
# =========================================

@router.put("/api/rules/update/{rule_id}")
def edit_rule(
    rule_id: int,
    updated_rule: dict = Body(...),
    authorization: Optional[str] = Header(None)
):
    _require_admin(authorization)

    # Validate numeric fields if provided
    for field in ["threshold", "window_sec"]:
        if field in updated_rule:
            try:
                updated_rule[field] = int(updated_rule[field])
            except (ValueError, TypeError):
                raise HTTPException(
                    status_code=422,
                    detail=f"{field} must be an integer"
                )

    if "severity" in updated_rule:
        updated_rule["severity"] = str(updated_rule["severity"]).upper()

    update_rule(rule_id, updated_rule)
    return {"status": "success", "message": "Rule updated successfully"}


# =========================================
# DELETE RULE  (admin only)
# =========================================

@router.delete("/api/rules/delete/{rule_id}")
def remove_rule(
    rule_id: int,
    authorization: Optional[str] = Header(None)
):
    _require_admin(authorization)

    # Confirm rule exists
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, rule_name FROM detection_rules WHERE id = ?", (rule_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(
            status_code=404,
            detail=f"Rule {rule_id} not found"
        )

    delete_rule(rule_id)
    return {"status": "success", "message": f"Rule '{row[1]}' deleted successfully"}