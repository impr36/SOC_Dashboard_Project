"""
investigation_api.py
====================
FastAPI router for the AI Investigation Center.
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional

from app.database.database import get_connection
from app.services.investigation_service import investigate, check_ollama

router = APIRouter()


# =========================================
# OLLAMA STATUS
# =========================================

@router.get("/api/investigate/ollama-status")
async def ollama_status():
    return check_ollama()


# =========================================
# INVESTIGATE SELECTED ALERTS
# =========================================

class InvestigateRequest(BaseModel):
    alert_ids: Optional[List[int]] = None   # specific alert IDs
    category:  Optional[str]       = None   # or investigate a whole category
    severity:  Optional[str]       = None   # or a severity level
    context:   Optional[str]       = ""     # analyst notes / extra context
    limit:     Optional[int]       = 50     # max alerts to send to LLM


@router.post("/api/investigate")
async def investigate_alerts(req: InvestigateRequest):
    conn   = get_connection()
    cursor = conn.cursor()

    if req.alert_ids:
        placeholders = ",".join("?" * len(req.alert_ids))
        cursor.execute(
            f"SELECT * FROM alerts WHERE id IN ({placeholders}) ORDER BY id DESC",
            req.alert_ids
        )
    elif req.category:
        cursor.execute(
            "SELECT * FROM alerts WHERE category = ? ORDER BY id DESC LIMIT ?",
            (req.category, req.limit)
        )
    elif req.severity:
        cursor.execute(
            "SELECT * FROM alerts WHERE severity = ? ORDER BY id DESC LIMIT ?",
            (req.severity.upper(), req.limit)
        )
    else:
        # Investigate all alerts (latest N)
        cursor.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
            (req.limit,)
        )

    rows   = cursor.fetchall()
    conn.close()
    alerts = [dict(r) for r in rows]

    if not alerts:
        return {"error": "No alerts found matching the criteria"}

    result = investigate(alerts, req.context or "")
    result["input_alert_count"] = len(alerts)
    return result


# =========================================
# INVESTIGATE ALL (convenience endpoint)
# =========================================

@router.get("/api/investigate/all")
async def investigate_all(limit: int = 50):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows   = cursor.fetchall()
    conn.close()
    alerts = [dict(r) for r in rows]
    if not alerts:
        return {"error": "No alerts in database. Run a Full Scan first."}
    result = investigate(alerts)
    result["input_alert_count"] = len(alerts)
    return result


# =========================================
# CHAT (follow-up questions about alerts)
# =========================================

class ChatRequest(BaseModel):
    question:  str
    alert_ids: Optional[List[int]] = None
    limit:     Optional[int]       = 30


@router.post("/api/investigate/chat")
async def investigation_chat(req: ChatRequest):
    conn   = get_connection()
    cursor = conn.cursor()

    if req.alert_ids:
        placeholders = ",".join("?" * len(req.alert_ids))
        cursor.execute(
            f"SELECT * FROM alerts WHERE id IN ({placeholders})",
            req.alert_ids
        )
    else:
        cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (req.limit,))

    rows   = cursor.fetchall()
    conn.close()
    alerts = [dict(r) for r in rows]

    # Use investigation service with the question as context
    context = f"Analyst question: {req.question}"
    result  = investigate(alerts, context)

    # Return focused chat answer
    return {
        "question": req.question,
        "answer":   result.get("technical_assessment", "Unable to process question"),
        "executive": result.get("executive_summary", ""),
        "risk_score": result.get("risk_score", 0),
        "generated_by": result.get("generated_by", "unknown"),
    }
