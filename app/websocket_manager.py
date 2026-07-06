"""
websocket_manager.py
=====================
Manages all active WebSocket connections and
broadcasts messages to connected browser clients.

Message types sent to the browser:
  {"type": "NEW_ALERTS"}              — reload dashboard data
  {"type": "CONSOLE", "line": "..."}  — terminal overlay line
  {"type": "SCAN_START"}              — start timer in overlay
  {"type": "SCAN_END", "total_alerts": N} — stop timer

HOW TERMINAL OUTPUT WORKS:
  soc_service.py calls manager.send_console("line") directly
  at key points during the scan. The event loop is stored
  at startup via set_event_loop() so thread-safe broadcasting
  works correctly from background scan threads.

  Do NOT use install_console_interceptor() — wrapping
  sys.stdout breaks uvicorn's signal handler on shutdown.
"""

import json
import asyncio
from fastapi import WebSocket

# =========================================
# EVENT LOOP — stored at startup
# =========================================

_loop: asyncio.AbstractEventLoop | None = None


def set_event_loop(loop: asyncio.AbstractEventLoop):
    """
    Call once from main.py lifespan with the running loop.
    This lets send_console() safely schedule coroutines
    from background scan threads.
    """
    global _loop
    _loop = loop


# =========================================
# CONNECTION MANAGER
# =========================================

class ConnectionManager:

    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    # ---- broadcast helpers (async) ----

    async def _broadcast(self, payload: dict):
        msg  = json.dumps(payload)
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    async def broadcast_new_alerts(self):
        await self._broadcast({"type": "NEW_ALERTS"})

    async def broadcast_console(self, line: str):
        await self._broadcast({"type": "CONSOLE", "line": line})

    async def broadcast_scan_start(self):
        await self._broadcast({"type": "SCAN_START"})

    async def broadcast_scan_end(self, total_alerts: int = 0):
        await self._broadcast({
            "type": "SCAN_END",
            "total_alerts": total_alerts
        })

    # ---- sync wrapper (safe from background threads) ----

    def send_console(self, line: str):
        """
        Thread-safe: schedules broadcast_console on the
        stored uvicorn event loop. Never blocks, never
        crashes if no clients are connected.
        """
        if not line or not line.strip():
            return
        if _loop is None or not _loop.is_running():
            return
        try:
            asyncio.run_coroutine_threadsafe(
                self.broadcast_console(line),
                _loop
            )
        except Exception:
            pass

    def send_scan_start(self):
        if _loop is None or not _loop.is_running():
            return
        try:
            asyncio.run_coroutine_threadsafe(
                self.broadcast_scan_start(), _loop
            )
        except Exception:
            pass

    def send_scan_end(self, total_alerts: int = 0):
        if _loop is None or not _loop.is_running():
            return
        try:
            asyncio.run_coroutine_threadsafe(
                self.broadcast_scan_end(total_alerts), _loop
            )
        except Exception:
            pass


# =========================================
# GLOBAL INSTANCE
# =========================================

manager = ConnectionManager()


# =========================================
# KEPT FOR IMPORT COMPATIBILITY
# install_console_interceptor is a no-op now.
# main.py imports it — keeping the name avoids
# an ImportError if old code references it.
# =========================================

def install_console_interceptor():
    """No-op. Stdout wrapping removed — see module docstring."""
    pass