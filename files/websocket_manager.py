"""
websocket_manager.py
=====================
Manages all active WebSocket connections and
provides broadcast helpers used throughout the app.

Message types sent to the browser:
  {"type": "NEW_ALERTS"}             — tells dashboard to reload
  {"type": "CONSOLE", "line": "..."}  — terminal line for overlay
  {"type": "SCAN_START"}             — starts the timer in overlay
  {"type": "SCAN_END",
   "total_alerts": N}                — stops the timer
"""

import json
import asyncio
import sys
import io
from typing import Any
from fastapi import WebSocket


class ConnectionManager:

    def __init__(self):
        self.active: list[WebSocket] = []

    # ---- connection lifecycle ----

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    # ---- broadcast helpers ----

    async def _broadcast(self, payload: dict):
        """Send JSON to every connected client."""
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
        """Stream a single terminal line to the overlay."""
        await self._broadcast({
            "type": "CONSOLE",
            "line": line
        })

    async def broadcast_scan_start(self):
        await self._broadcast({"type": "SCAN_START"})

    async def broadcast_scan_end(self, total_alerts: int = 0):
        await self._broadcast({
            "type": "SCAN_END",
            "total_alerts": total_alerts
        })

    # ---- sync wrapper (call from non-async code) ----

    def send_console(self, line: str):
        """
        Thread-safe sync wrapper.
        Call this from soc_service.py / detection_engine.py
        wherever you currently use print().
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self.broadcast_console(line),
                    loop
                )
            else:
                loop.run_until_complete(
                    self.broadcast_console(line)
                )
        except Exception:
            pass  # Never crash the scan on WS error


# =========================================
# GLOBAL INSTANCE
# =========================================

manager = ConnectionManager()


# =========================================
# CONSOLE INTERCEPTOR
# =========================================
# Wraps sys.stdout so every print() in the
# application is also forwarded to the WS
# overlay — you don't need to replace print()
# calls throughout your codebase.

class _WSConsoleInterceptor(io.TextIOBase):
    """
    Sits between Python's print() and the real
    stdout. Every line is sent to connected
    WebSocket clients AND still printed to the
    real terminal.
    """

    def __init__(self, real_stdout):
        self._real  = real_stdout
        self._buf   = ""

    def write(self, text: str) -> int:
        # Always write to real terminal
        self._real.write(text)
        self._real.flush()

        # Buffer until newline
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            line = line.rstrip("\r")
            if line:
                manager.send_console(line)

        return len(text)

    def flush(self):
        self._real.flush()

    def fileno(self):
        return self._real.fileno()

    @property
    def encoding(self):
        return getattr(self._real, "encoding", "utf-8")


def install_console_interceptor():
    """
    Call once at app startup (in main.py lifespan)
    to redirect all print() output to the WS overlay.
    """
    if not isinstance(sys.stdout, _WSConsoleInterceptor):
        sys.stdout = _WSConsoleInterceptor(sys.stdout)
