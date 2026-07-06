# SOC Simulator — Deployment & Build Guide

## Files Delivered

| File | Purpose |
|---|---|
| `launcher.py` | Replace your existing launcher.py |
| `websocket_manager.py` | Replace your existing websocket_manager.py |
| `console_overlay.js` | Copy to `app/static/js/` |
| `integrity_guard.py` | Place in project root |
| `build_exe.py` | Place in project root |

---

## Step 1 — Add console_overlay.js to dashboard.html

Open `app/templates/dashboard.html` and add ONE line
at the bottom of the `<body>`, after the existing
script tags:

```html
<script src="/static/js/console_overlay.js"></script>
```

Also add the Terminal toggle button somewhere in your
sidebar or top bar HTML:

```html
<button onclick="SOCConsole.toggle()" style="...">
    ⬛ Terminal
</button>
```

---

## Step 2 — Update main.py lifespan to activate console interceptor

Open `app/main.py` and add two lines inside the
`lifespan` function:

```python
from app.websocket_manager import install_console_interceptor

@asynccontextmanager
async def lifespan(app: FastAPI):
    install_console_interceptor()   # ← ADD THIS LINE
    soc_service.reset_live_dashboard()
    print("[SOC] Dashboard session initialized")
    yield
```

That single call redirects ALL print() output in your
entire application to the WebSocket overlay — no other
changes needed anywhere.

Also add scan_start/scan_end broadcasts in soc_service.py:

```python
from app.websocket_manager import manager
import asyncio

# At the start of run_full_scan():
asyncio.run(manager.broadcast_scan_start())

# At the end of run_full_scan():
asyncio.run(manager.broadcast_scan_end(
    total_alerts=len(alerts)
))
```

---

## Step 3 — Seal the project (tamper protection)

Run this ONCE after you finish all development:

```cmd
python integrity_guard.py
```

Output:
```
[HASH] app/main.py
[HASH] app/engines/detection_engine.py
...
[SEAL] ✅ 87 files sealed
[SEAL] Manifest: security/manifest.json
[SEAL] Lock applied to security/ folder
```

This creates:
- `security/manifest.json` — HMAC-signed hashes of every .py .js .html .css .json file
- `security/.seal_key` — random 32-byte key (hidden, system-flagged)

**After sealing:** if anyone modifies any source file,
the next launch will show:

```
TAMPER DETECTED
[MODIFIED] app/engines/detection_engine.py
The application cannot start.
```

To reseal after intentional changes:
```cmd
python integrity_guard.py reseal
```

To verify without launching:
```cmd
python integrity_guard.py verify
```

---

## Step 4 — Build the .exe

On your development machine (with Python + venv active):

```cmd
python build_exe.py
```

This will:
1. Install PyInstaller if missing
2. Bundle your entire project into `dist/SOC_Dashboard/`
3. The final EXE is `dist/SOC_Dashboard/SOC_Dashboard.exe`

**Distribute the entire `dist/SOC_Dashboard/` folder**,
not just the .exe — it needs `_internal/` next to it.

---

## Step 5 — What happens when someone runs SOC_Dashboard.exe

```
Double-click SOC_Dashboard.exe
       │
       ▼
UAC prompt (admin required)
       │
       ▼
Integrity check
  → All files OK? Continue
  → Any file tampered? ABORT + show which file
       │
       ▼
Python dialog (if packages missing):
  [Use existing Python] [Install fresh Python] [Cancel]
       │
       ▼
Install progress window (live console output):
  [████████░░] Installing Python packages...
  [SOC] Installing Sysmon...
  [SOC] Sealing project...
       │
       ▼
Login window:
  Username: admin
  Password: admin123
       │
       ▼
SOC backend starts (uvicorn)
       │
       ▼
Browser opens → http://127.0.0.1:8000/dashboard
       │
       ▼
⬛ Terminal button (bottom-right) → floating overlay
  shows all scan output in real time with timer
```

---

## Tamper Protection Summary

| Layer | What it does |
|---|---|
| HMAC-signed hashes | Every .py .js .html .css .json file is hashed and signed with a secret key |
| Key is hidden | `.seal_key` is flagged Hidden+System on Windows |
| Folder is locked | `icacls` removes Everyone write permissions from `security/` |
| Launch check | Every startup re-verifies all hashes before showing login |
| Abort on tamper | Any modified or missing file → app refuses to start |

---

## Credentials

Default login: `admin` / `admin123`

To change: edit `launcher.py` lines:
```python
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
```
Then reseal: `python integrity_guard.py reseal`
Then rebuild: `python build_exe.py`

---

## Folder structure after build

```
SOC_Dashboard/          ← distribute this entire folder
├── SOC_Dashboard.exe   ← double-click to run
└── _internal/          ← bundled Python + all packages
    ├── app/
    ├── requirements.txt
    └── ...
```
