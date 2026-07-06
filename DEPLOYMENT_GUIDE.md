# SOC Dashboard — Installation Guide
### Pratyush Raj | CFEES-DRDO Internship Project
### Host + Network IDS Platform v1.0

---

## Table of Contents
1. [Quick Start (Developer Machine)](#1-quick-start-developer-machine)
2. [Building the Portable EXE](#2-building-the-portable-exe)
3. [Building the Setup Installer](#3-building-the-setup-installer)
4. [Installing on a New Machine](#4-installing-on-a-new-machine)
5. [First Launch & Login](#5-first-launch--login)
6. [User Management & Roles](#6-user-management--roles)
7. [Troubleshooting](#7-troubleshooting)
8. [System Requirements](#8-system-requirements)
9. [File Structure](#9-file-structure)

---

## 1. Quick Start (Developer Machine)

If you already have Python and the project folder on the machine:

**Step 1 — Open CMD as Administrator**
```cmd
Right-click CMD → Run as Administrator
```

**Step 2 — Navigate to project folder**
```cmd
cd C:\ME\SOC_Dashboard-main
```

**Step 3 — Create virtual environment (first time only)**
```cmd
python -m venv venv
venv\Scripts\pip install -r requirements.txt
```

**Step 4 — Launch**
```cmd
venv\Scripts\python launcher.py
```

The login window appears. Enter `admin` / `admin123`.

> **Note:** From the second launch onwards, just run Step 4.
> The venv only needs to be created once.

---

## 2. Building the Portable EXE

This bundles everything into a folder you can copy to any Windows machine.
No Python, no terminal, no venv needed on the target machine.

**Requirements (on your dev machine only):**
- Python 3.11+ with venv activated
- Internet connection (one time only)

**Step 1 — Install PyInstaller**
```cmd
cd C:\ME\SOC_Dashboard-main
venv\Scripts\pip install pyinstaller
```

**Step 2 — Run the build script**
```cmd
venv\Scripts\python build_exe.py
```

**Output:**
```
dist/
└── SOC_Dashboard/
    ├── SOC_Dashboard.exe     ← Launch this
    └── _internal/            ← Required (keep next to .exe)
```

**Step 3 — Copy to target machine**

Copy the **entire** `dist/SOC_Dashboard/` folder (not just the .exe).
The `_internal/` folder must sit next to `SOC_Dashboard.exe`.

**Step 4 — Run on target machine**

Right-click `SOC_Dashboard.exe` → **Run as Administrator**
(or double-click — UAC prompt will appear automatically)

---

## 3. Building the Setup Installer

This creates a single `SOC_Dashboard_Setup.exe` — like a game installer.
Anyone can run it, it installs everything, and creates a Desktop shortcut.

**Step 1 — Install NSIS (free, one time)**

Download from: https://nsis.sourceforge.io/Download

Install with default settings. NSIS installs to:
`C:\Program Files (x86)\NSIS\`

**Step 2 — Build (PyInstaller + NSIS in one command)**
```cmd
cd C:\ME\SOC_Dashboard-main
venv\Scripts\python build_exe.py
```

The script automatically detects NSIS and runs both builds.

**Output:**
```
dist/
├── SOC_Dashboard/
│   ├── SOC_Dashboard.exe
│   └── _internal/
└── SOC_Dashboard_Setup.exe   ← Send this to anyone
```

> If NSIS was not installed when you ran `build_exe.py`, just install
> NSIS and re-run `build_exe.py` — the portable EXE step is fast (cached).

---

## 4. Installing on a New Machine

**Using the Setup installer:**

1. Copy `SOC_Dashboard_Setup.exe` to the target machine
2. Right-click → **Run as Administrator**
3. Choose install directory (default: `C:\Program Files\SOC Dashboard`)
4. Click **Install**
5. A success message shows the default login credentials
6. **SOC Dashboard** shortcut appears on the Desktop and Start Menu

**To uninstall:**
- Settings → Apps → SOC Dashboard → Uninstall
- Or run `C:\Program Files\SOC Dashboard\Uninstall.exe`

---

## 5. First Launch & Login

**Double-click the Desktop shortcut** (or `SOC_Dashboard.exe`)

- UAC prompt appears → click **Yes** (required for Windows Event Log access)
- The SOC Dashboard login window opens
- Enter credentials and click **Login**

**Default credentials:**
| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | Admin — full access |

> Change the admin password after first login via **Settings → Change Admin Password**

**What happens after login:**
1. Server starts silently in background (no terminal window)
2. Browser opens automatically to `http://127.0.0.1:8000/dashboard`
3. Dashboard loads with your role and permissions applied

**Logout flow:**
1. Go to **Settings** page in the dashboard
2. Click **Logout** button
3. Confirm the dialog
4. Browser tab closes automatically
5. Login window reappears for the next user

---

## 6. User Management & Roles

Create additional users from **Settings → User Management** after logging in as Admin.

### Role Permissions

| Feature | Admin | SOC Analyst | Viewer |
|---|:---:|:---:|:---:|
| View dashboard & alerts | ✅ | ✅ | ✅ |
| Run Full Scan | ✅ | ✅ | ❌ |
| Refresh dashboard | ✅ | ✅ | ❌ |
| Export forensic data | ✅ | ✅ | ❌ |
| Run AI Investigation | ✅ | ✅ | ❌ |
| Add / Edit / Delete rules | ✅ | ❌ | ❌ |
| Reset dashboard & DB | ✅ | ❌ | ❌ |
| Manage users | ✅ | ❌ | ❌ |
| Access Settings page | ✅ | ❌ | ❌ |

### Viewer Mode (Read-Only)
When a Viewer logs in, the server **preserves the last scan results** from the previous Admin/Analyst session. The Viewer sees all alerts and charts from that scan but cannot run new scans or change anything.

### How Users are Stored
All users are saved in `database/soc_users.db` — a **permanent file** that is never deleted when the dashboard resets or the server restarts. Users you create persist across all sessions.

---

## 7. Troubleshooting

### Login window doesn't appear
- Make sure you ran as Administrator
- Check if port 8000 is already in use:
  ```cmd
  netstat -ano | findstr :8000
  ```
  If occupied, kill the process or change PORT in `launcher.py`

### "Invalid username or password" for a created user
- The user may have been created before the `soc_users.db` fix
- Delete `database/soc_users.db` and restart — then recreate the user
- Make sure the password is at least 8 characters

### Dashboard shows 0 alerts after scan
- Run CMD as Administrator (event log access requires admin rights)
- Wait 60 seconds — Windows audit policies activate after first restart
- Check the SOC Terminal (floating button, bottom-right) for collector errors

### NSIS not found during build
```
[BUILD] NSIS not installed — Setup.exe skipped.
```
- Download NSIS from https://nsis.sourceforge.io/Download
- Install it, then re-run `python build_exe.py`

### PyInstaller build fails with missing module
Add the missing module to `build_exe.py` under `--hidden-import` flags, then rebuild.

### Browser doesn't open automatically
Navigate manually to: `http://127.0.0.1:8000/dashboard`

### Audit policies / no Security log events
Run CMD as Administrator and execute:
```cmd
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```
Then restart once for policies to take full effect.

---

## 8. System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| OS | Windows 10 (64-bit) | Windows 11 (64-bit) |
| RAM | 4 GB | 8 GB |
| Disk | 2 GB free | 5 GB free |
| Rights | Administrator | Administrator |
| Browser | Chrome / Edge / Firefox | Chrome or Edge |
| Python (dev only) | 3.11 | 3.12 |

> Python is **not required** on the target machine when using the EXE or Setup installer.
> Python is only needed on your development machine to run `build_exe.py`.

---

## 9. File Structure

```
SOC_Dashboard-main/
│
├── launcher.py                  ← Entry point (Tkinter login + server)
├── build_exe.py                 ← Build script (run once to create EXE/installer)
├── requirements.txt             ← Python dependencies
├── INSTALL_GUIDE.md             ← This file
│
├── app/
│   ├── main.py                  ← FastAPI app + router registration
│   ├── websocket_manager.py     ← SOC Terminal WebSocket
│   │
│   ├── api/
│   │   ├── auth_api.py          ← Login, user CRUD, logout endpoint
│   │   ├── dashboard_api.py     ← Chart data, scan, reset, forensics
│   │   ├── rules_api.py         ← Detection rule CRUD
│   │   ├── settings_api.py      ← Platform stats
│   │   └── investigation_api.py ← AI Investigation Center
│   │
│   ├── collectors/
│   │   ├── collector_manager.py ← Orchestrates all collectors (24h window)
│   │   ├── security_collector.py
│   │   ├── network_collector.py ← NIDS via netstat + Scapy
│   │   ├── filesystem_collector.py ← C: drive file change monitoring
│   │   ├── defender_collector.py
│   │   ├── firewall_collector.py
│   │   ├── registry_collector.py
│   │   └── ...
│   │
│   ├── services/
│   │   ├── soc_service.py       ← Scan orchestration
│   │   └── investigation_service.py ← Ollama LLM + rule-based fallback
│   │
│   ├── database/
│   │   └── database.py          ← Session DB + viewer mode
│   │
│   ├── static/
│   │   ├── css/                 ← style.css, theme.css, page-specific CSS
│   │   ├── js/                  ← dashboard.js, rules.js, settings.js, ...
│   │   └── icons-W/ icons-B/   ← Theme icon sets
│   │
│   └── templates/
│       ├── dashboard.html
│       ├── components/          ← header.html, sidebar.html
│       └── pages/               ← dashboard_page.html, settings_page.html, ...
│
└── database/
    ├── soc_YYYYMMDD_HHMMSS.db  ← Session DB (alerts, cursors) — auto-created
    ├── soc_users.db             ← Persistent user accounts — never deleted
    └── persistent_seen.db       ← Alert dedup — cleared on Reset
```

---

*SOC Simulator Dashboard — CFEES-DRDO Internship Project*
*Developed by Pratyush Raj (220905042) | MIT Manipal*