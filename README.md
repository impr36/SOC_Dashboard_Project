<div align="center">

<img src="app/static/icons-W/shield.png" alt="SOC Simulator Logo" width="80"/>

# SOC Simulation Dashboard

### Host + Network IDS Platform

**A full-stack cybersecurity monitoring platform simulating real-world Security Operations Center (SOC) workflows — built during an internship at CFEES, DRDO, New Delhi.**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

---

> **Developed by:** Pratyush Raj (Reg. No. 220905256)  
> **Institution:** Manipal Institute of Technology, Manipal  
> **Internship:** CFEES — Centre for Fire, Explosive and Environment Safety, DRDO, New Delhi  
> **Supervisor:** Mr. T. S. Rathore, Scientist 'F', CFEES-DRDO  
> **Internal Guide:** Dr. Srikanth Prabhu, Professor, School of Computer Engineering, MIT Manipal

</div>

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Screenshots](#screenshots)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Method 1 — Run from Source (Recommended for Development)](#method-1--run-from-source-recommended-for-development)
  - [Method 2 — One-Click Installer (Recommended for Deployment)](#method-2--one-click-installer-recommended-for-deployment)
- [Default Credentials](#default-credentials)
- [How to Use](#how-to-use)
- [Detection Capabilities](#detection-capabilities)
- [File Structure](#file-structure)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Tech Stack](#tech-stack)
- [License](#license)

---

## Overview

The **SOC Simulation Dashboard** is a comprehensive, offline-capable cybersecurity monitoring platform that simulates the complete workflow of a Security Operations Center. It integrates **Host-Based Intrusion Detection (HIDS)** and **Network-Based Intrusion Detection (NIDS)** into a single unified analyst interface, with AI-powered threat investigation, role-based access control, persistent multi-user authentication, and a one-click Windows installer.

Built entirely in Python and deployed as a browser-based dashboard, the platform is designed for:

- **Cybersecurity education and SOC analyst training**
- **Threat detection research in isolated/air-gapped environments**
- **Practical demonstration of real-world SOC monitoring workflows**
- **Defence and government training labs without cloud dependency**

The system collects telemetry from **11 Windows event sources**, evaluates events against **1,419 detection rules**, generates classified alerts with **MITRE ATT&CK annotations**, and presents everything through a dark-themed real-time analyst dashboard — all without requiring any external services or internet connectivity.

---

## Key Features

| Feature | Description |
|---|---|
| 🛡️ **HIDS Monitoring** | 10 Windows telemetry collectors covering Security logs, Sysmon, PowerShell, Defender, Firewall, DNS, Registry, Task Scheduler, WMI, and Filesystem |
| 🌐 **NIDS Monitoring** | Network collector using netstat + optional Scapy for port scan, C2 beaconing, lateral movement, and suspicious port detection |
| 🤖 **AI Investigation Center** | 7-tab investigation interface with Ollama LLM integration and deterministic rule-based fallback — works fully offline |
| 🎯 **MITRE ATT&CK Mapping** | All alerts annotated with ATT&CK technique IDs across 14 tactical categories |
| 👥 **Role-Based Access Control** | Three-tier RBAC (Admin / SOC Analyst / Viewer) enforced in both FastAPI backend and JavaScript frontend |
| 🔐 **Persistent Authentication** | PBKDF2-SHA256 multi-user authentication with 260,000 iterations stored in a permanent dedicated database |
| 📊 **Real-Time Dashboard** | Live severity charts, threat category distribution, alert queue with WebSocket streaming |
| 📁 **Forensic Export** | JSON + CSV + TXT export with timestamp-grouped bundles and ZIP download |
| 📋 **Detection Rules CRUD** | Full add/edit/delete management of 925 HIDS + 494 NIDS rules through the browser UI |
| 🖥️ **SOC Terminal** | Floating draggable terminal overlay streaming live collector output over WebSocket |
| 🔒 **File Integrity Guard** | HMAC-SHA256 tamper detection — verifies all project files on launch |
| 📦 **One-Click Installer** | PyInstaller + NSIS deployment pipeline — no Python required on target machine |

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     PRESENTATION LAYER                          │
│         Browser Dashboard — Chart.js, HTML/CSS/JS               │
├─────────────────────────────────────────────────────────────────┤
│                     APPLICATION LAYER                           │
│         FastAPI — REST API, WebSocket, RBAC Middleware          │
├─────────────────────────────────────────────────────────────────┤
│                      ANALYSIS LAYER                             │
│    AI Investigation — MITRE ATT&CK Mapping — Alert Correlation  │
├─────────────────────────────────────────────────────────────────┤
│                      DETECTION LAYER                            │
│       Rule Engine — 1,419 Signatures — Alert Deduplication      │
├─────────────────────────────────────────────────────────────────┤
│                     COLLECTION LAYER                            │
│  11 Collectors: Security | Sysmon | PS | Defender | Firewall    │
│               DNS | Registry | Tasks | WMI | FS | Network       │
├─────────────────────────────────────────────────────────────────┤
│                      FORENSICS LAYER                            │
│         Evidence Export — Bundle Management — ZIP Download      │
├─────────────────────────────────────────────────────────────────┤
│                      DATABASE LAYER                             │
│  soc_session.db | soc_users.db | rules.db | persistent_seen.db  │
└─────────────────────────────────────────────────────────────────┘
```

**Data Flow:** Windows telemetry → Normalization → Rule Engine → Deduplication → SQLite → WebSocket → Dashboard

---

## Screenshots

> Screenshots from the live dashboard — taken during testing on Windows 11

### Main Dashboard
![Main Dashboard](docs/screenshots/dashboard.png)

*335 alerts detected — 152 Critical, 168 High, 15 Medium | Defense Evasion and Persistence as top categories*

### HIDS Investigation Console
![HIDS Console](docs/screenshots/hids_console.png)

*Correlated incident groups GRP-150 to GRP-147 — Firmware Persistence, ICS SCADA Command Injection, UEBA Long Term Persistence*

### AI Investigation Center
![AI Investigation](docs/screenshots/ai_investigation.png)

*Risk score 69/100 — HIGH threat level — MITRE ATT&CK technique mapping across 7 analysis tabs*

### Detection Rules Management
![Detection Rules](docs/screenshots/rules.png)

*1,419 rules — HIDS and NIDS tabs — full CRUD for Admin role*

---

## Prerequisites

Before running the SOC Dashboard, ensure the following are installed on your Windows machine:

### Required

| Requirement | Version | Notes |
|---|---|---|
| **Windows** | 10 or 11 (64-bit) | Linux/macOS not supported — Windows event log APIs required |
| **Python** | 3.11 or higher | [Download](https://python.org/downloads/) — add to PATH during install |
| **Administrator privileges** | — | Required for reading Windows Security event logs |

### Optional (for enhanced functionality)

| Requirement | Purpose | Download |
|---|---|---|
| **Microsoft Sysmon** | Detailed host telemetry (process creation, registry, network by process) | [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| **Npcap** | Full packet capture for NIDS (otherwise netstat-only) | [Npcap](https://npcap.com/) |
| **Ollama** | Local LLM for AI Investigation Center (rule-based fallback works without it) | [Ollama](https://ollama.ai/) |

### Enable Windows Audit Policies (Recommended)

Run these commands in an elevated PowerShell to enable full telemetry:

```powershell
# Enable Security audit logging
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"Process Tracking" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable

# Enable PowerShell Script Block Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Force
```

---

## Installation

### Method 1 — Run from Source (Recommended for Development)

#### Step 1 — Clone the Repository

```bash
git clone https://github.com/impr360/SOC_Simulator.git
cd SOC_Simulator
```

Or download the ZIP from GitHub and extract it.

#### Step 2 — Create a Virtual Environment

```bash
python -m venv venv
```

Activate it:

```bash
# Windows Command Prompt
venv\Scripts\activate

# Windows PowerShell
venv\Scripts\Activate.ps1

# If PowerShell execution policy blocks activation:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

This installs FastAPI, uvicorn, pandas, pywin32, scapy, and all other required packages.

#### Step 4 — Launch the Dashboard

**Right-click** your terminal and select **"Run as Administrator"**, then:

```bash
python launcher.py
```

> ⚠️ **Administrator privileges are required.** The launcher will automatically prompt for UAC elevation if not already running as admin.

#### Step 5 — Log In

The Tkinter login window will appear. Use the default credentials:

```
Username: admin
Password: admin123
```

The browser will open automatically at `http://127.0.0.1:8000/dashboard`

---

### Method 2 — One-Click Installer (Recommended for Deployment)

If you want to install the dashboard on a machine without Python:

#### Step 1 — Build the Installer (on your development machine)

Ensure you have PyInstaller and NSIS installed:

```bash
pip install pyinstaller
# Download NSIS from https://nsis.sourceforge.io/ and install it
```

Then run:

```bash
python build_exe.py
```

This will:
1. Bundle the application with PyInstaller into `dist/SOC_Dashboard/`
2. Generate `SOC_Dashboard_Setup.nsi`
3. Compile `SOC_Dashboard_Setup.exe` using NSIS

#### Step 2 — Run the Installer on the Target Machine

Double-click `SOC_Dashboard_Setup.exe` and follow the wizard:

1. Accept the license agreement
2. Choose installation directory (default: `C:\Program Files\SOC Dashboard`)
3. Click **Install**
4. A Desktop shortcut and Start Menu entry will be created
5. Post-installation credentials are displayed

#### Step 3 — Launch

Double-click the **SOC Dashboard** shortcut on the Desktop.

---

## Default Credentials

| Username | Password | Role | Access Level |
|---|---|---|---|
| `admin` | `admin123` | Administrator | Full access — all features |

> ⚠️ **Change the default password immediately after first login** via Settings → Change Admin Password.

### Creating Additional Users

1. Log in as Admin
2. Navigate to **Settings** (gear icon in sidebar)
3. Scroll to **User Management → Add New User**
4. Fill in username, display name, password (min 8 chars), and select role
5. Click **Create User**

Available roles:

| Role | Permissions |
|---|---|
| **Admin** | Full access — scan, reset, manage users, edit rules, investigate, export |
| **SOC Analyst** | Monitor, scan, investigate, export — cannot manage users or edit rules |
| **Viewer** | Read-only — views last scan results without operational controls |

---

## How to Use

### Running Your First Scan

1. Launch the dashboard and log in as Admin
2. The browser opens at `http://127.0.0.1:8000/dashboard`
3. Click **Run Full Scan** — the button is at the bottom of the main page
4. Monitor live output in the **SOC Terminal** (floating button, bottom-right corner)
5. After the scan completes, the dashboard auto-refreshes with detected alerts

### Investigating Alerts

**HIDS Investigation Console:**
- Click the monitor icon in the left sidebar
- Browse correlated incident groups (GRP-NNN)
- Click the arrow on any group to expand and see constituent alerts
- Update investigation status using the dropdown (New → In Progress → Resolved)

**NIDS Investigation Console:**
- Click the globe icon in the left sidebar
- Browse network-based incidents (NET-NNN)
- Expand groups to see source IP, destination IP, protocol, and MITRE technique

**AI Investigation Center:**
- Click the brain/search icon in the sidebar
- Select alert scope (All Current Alerts / filter by severity or category)
- Optionally add analyst context notes
- Click **Run Investigation**
- Review results across 7 tabs: Summary, Technical, Attack Story, MITRE ATT&CK, Remediation, Plain Language, Chat

### Exporting Forensic Evidence

1. After a scan, click **Save to Forensics** on the main dashboard
2. Navigate to **Saved Files** (folder icon in sidebar)
3. Find your export bundle grouped by timestamp
4. Download individual files (JSON / CSV / TXT) or click **ZIP All** for the complete bundle

### Managing Detection Rules

1. Navigate to **Detection Rules** (document icon in sidebar)
2. Switch between **HIDS Rules** and **NIDS Rules** tabs
3. Use the search bar to find specific rules
4. Admin users can:
   - Click **+ Add Rule** to create a new signature
   - Click **Edit** on any row to modify an existing rule
   - Select rules and click **Delete Rule** to remove them

---

## Detection Capabilities

### HIDS Detection — Windows Event Sources

| Collector | Event IDs / Source | What It Detects |
|---|---|---|
| Security Log | 4624, 4625, 4648, 4672, 4688, 4698, 4720, 4726, 4663, 4660 | Authentication, privilege escalation, process creation, file access |
| Sysmon | 1, 3, 11, 13 | Process creation, network connections by process, file create, registry |
| PowerShell | 4104 | Script block logging — obfuscated/malicious PowerShell |
| Windows Defender | Various | Malware detections, quarantine actions, tampering |
| Firewall | Various | Blocked inbound/outbound connections |
| DNS | Various | Suspicious query patterns, potential DNS tunnelling |
| Registry | 4657 + autorun keys | Persistence via Run keys, startup modification |
| Task Scheduler | Various | Malicious scheduled task creation |
| WMI | Various | Remote WMI execution, subscription-based persistence |
| Filesystem | 4663, 4660 + direct scan | File creation/deletion in high-risk directories, suspicious extensions |

### NIDS Detection — Network Patterns

| Pattern | Trigger Condition | Severity |
|---|---|---|
| Port Scanning | ≥ 10 unique destination ports from one source | HIGH |
| Connection Flooding | ≥ 50 simultaneous connections from one source | CRITICAL |
| C2 Beaconing | ≥ 5 repeated connections to the same external IP | HIGH |
| Suspicious Ports | Connections on Metasploit (4444/4445), Tor (9050), WinRM (5985/5986) | HIGH |
| Lateral Movement | Connections on SMB (445), RDP (3389), WinRM (5985/5986) | HIGH |
| Tor Traffic | Connections to Tor ORPort (9001) or SOCKS (9050/9150) | HIGH |
| NetBIOS Exposure | Ports 137–139 publicly accessible | MEDIUM |
| Unusual Listening Ports | Services bound to unexpected port ranges | MEDIUM |

### Severity Classification

| Level | Color | Meaning |
|---|---|---|
| 🔴 **CRITICAL** | Red | Immediate action required — active compromise indicators |
| 🟠 **HIGH** | Orange | Significant threat — investigate promptly |
| 🟡 **MEDIUM** | Yellow | Suspicious activity — review when possible |
| 🟢 **LOW** | Green | Informational — routine monitoring |

---

## File Structure

```
SOC_Dashboard-main/
│
├── launcher.py                    ← Entry point: Tkinter login + UAC elevation + server launch
├── integrity_guard.py             ← HMAC-SHA256 tamper detection for all project files
├── build_exe.py                   ← PyInstaller EXE builder + NSIS installer generator
├── requirements.txt               ← Python package dependencies
├── DEPLOYMENT_GUIDE.md            ← Deployment and configuration reference
│
├── app/                           ← Main application package
│   │
│   ├── main.py                    ← FastAPI app factory + router registration + WebSocket
│   ├── websocket_manager.py       ← WebSocket connection manager + SOC Terminal buffer
│   │
│   ├── api/                       ← REST API route handlers
│   │   ├── auth_api.py            ← /api/auth/* — login, /me, user CRUD, JWT tokens
│   │   ├── dashboard_api.py       ← /api/chart-data, /api/run-scan, /api/alerts, forensics
│   │   ├── rules_api.py           ← /api/rules/* — HIDS/NIDS rule CRUD
│   │   ├── settings_api.py        ← /api/settings/* — platform stats, config
│   │   └── investigation_api.py   ← /api/investigate, /api/chat, /api/ollama-status
│   │
│   ├── collectors/                ← Windows telemetry collection modules
│   │   ├── collector_manager.py   ← Orchestrates all collectors via ThreadPoolExecutor
│   │   ├── security_collector.py  ← Windows Security event log (4624, 4625, 4688...)
│   │   ├── sysmon_collector.py    ← Sysmon events (process, registry, network, file)
│   │   ├── system_collector.py    ← System log (USB, services, shutdowns, Event 7045)
│   │   ├── application_collector.py ← Application event log
│   │   ├── powershell_collector.py  ← PowerShell script block logging (Event 4104)
│   │   ├── network_collector.py   ← NIDS: netstat + optional Scapy packet capture
│   │   ├── firewall_collector.py  ← Windows Firewall rule change events
│   │   ├── dns_collector.py       ← DNS query monitoring
│   │   ├── defender_collector.py  ← Windows Defender detection events
│   │   ├── registry_collector.py  ← Registry autorun keys + Event 4657
│   │   ├── taskscheduler_collector.py ← Scheduled task creation/modification events
│   │   ├── wmi_collector.py       ← WMI subscription and remote execution events
│   │   ├── filesystem_collector.py ← File create/delete/modify on C: drive
│   │   ├── forensic_scanner.py    ← File snapshot hashing for integrity verification
│   │   └── system_info.py         ← OS version, IP, hostname, memory, disk stats
│   │
│   ├── engines/                   ← Detection and analysis engines
│   │   ├── detection_engine.py    ← Rule evaluation engine + MITRE ATT&CK mapping
│   │   ├── correlation_engine.py  ← Alert correlation + incident group assignment
│   │   ├── incident_engine.py     ← Structured incident record builder
│   │   ├── normalization_engine.py ← Multi-source log normalization to unified schema
│   │   ├── threat_hunting_engine.py ← Hunt query execution across alert dataset
│   │   └── timeline_engine.py     ← Attack timeline reconstruction from alert sequence
│   │
│   ├── services/                  ← Business logic and orchestration services
│   │   ├── soc_service.py         ← run_full_scan(), refresh_alerts() orchestration
│   │   ├── investigation_service.py ← Ollama LLM + rule-based fallback analysis engine
│   │   └── realtime_monitor.py    ← Background continuous monitoring service
│   │
│   ├── alerts/
│   │   └── alert_manager.py       ← store_alert(), insert_alert() with SHA-256 dedup
│   │
│   ├── core/
│   │   └── session_manager.py     ← Session creation and database lifecycle management
│   │
│   ├── database/
│   │   └── database.py            ← SQLite connection management + schema init + cursors
│   │
│   ├── rules/                     ← Detection rule libraries
│   │   ├── hids_rules.json        ← 925 HIDS detection rules with MITRE annotations
│   │   ├── nids_rules.json        ← 494 NIDS detection rules with MITRE annotations
│   │   └── load_default_rules.py  ← Loads JSON rules into database on first startup
│   │
│   ├── static/                    ← Frontend assets
│   │   ├── css/
│   │   │   ├── style.css          ← Main dashboard stylesheet + RBAC visibility rules
│   │   │   ├── theme.css          ← Dark/light mode CSS custom properties
│   │   │   ├── settings.css       ← Settings page styles
│   │   │   ├── rules.css          ← Detection rules page styles
│   │   │   ├── saved_files.css    ← Saved files grouped bundle styles
│   │   │   └── investigation.css  ← AI Investigation Center styles
│   │   │
│   │   ├── js/
│   │   │   ├── dashboard.js       ← Charts, scan/refresh/reset, RBAC, floating terminal
│   │   │   ├── settings.js        ← Theme toggle, user CRUD, password change
│   │   │   ├── rules.js           ← Rule table, add/edit/delete modal logic
│   │   │   ├── saved_files.js     ← Bundle view, ZIP download, file preview modal
│   │   │   ├── investigation.js   ← AI investigation, Ollama status, 7-tab interface
│   │   │   ├── console_overlay.js ← Floating SOC Terminal panel and WebSocket client
│   │   │   └── chart.umd.min.js   ← Local Chart.js (offline — no CDN dependency)
│   │   │
│   │   └── icons-W/               ← White icon set for dark mode UI
│   │       ├── shield.png
│   │       ├── cctv.png
│   │       ├── analytics.png
│   │       └── ...
│   │
│   └── templates/                 ← Jinja2 HTML templates
│       ├── dashboard.html         ← Main shell — links all CSS/JS, includes page partials
│       ├── components/
│       │   ├── header.html        ← Fixed header with logo, title, user display, signature
│       │   ├── sidebar.html       ← Navigation (role-filtered sidebar buttons)
│       │   └── top_cards.html     ← Severity/Total/LastScan/System/Memory/Disk cards
│       │
│       └── pages/
│           ├── dashboard_page.html    ← Charts + alert queue + action buttons
│           ├── hids_page.html         ← HIDS Investigation Console
│           ├── nids_page.html         ← NIDS Investigation Console
│           ├── rules_page.html        ← Detection Rules CRUD interface
│           ├── settings_page.html     ← Theme toggle + user management
│           ├── saved_files_page.html  ← Grouped forensic export bundles
│           └── investigation_page.html ← AI Investigation Center (7 tabs + chat)
│
├── database/                      ← Runtime databases (auto-created on first launch)
│   ├── soc_YYYYMMDD_HHMMSS.db    ← Session alert database (fresh each Admin/Analyst launch)
│   ├── soc_users.db               ← Persistent user accounts — NEVER deleted
│   └── persistent_seen.db         ← Cross-session alert deduplication hashes
│
├── forensics_exports/             ← Forensic evidence bundles (auto-created)
│   ├── forensic_alerts_*.json     ← Full alert records with all metadata
│   ├── alert_summary_*.csv        ← Alert summary for spreadsheet analysis
│   └── dashboard_report_*.txt     ← Formatted security statistics report
│
├── powershell_logs/               ← PowerShell transcript logs (auto-created)
│
└── security/                      ← File integrity verification
    ├── manifest.json              ← HMAC-SHA256 hashes of all protected project files
    └── .seal_key                  ← Seal verification key (hidden system file)
```

---

## Configuration

### Environment Variables

The launcher automatically sets these environment variables before starting the server:

| Variable | Values | Purpose |
|---|---|---|
| `SOC_LOGGED_USER` | username string | Authenticated user's username |
| `SOC_LOGGED_ROLE` | `admin` / `analyst` / `viewer` | Authenticated user's role |
| `SOC_LOGGED_DISPLAY` | display name string | Display name shown in dashboard header |
| `SOC_VIEWER_MODE` | `0` or `1` | `1` = skip DB deletion, reuse last session for Viewer |
| `SOC_LOGOUT_REQUESTED` | `0` or `1` | `1` = trigger server shutdown and return to login |

### Server Settings

Edit these constants in `launcher.py` if you need to change the server binding:

```python
HOST = "127.0.0.1"   # Change to "0.0.0.0" to allow LAN access
PORT = 8000          # Change if port 8000 is already in use
```

### Scan Window

The default collection window is 24 hours. To change this, edit `app/services/soc_service.py`:

```python
DEFAULT_HOURS = 24   # Increase if you want to capture older events
```

### Enabling Ollama for AI Investigation

1. Install Ollama from [https://ollama.ai/](https://ollama.ai/)
2. Pull a model:
   ```bash
   ollama pull llama3
   # or
   ollama pull mistral
   ```
3. Start Ollama:
   ```bash
   ollama serve
   ```
4. The AI Investigation Center will automatically detect Ollama and use it. If Ollama is offline, the rule-based fallback engine activates automatically — no configuration needed.

---

## Troubleshooting

### Dashboard shows 0 alerts after a scan

**Cause:** All generated alerts were filtered by the deduplication system — they already exist in `persistent_seen.db` from a previous scan.

**Fix:** Click the **Reset** button (red, in the action bar) to clear the session database and deduplication hashes, then run a new Full Scan.

---

### `TypeError: can't compare offset-naive and offset-aware datetimes`

**Cause:** Timestamp mismatch between UTC and local time in `dashboard_api.py`.

**Fix:** In `app/api/dashboard_api.py`, find the cutoff calculation and ensure it uses:
```python
now_utc = datetime.now(timezone.utc)
cutoff  = now_utc - timedelta(hours=selected_hours)
```

---

### Login window does not reappear after logout

**Cause:** The Tkinter root window was destroyed instead of hidden.

**Fix:** Ensure `launcher.py` uses `self.root.withdraw()` in `_launch_dashboard()` and `self.root.deiconify()` in `_poll_logout()`, rather than `self.root.destroy()`.

---

### Sysmon collection failed — `EvtQuery` channel not found

**Cause:** Sysmon is not installed on the machine.

**Fix (Option 1):** Install Sysmon for enhanced telemetry:
```powershell
# Download from https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

**Fix (Option 2):** This is a non-fatal warning — the system automatically falls back to high-fidelity telemetry from other collectors. The dashboard will still function correctly.

---

### Server did not start in time

**Cause:** Port 8000 is already in use by another application.

**Fix:**
```bash
# Check what is using port 8000
netstat -ano | findstr :8000

# Kill the process (replace PID with the actual PID from above)
taskkill /PID <PID> /F
```

Or change `PORT = 8000` to a different port in `launcher.py`.

---

### `[TAMPER] Cannot read security manifest` on launch

**Cause:** The security manifest was corrupted or a project file was modified after sealing.

**Fix:** Delete the `security/` folder and relaunch — the manifest will be rebuilt automatically on the next clean launch:
```bash
rmdir /s /q security
python launcher.py
```

---

### pywin32 import errors

**Cause:** pywin32 post-install scripts did not run.

**Fix:**
```bash
pip install pywin32 --upgrade
python Scripts/pywin32_postinstall.py -install
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.11, FastAPI, Uvicorn |
| **Database** | SQLite (sqlite3) |
| **Frontend** | HTML5, CSS3, JavaScript (ES6+) |
| **Visualization** | Chart.js (local, no CDN) |
| **Data Processing** | Pandas |
| **Desktop UI** | Tkinter |
| **Windows Telemetry** | pywin32 (win32evtlog) |
| **Host Monitoring** | Microsoft Sysmon |
| **Network Monitoring** | Scapy (optional), netstat |
| **AI Investigation** | Ollama (optional), deterministic rule-based fallback |
| **Password Security** | PBKDF2-SHA256, 260,000 iterations |
| **File Integrity** | HMAC-SHA256 |
| **Deployment** | PyInstaller, NSIS |
| **Version Control** | Git |

---

## Acknowledgements

This project was developed during an internship at **CFEES, DRDO, New Delhi** (January – July 2026).

Special thanks to:
- **Mr. T. S. Rathore**, Scientist 'F', CFEES-DRDO — for industry guidance and SOC operational insights
- **Dr. Srikanth Prabhu**, Professor, MIT Manipal — for academic mentorship and technical direction
- **Dr. Smitha N. Pai**, Associate Dean, School of Computer Engineering, MIT Manipal

---


**Pratyush Raj** · [LinkedIn](https://linkedin.com/in/impr36) · [GitHub](https://github.com/impr36)

*B.Tech Computer Science (Minor: Cybersecurity) · Manipal Institute of Technology · 2026*

</div>
