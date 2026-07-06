"""
build_exe.py
============
Run this on YOUR development machine (not the target)
to produce:
  dist/SOC_Dashboard/SOC_Dashboard.exe     ← portable folder
  dist/SOC_Dashboard_Setup.exe             ← single-file installer (needs NSIS)

USAGE:
    pip install pyinstaller
    python build_exe.py

For the Setup.exe (recommended):
    1. Download NSIS free: https://nsis.sourceforge.io/Download
    2. Install it (default path)
    3. Run: python build_exe.py
    → produces dist/SOC_Dashboard_Setup.exe  (send this to anyone)

THE EXE WILL:
  1. Prompt UAC for admin rights automatically (no right-click needed)
  2. Show login window directly (no CMD, no terminal, no venv)
  3. Start uvicorn server silently in background
  4. Open browser to dashboard
  5. On logout → browser closes → login window reappears for next user

THE INSTALLER (Setup.exe) WILL:
  1. Install to C:\\Program Files\\SOC Dashboard
  2. Create Desktop shortcut  ← double-click to launch
  3. Create Start Menu entry
  4. Add to Programs & Features (can uninstall cleanly)
  5. Show success message with default login credentials
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent


# =========================================
# STEP 1 — CHECK PYINSTALLER
# =========================================

def check_pyinstaller():
    try:
        import PyInstaller  # noqa
        print("[BUILD] PyInstaller found.")
    except ImportError:
        print("[BUILD] Installing PyInstaller...")
        subprocess.run(
            [sys.executable, "-m", "pip",
             "install", "pyinstaller", "--quiet"],
            check=True
        )


# =========================================
# STEP 2 — CLEAN OLD BUILD
# =========================================

def clean_old_build():
    for folder in ["build", "dist"]:
        p = PROJECT_ROOT / folder
        if p.exists():
            shutil.rmtree(p)
            print(f"[BUILD] Cleaned: {folder}/")

    spec = PROJECT_ROOT / "SOC_Dashboard.spec"
    if spec.exists():
        spec.unlink()
        print("[BUILD] Cleaned: SOC_Dashboard.spec")


# =========================================
# STEP 3 — COLLECT DATA FILES
# =========================================

def collect_data_files() -> list[tuple[str, str]]:
    """
    Build the --add-data list.
    Format: (source_path, dest_in_bundle)
    """
    datas = []

    # App source tree — exclude database/ (runtime generated)
    app_dir = PROJECT_ROOT / "app"
    for sub in [
        "templates", "static",
        "rules", "engines", "collectors",
        "services", "api",
        "core", "alerts"
        # database/ excluded: session DB is created at runtime
        # security/ excluded: seal key must not be bundled
    ]:
        src_path = app_dir / sub
        if src_path.exists():
            datas.append((str(src_path), f"app/{sub}"))

    # requirements.txt (needed by installer logic)
    req = PROJECT_ROOT / "requirements.txt"
    if req.exists():
        datas.append((str(req), "."))

    # IMPORTANT: chart.umd.min.js must be present at
    # app/static/js/chart.umd.min.js before building.
    # The VM has no internet so Chart.js must be local.
    # Download from: https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js

    return datas


# =========================================
# STEP 4 — BUILD EXE WITH PYINSTALLER
# =========================================

def build_exe():
    check_pyinstaller()
    clean_old_build()

    datas = collect_data_files()

    # PyInstaller separator is ; on Windows, : on Unix
    sep = ";" if sys.platform == "win32" else ":"
    data_flags = []
    for src, dst in datas:
        data_flags += ["--add-data", f"{src}{sep}{dst}"]

    # Icon path — use shield.ico if available
    icon_path  = PROJECT_ROOT / "app" / "static" / "icons-W" / "shield.ico"
    icon_flags = ["--icon", str(icon_path)] if icon_path.exists() else []

    cmd = [
        sys.executable, "-m", "PyInstaller",

        "--onedir",      # folder output (faster startup than --onefile)
        "--noconsole",   # no CMD window — login window appears directly
        "--uac-admin",   # auto-request admin rights on launch (no right-click needed)

        "--name", "SOC_Dashboard",

        "--distpath", str(PROJECT_ROOT / "dist"),
        "--workpath", str(PROJECT_ROOT / "build"),
        "--specpath", str(PROJECT_ROOT),

        # ── Hidden imports PyInstaller misses ──────────────
        "--hidden-import", "uvicorn.logging",
        "--hidden-import", "uvicorn.loops",
        "--hidden-import", "uvicorn.loops.auto",
        "--hidden-import", "uvicorn.protocols",
        "--hidden-import", "uvicorn.protocols.http",
        "--hidden-import", "uvicorn.protocols.http.auto",
        "--hidden-import", "uvicorn.protocols.websockets",
        "--hidden-import", "uvicorn.protocols.websockets.auto",
        "--hidden-import", "uvicorn.lifespan",
        "--hidden-import", "uvicorn.lifespan.on",
        "--hidden-import", "fastapi",
        "--hidden-import", "starlette",
        "--hidden-import", "jinja2",
        "--hidden-import", "aiofiles",
        "--hidden-import", "pydantic",
        "--hidden-import", "pandas",
        "--hidden-import", "sqlite3",
        "--hidden-import", "psutil",
        "--hidden-import", "win32api",
        "--hidden-import", "win32con",
        "--hidden-import", "win32evtlog",
        "--hidden-import", "wmi",
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "--hidden-import", "tkinter.messagebox",
        "--hidden-import", "app.main",
        "--hidden-import", "app.api.dashboard_api",
        "--hidden-import", "app.api.auth_api",
        "--hidden-import", "app.api.rules_api",
        "--hidden-import", "app.api.settings_api",
        "--hidden-import", "app.api.investigation_api",
        "--hidden-import", "app.services.soc_service",
        "--hidden-import", "app.services.investigation_service",
        "--hidden-import", "app.collectors.collector_manager",
        "--hidden-import", "app.collectors.filesystem_collector",
        "--hidden-import", "app.collectors.network_collector",
        "--hidden-import", "app.database.database",
        "--hidden-import", "app.websocket_manager",

        # ── Collect entire packages ─────────────────────────
        "--collect-all", "jinja2",
        "--collect-all", "starlette",
        "--collect-all", "fastapi",

        *icon_flags,
        *data_flags,

        # Entry point
        str(PROJECT_ROOT / "launcher.py"),
    ]

    print("\n[BUILD] Running PyInstaller...\n")
    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))

    if result.returncode == 0:
        exe_path = (
            PROJECT_ROOT / "dist" /
            "SOC_Dashboard" / "SOC_Dashboard.exe"
        )
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n{'='*55}")
        print(f"  ✅ EXE BUILD SUCCESSFUL")
        print(f"  EXE  : {exe_path}")
        print(f"  SIZE : {size_mb:.1f} MB")
        print(f"{'='*55}")
        print("  Distribute the entire dist/SOC_Dashboard/ folder.")
        print("  The .exe needs _internal/ next to it to run.\n")
    else:
        print(f"\n[BUILD] ❌ PyInstaller failed "
              f"(exit code {result.returncode})")
        sys.exit(1)


# =========================================
# STEP 5 — CREATE NSIS INSTALLER SCRIPT
# =========================================

def create_nsis_script() -> Path:
    """Generate the NSIS script that wraps the PyInstaller output
    into a single Setup.exe anyone can double-click to install."""

    dist_dir  = PROJECT_ROOT / "dist" / "SOC_Dashboard"
    nsi_path  = PROJECT_ROOT / "SOC_Dashboard_Setup.nsi"
    icon_path = PROJECT_ROOT / "app" / "static" / "icons-W" / "shield.ico"
    icon_line = f'Icon "{icon_path}"' if icon_path.exists() else ""

    nsis_script = f"""; SOC Dashboard — NSIS Installer Script
; Auto-generated by build_exe.py
; Compile with: makensis SOC_Dashboard_Setup.nsi

Unicode True

!define APPNAME    "SOC Dashboard"
!define APPVERSION "1.0"
!define PUBLISHER  "Pratyush Raj — CFEES DRDO"
!define INSTALLDIR "$PROGRAMFILES64\\SOC Dashboard"
!define REGKEY     "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SOCDashboard"

Name "${{APPNAME}} ${{APPVERSION}}"
OutFile "dist\\SOC_Dashboard_Setup.exe"
InstallDir "${{INSTALLDIR}}"
InstallDirRegKey HKLM "${{REGKEY}}" "InstallLocation"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
{icon_line}

Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

; ── Install ───────────────────────────────────────────────
Section "SOC Dashboard" SecMain

    SetOutPath "$INSTDIR"

    ; Copy the entire PyInstaller output folder
    File /r "{dist_dir}\\*.*"

    ; Desktop shortcut — double-click opens login window directly
    CreateShortcut "$DESKTOP\\SOC Dashboard.lnk" \\
        "$INSTDIR\\SOC_Dashboard.exe" "" \\
        "$INSTDIR\\SOC_Dashboard.exe" 0 \\
        SW_SHOWNORMAL "" "SOC Security Dashboard — CFEES DRDO"

    ; Start Menu shortcuts
    CreateDirectory "$SMPROGRAMS\\SOC Dashboard"
    CreateShortcut "$SMPROGRAMS\\SOC Dashboard\\SOC Dashboard.lnk" \\
        "$INSTDIR\\SOC_Dashboard.exe" "" \\
        "$INSTDIR\\SOC_Dashboard.exe" 0 \\
        SW_SHOWNORMAL "" "SOC Security Dashboard"
    CreateShortcut "$SMPROGRAMS\\SOC Dashboard\\Uninstall.lnk" \\
        "$INSTDIR\\Uninstall.exe"

    ; Write uninstaller
    WriteUninstaller "$INSTDIR\\Uninstall.exe"

    ; Registry: Programs & Features entry
    WriteRegStr   HKLM "${{REGKEY}}" "DisplayName"     "${{APPNAME}}"
    WriteRegStr   HKLM "${{REGKEY}}" "UninstallString" "$INSTDIR\\Uninstall.exe"
    WriteRegStr   HKLM "${{REGKEY}}" "InstallLocation" "$INSTDIR"
    WriteRegStr   HKLM "${{REGKEY}}" "Publisher"       "${{PUBLISHER}}"
    WriteRegStr   HKLM "${{REGKEY}}" "DisplayVersion"  "${{APPVERSION}}"
    WriteRegDWORD HKLM "${{REGKEY}}" "NoModify"        1
    WriteRegDWORD HKLM "${{REGKEY}}" "NoRepair"        1

    MessageBox MB_ICONINFORMATION \\
        "SOC Dashboard installed successfully!$\\r$\\n$\\r$\\nA shortcut has been created on your Desktop.$\\r$\\nDouble-click it to launch the login window.$\\r$\\n$\\r$\\nDefault login$\\r$\\n  Username : admin$\\r$\\n  Password : admin123" \\
        /SD IDOK

SectionEnd

; ── Uninstall ─────────────────────────────────────────────
Section "Uninstall"

    Delete "$DESKTOP\\SOC Dashboard.lnk"
    Delete "$SMPROGRAMS\\SOC Dashboard\\SOC Dashboard.lnk"
    Delete "$SMPROGRAMS\\SOC Dashboard\\Uninstall.lnk"
    RMDir  "$SMPROGRAMS\\SOC Dashboard"
    RMDir  /r "$INSTDIR"
    DeleteRegKey HKLM "${{REGKEY}}"

SectionEnd
"""

    nsi_path.write_text(nsis_script, encoding="utf-8")
    print(f"[BUILD] NSIS script written: {nsi_path.name}")
    return nsi_path


# =========================================
# STEP 6 — COMPILE WITH NSIS (if installed)
# =========================================

def build_installer(nsi_path: Path):
    """Try to compile the NSIS script into a single Setup.exe"""

    nsis_candidates = [
        r"C:\Program Files (x86)\NSIS\makensis.exe",
        r"C:\Program Files\NSIS\makensis.exe",
        "makensis",
    ]

    makensis = None
    for candidate in nsis_candidates:
        if Path(candidate).exists():
            makensis = candidate
            break
        if shutil.which(candidate):
            makensis = candidate
            break

    if not makensis:
        print("\n[BUILD] ⚠️  NSIS not installed — Setup.exe skipped.")
        print("        To build the single-file installer later:")
        print("        1. Download NSIS: https://nsis.sourceforge.io/Download")
        print("        2. Install it (default path is fine)")
        print("        3. Re-run: python build_exe.py")
        print("\n        Your portable build is already ready at:")
        print("        dist/SOC_Dashboard/SOC_Dashboard.exe")
        return

    print(f"\n[BUILD] Compiling Setup.exe with NSIS...")
    result = subprocess.run(
        [makensis, str(nsi_path)],
        cwd=str(PROJECT_ROOT)
    )

    if result.returncode == 0:
        setup_path = PROJECT_ROOT / "dist" / "SOC_Dashboard_Setup.exe"
        size_mb    = setup_path.stat().st_size / (1024 * 1024)
        print(f"\n{'='*55}")
        print(f"  ✅ INSTALLER BUILD SUCCESSFUL")
        print(f"  FILE : {setup_path}")
        print(f"  SIZE : {size_mb:.1f} MB")
        print(f"{'='*55}")
        print("  Send SOC_Dashboard_Setup.exe to any Windows machine.")
        print("  Run as Administrator → Install → Desktop shortcut ready.")
        print("  Double-click shortcut → login window opens. No terminal.\n")
    else:
        print("[BUILD] ❌ NSIS compilation failed — check output above.")


# =========================================
# MAIN
# =========================================

if __name__ == "__main__":
    print("=" * 55)
    print("  SOC Dashboard — Build System")
    print("  Pratyush Raj | CFEES DRDO Internship Project")
    print("=" * 55)

    # 1. Build portable EXE folder
    build_exe()

    # 2. Write NSIS installer script
    nsi = create_nsis_script()

    # 3. Compile into single Setup.exe if NSIS is installed
    build_installer(nsi)

    print("\n[BUILD] Summary:")
    print("  Portable EXE → dist/SOC_Dashboard/SOC_Dashboard.exe")
    print("  NSIS Script  → SOC_Dashboard_Setup.nsi (compile manually if needed)")
    print("  Setup EXE    → dist/SOC_Dashboard_Setup.exe (if NSIS was installed)")