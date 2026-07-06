"""
build_exe.py
============
Run this on YOUR development machine (not the target)
to produce  dist/SOC_Dashboard.exe

USAGE:
    pip install pyinstaller
    python build_exe.py

The output will be:
    dist/
    └── SOC_Dashboard/
        ├── SOC_Dashboard.exe   ← send this to the target
        └── _internal/          ← bundled dependencies

WHAT IT BUNDLES:
  • launcher.py  (entry point)
  • app/         (all FastAPI code, templates, static)
  • requirements already installed in current venv
  • integrity_guard logic (embedded in launcher)

THE EXE WILL:
  1. Prompt UAC for admin rights
  2. Check Python on target machine (ask user)
  3. Install pip packages if needed
  4. Install Sysmon if missing
  5. Seal the project manifest
  6. Show login window
  7. Start uvicorn server
  8. Open browser to dashboard
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent


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


def collect_data_files() -> list[tuple[str, str]]:
    """
    Build the --add-data list.
    Format: (source_glob, dest_in_bundle)
    """
    datas = []

    # App source tree
    app_dir = PROJECT_ROOT / "app"
    for sub in [
        "templates", "static",
        "rules", "engines", "collectors",
        "services", "api", "database",
        "core", "alerts"
    ]:
        src = app_dir / sub
        if src.exists():
            datas.append((str(src), f"app/{sub}"))

    # requirements.txt (needed by installer logic)
    req = PROJECT_ROOT / "requirements.txt"
    if req.exists():
        datas.append((str(req), "."))

    return datas


def build():
    check_pyinstaller()
    clean_old_build()

    datas = collect_data_files()

    # Build --add-data flags
    # PyInstaller separator is ; on Windows, : on Unix
    sep = ";" if sys.platform == "win32" else ":"
    data_flags = []
    for src, dst in datas:
        data_flags += ["--add-data", f"{src}{sep}{dst}"]

    cmd = [
        sys.executable, "-m", "PyInstaller",

        # Single-file EXE
        "--onedir",

        # Hide the console window
        "--noconsole",

        # Windows: embed UAC manifest (requireAdministrator)
        "--uac-admin",

        # Icon (use your own .ico if you have one)
        # "--icon", "app/static/images/shield.ico",

        # EXE name
        "--name", "SOC_Dashboard",

        # Output folder
        "--distpath", str(PROJECT_ROOT / "dist"),
        "--workpath", str(PROJECT_ROOT / "build"),
        "--specpath", str(PROJECT_ROOT),

        # Hidden imports that PyInstaller misses
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
        "--hidden-import", "wmi",
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "--hidden-import", "tkinter.messagebox",

        # Collect entire packages (templates, static)
        "--collect-all", "jinja2",
        "--collect-all", "starlette",
        "--collect-all", "fastapi",

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
        print(f"\n{'='*50}")
        print(f"  ✅ BUILD SUCCESSFUL")
        print(f"  EXE : {exe_path}")
        print(f"  SIZE: {size_mb:.1f} MB")
        print(f"{'='*50}\n")
        print("  Distribute the entire dist/SOC_Dashboard/")
        print("  folder — the .exe needs _internal/ next to it.")
    else:
        print(f"\n[BUILD] ❌ PyInstaller failed "
              f"(exit code {result.returncode})")
        sys.exit(1)


if __name__ == "__main__":
    build()
