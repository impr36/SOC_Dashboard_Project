"""
SOC Simulator — launcher.py
============================
Single entry point. Does in order:
  1. Elevate to admin if not already
  2. Run integrity check (tamper detection)
  3. Ask about Python install preference
  4. Install all dependencies (with live
     progress shown in the splash window)
  5. Show login window
  6. Start FastAPI server
  7. Open dashboard in browser
  8. Terminal output floats over dashboard
     via WebSocket console panel
"""

import os
import sys
import time
import json
import hmac
import ctypes
import hashlib
import subprocess
import threading
import urllib.request
import tkinter as tk
from tkinter import messagebox, ttk
from pathlib import Path


# =========================================
# RESOURCE PATH (PyInstaller compatible)
# =========================================

def resource_path(relative_path: str) -> str:
    try:
        base = sys._MEIPASS
    except AttributeError:
        base = os.path.abspath(".")
    return os.path.join(base, relative_path)


PROJECT_ROOT = Path(resource_path("."))


# =========================================
# STEP 1 — ADMIN ELEVATION
# Must happen before anything else.
# =========================================

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


if not is_admin():
    # Re-launch self with UAC prompt
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas",
        sys.executable,
        f'"{os.path.abspath(__file__)}"',
        None, 1
    )
    sys.exit(0)


# =========================================
# STEP 2 — INTEGRITY CHECK
# Verifies no source file has been modified
# since the manifest was sealed.
# =========================================

MANIFEST_PATH = PROJECT_ROOT / "security" / "manifest.json"
SEAL_KEY_PATH = PROJECT_ROOT / "security" / ".seal_key"

# File extensions to protect
PROTECTED_EXTENSIONS = {
    ".py", ".js", ".html", ".css", ".json"
}

# Directories to skip (generated at runtime)
SKIP_DIRS = {
    "__pycache__", ".venv", "venv",
    "database", "forensics_exports",
    "security", ".git"
}


def _hmac_sign(data: bytes, key: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def integrity_check() -> tuple[bool, list[str]]:
    """
    Returns (passed, list_of_violations).
    If manifest doesn't exist yet, returns (True, [])
    so first run always succeeds (seal is built on
    first legitimate launch).
    """
    if not MANIFEST_PATH.exists():
        return True, []

    try:
        seal_key = SEAL_KEY_PATH.read_bytes()
        manifest = json.loads(MANIFEST_PATH.read_text())
    except Exception:
        return False, ["[TAMPER] Cannot read security manifest"]

    violations = []

    for rel_path, expected_hash in manifest.items():
        full_path = PROJECT_ROOT / rel_path
        if not full_path.exists():
            violations.append(f"[MISSING] {rel_path}")
            continue
        actual = hashlib.sha256(
            full_path.read_bytes()
        ).hexdigest()
        signed = _hmac_sign(actual.encode(), seal_key)
        if signed != expected_hash:
            violations.append(f"[MODIFIED] {rel_path}")

    return len(violations) == 0, violations


def build_manifest():
    """
    Seal the project: hash every protected file,
    HMAC-sign each hash, write manifest.json.
    Called only when no manifest exists (first run).
    """
    security_dir = PROJECT_ROOT / "security"
    security_dir.mkdir(exist_ok=True)

    # Generate seal key if missing
    if not SEAL_KEY_PATH.exists():
        seal_key = os.urandom(32)
        SEAL_KEY_PATH.write_bytes(seal_key)
        # Hide the key file on Windows
        try:
            subprocess.run(
                ["attrib", "+H", "+S", str(SEAL_KEY_PATH)],
                capture_output=True
            )
        except Exception:
            pass
    else:
        seal_key = SEAL_KEY_PATH.read_bytes()

    manifest = {}

    for path in PROJECT_ROOT.rglob("*"):
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in PROTECTED_EXTENSIONS:
            continue

        rel = str(path.relative_to(PROJECT_ROOT))
        file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        signed = _hmac_sign(file_hash.encode(), seal_key)
        manifest[rel] = signed

    MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2)
    )

    # Lock permissions on security folder
    _lock_security_folder(security_dir)

    print(
        f"[SEAL] Manifest built: "
        f"{len(manifest)} files protected"
    )


def _lock_security_folder(folder: Path):
    """
    Remove Everyone write permissions from the
    security folder using icacls (Windows).
    """
    try:
        subprocess.run([
            "icacls", str(folder),
            "/inheritance:r",
            "/grant:r",
            f"{os.environ.get('USERNAME', 'Administrator')}:(OI)(CI)F",
            "/deny",
            "Everyone:(W)"
        ], capture_output=True)
    except Exception:
        pass


# =========================================
# STEP 3 — PYTHON INSTALL DIALOG
# =========================================

PYTHON_MIN = (3, 10)
REQUIREMENTS = PROJECT_ROOT / "requirements.txt"


def python_is_ok() -> bool:
    return sys.version_info >= PYTHON_MIN


def _ask_python_preference(root_win) -> str:
    """
    Returns: 'existing' | 'fresh' | 'cancel'
    """
    result = {"choice": "cancel"}
    dialog = tk.Toplevel(root_win)
    dialog.title("Python Setup")
    dialog.geometry("520x300")
    dialog.configure(bg="#06131f")
    dialog.grab_set()
    dialog.resizable(False, False)

    tk.Label(
        dialog,
        text="Python Installation",
        font=("Segoe UI", 16, "bold"),
        bg="#06131f", fg="white"
    ).pack(pady=(30, 5))

    ver = (
        f"Python {sys.version_info.major}."
        f"{sys.version_info.minor} detected"
        if python_is_ok()
        else "Python not found or too old (need 3.10+)"
    )

    tk.Label(
        dialog, text=ver,
        font=("Segoe UI", 11),
        bg="#06131f",
        fg="#00ff88" if python_is_ok() else "#ff4444"
    ).pack(pady=5)

    tk.Label(
        dialog,
        text="How would you like to proceed?",
        font=("Segoe UI", 11),
        bg="#06131f", fg="#aaaaaa"
    ).pack(pady=10)

    btn_frame = tk.Frame(dialog, bg="#06131f")
    btn_frame.pack(pady=10)

    def choose(val):
        result["choice"] = val
        dialog.destroy()

    if python_is_ok():
        tk.Button(
            btn_frame,
            text="Use existing Python\n(install packages only)",
            font=("Segoe UI", 11, "bold"),
            bg="#2563eb", fg="white",
            width=24, height=2,
            cursor="hand2", bd=0,
            command=lambda: choose("existing")
        ).pack(side="left", padx=10)

    tk.Button(
        btn_frame,
        text="Install fresh Python\n(fully self-contained)",
        font=("Segoe UI", 11, "bold"),
        bg="#065f46", fg="white",
        width=24, height=2,
        cursor="hand2", bd=0,
        command=lambda: choose("fresh")
    ).pack(side="left", padx=10)

    tk.Button(
        btn_frame,
        text="Cancel",
        font=("Segoe UI", 11),
        bg="#4b1c1c", fg="white",
        width=10, height=2,
        cursor="hand2", bd=0,
        command=lambda: choose("cancel")
    ).pack(side="left", padx=10)

    root_win.wait_window(dialog)
    return result["choice"]


# =========================================
# STEP 4 — DEPENDENCY INSTALLER
# =========================================

SYSMON_URL = (
    "https://download.sysinternals.com"
    "/files/Sysmon.zip"
)

SYSMON_CONFIG_URL = (
    "https://raw.githubusercontent.com"
    "/SwiftOnSecurity/sysmon-config"
    "/master/sysmonconfig-export.xml"
)

PYTHON_INSTALLER_URL = (
    "https://www.python.org/ftp/python"
    "/3.13.0/python-3.13.0-amd64.exe"
)


def _log(console_widget, msg: str):
    """Append a line to the install console."""
    if console_widget is None:
        print(msg)
        return
    console_widget.config(state="normal")
    console_widget.insert("end", msg + "\n")
    console_widget.see("end")
    console_widget.config(state="disabled")
    console_widget.update()


def _run_cmd(args: list, console_widget=None) -> int:
    """Run a subprocess and stream output to console."""
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace"
    )
    for line in proc.stdout:
        _log(console_widget, line.rstrip())
    proc.wait()
    return proc.returncode


def install_python_fresh(console_widget=None):
    _log(console_widget, "[INSTALL] Downloading Python 3.13...")
    installer = PROJECT_ROOT / "python_installer.exe"
    urllib.request.urlretrieve(
        PYTHON_INSTALLER_URL,
        str(installer)
    )
    _log(console_widget, "[INSTALL] Running Python installer...")
    _run_cmd([
        str(installer),
        "/quiet",
        "InstallAllUsers=1",
        "PrependPath=1",
        "Include_test=0"
    ], console_widget)
    installer.unlink(missing_ok=True)
    _log(console_widget, "[INSTALL] Python installed.")


def install_packages(console_widget=None):
    _log(console_widget, "[PACKAGES] Installing requirements...")
    _run_cmd([
        sys.executable, "-m", "pip",
        "install", "-r", str(REQUIREMENTS),
        "--quiet", "--disable-pip-version-check"
    ], console_widget)
    _log(console_widget, "[PACKAGES] All packages installed.")


def install_sysmon(console_widget=None):
    """
    Download and install Sysmon + SwiftOnSecurity config.
    Skips if Sysmon service already exists.
    """
    import zipfile

    # Check if already installed
    result = subprocess.run(
        ["sc", "query", "sysmon64"],
        capture_output=True, text=True
    )
    if "RUNNING" in result.stdout:
        _log(console_widget, "[SYSMON] Already installed and running.")
        return

    _log(console_widget, "[SYSMON] Downloading Sysmon...")

    sysmon_zip = PROJECT_ROOT / "sysmon.zip"
    sysmon_dir = PROJECT_ROOT / "sysmon_temp"
    sysmon_dir.mkdir(exist_ok=True)

    urllib.request.urlretrieve(SYSMON_URL, str(sysmon_zip))

    with zipfile.ZipFile(sysmon_zip, "r") as z:
        z.extractall(sysmon_dir)

    sysmon_zip.unlink(missing_ok=True)

    # Download config
    _log(console_widget, "[SYSMON] Downloading config...")
    config_path = sysmon_dir / "sysmonconfig.xml"
    urllib.request.urlretrieve(SYSMON_CONFIG_URL, str(config_path))

    # Install
    sysmon_exe = sysmon_dir / "Sysmon64.exe"
    _log(console_widget, "[SYSMON] Installing Sysmon64...")
    _run_cmd([
        str(sysmon_exe),
        "-accepteula",
        "-i", str(config_path)
    ], console_widget)

    _log(console_widget, "[SYSMON] Sysmon installed successfully.")

    # Cleanup
    import shutil
    shutil.rmtree(sysmon_dir, ignore_errors=True)


def run_full_install(
    python_choice: str,
    console_widget=None,
    progress_var=None,
    status_label=None
):
    """Run the complete install sequence."""

    steps = []

    def update_status(msg, pct):
        _log(console_widget, msg)
        if status_label:
            status_label.config(text=msg)
        if progress_var is not None:
            progress_var.set(pct)
        if console_widget:
            console_widget.update()

    # STEP A — Python
    if python_choice == "fresh":
        update_status("Installing Python 3.13...", 10)
        install_python_fresh(console_widget)

    # STEP B — pip packages
    update_status("Installing Python packages...", 30)
    install_packages(console_widget)

    # STEP C — Sysmon
    update_status("Installing Sysmon...", 60)
    try:
        install_sysmon(console_widget)
    except Exception as e:
        _log(console_widget,
             f"[SYSMON WARNING] {e} — continuing anyway")

    # STEP D — Seal manifest (first run)
    update_status("Sealing project integrity...", 80)
    if not MANIFEST_PATH.exists():
        build_manifest()
        _log(console_widget, "[SEAL] Project sealed successfully.")

    update_status("All dependencies ready.", 100)


# =========================================
# SERVER CONFIG
# =========================================

HOST = "127.0.0.1"
PORT = 8000

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

server_process = None


def start_server():
    global server_process
    try:
        server_process = subprocess.Popen(
            [
                sys.executable, "-m", "uvicorn",
                "app.main:app",
                "--host", HOST,
                "--port", str(PORT)
            ],
            cwd=str(PROJECT_ROOT)
        )
    except Exception as e:
        print(f"[SERVER ERROR] {e}")


def wait_for_server(timeout: int = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(
                f"http://{HOST}:{PORT}/",
                timeout=1
            )
            return True
        except Exception:
            time.sleep(0.5)
    return False


# =========================================
# MAIN WINDOW BUILDER
# =========================================

class SOCLauncher:

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SOC Simulator")
        self.root.geometry("1000x640")
        self.root.configure(bg="#06131f")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._build_left_panel()
        self._build_right_panel()

        # Phase: 'login' | 'installing' | 'launching'
        self._phase = "pre_check"
        self._run_startup()

    # ---- PANELS ----

    def _build_left_panel(self):
        lf = tk.Frame(self.root, bg="#021526", width=460)
        lf.pack(side="left", fill="both")
        lf.pack_propagate(False)

        tk.Label(
            lf, text="SOC\nSimulator",
            font=("Segoe UI", 36, "bold"),
            bg="#021526", fg="white", justify="center"
        ).place(relx=0.5, rely=0.20, anchor="center")

        tk.Label(
            lf, text="Host + Network IDS Platform",
            font=("Segoe UI", 14),
            bg="#021526", fg="#7aa2d6"
        ).place(relx=0.5, rely=0.33, anchor="center")

        tk.Label(
            lf,
            text=(
                "✓  Real-Time Threat Detection\n\n"
                "✓  HIDS + NIDS Monitoring\n\n"
                "✓  MITRE ATT&CK Mapping\n\n"
                "✓  Threat Hunting Engine\n\n"
                "✓  Digital Forensics Support"
            ),
            font=("Segoe UI", 13),
            bg="#021526", fg="white", justify="left"
        ).place(relx=0.5, rely=0.64, anchor="center")

    def _build_right_panel(self):
        self.rf = tk.Frame(
            self.root, bg="#0b2239", width=540
        )
        self.rf.pack(side="right", fill="both", expand=True)
        self.rf.pack_propagate(False)
        self._show_login_ui()

    # ---- LOGIN UI ----

    def _show_login_ui(self):
        self._clear_right()

        tk.Label(
            self.rf, text="Admin Login",
            font=("Segoe UI", 26, "bold"),
            bg="#0b2239", fg="white"
        ).place(relx=0.5, rely=0.16, anchor="center")

        # Username
        tk.Label(
            self.rf, text="Username",
            font=("Segoe UI", 12),
            bg="#0b2239", fg="#aaaaaa"
        ).place(relx=0.18, rely=0.30)

        self.username_entry = tk.Entry(
            self.rf, width=28,
            font=("Segoe UI", 14),
            relief="flat", bg="#102b46",
            fg="white", insertbackground="white"
        )
        self.username_entry.place(
            relx=0.18, rely=0.36, height=40
        )

        # Password
        tk.Label(
            self.rf, text="Password",
            font=("Segoe UI", 12),
            bg="#0b2239", fg="#aaaaaa"
        ).place(relx=0.18, rely=0.50)

        self.password_entry = tk.Entry(
            self.rf, width=28, show="*",
            font=("Segoe UI", 14),
            relief="flat", bg="#102b46",
            fg="white", insertbackground="white"
        )
        self.password_entry.place(
            relx=0.18, rely=0.56, height=40
        )

        # Bind Enter key
        self.password_entry.bind(
            "<Return>", lambda e: self._login()
        )
        self.username_entry.bind(
            "<Return>", lambda e: self._login()
        )

        tk.Button(
            self.rf, text="LOGIN",
            font=("Segoe UI", 13, "bold"),
            bg="#2563eb", fg="white",
            activebackground="#1d4ed8",
            width=22, height=2,
            bd=0, cursor="hand2",
            command=self._login
        ).place(relx=0.18, rely=0.70)

        self.status_label = tk.Label(
            self.rf, text="",
            font=("Segoe UI", 10),
            bg="#0b2239", fg="#00ff88"
        )
        self.status_label.place(
            relx=0.18, rely=0.88
        )

    # ---- INSTALL UI ----

    def _show_install_ui(self):
        self._clear_right()

        tk.Label(
            self.rf, text="Setting Up SOC Simulator",
            font=("Segoe UI", 18, "bold"),
            bg="#0b2239", fg="white"
        ).place(relx=0.5, rely=0.07, anchor="center")

        self.install_status = tk.Label(
            self.rf, text="Preparing...",
            font=("Segoe UI", 11),
            bg="#0b2239", fg="#00ff88"
        )
        self.install_status.place(
            relx=0.5, rely=0.15, anchor="center"
        )

        self.progress_var = tk.DoubleVar(value=0)
        ttk.Style().configure(
            "SOC.Horizontal.TProgressbar",
            troughcolor="#102b46",
            background="#2563eb",
            thickness=18
        )
        self.progress = ttk.Progressbar(
            self.rf,
            variable=self.progress_var,
            style="SOC.Horizontal.TProgressbar",
            length=420, maximum=100
        )
        self.progress.place(
            relx=0.5, rely=0.23, anchor="center"
        )

        # Live console output
        console_frame = tk.Frame(
            self.rf, bg="#060f1a", bd=0
        )
        console_frame.place(
            relx=0.07, rely=0.30,
            relwidth=0.86, relheight=0.62
        )

        self.console = tk.Text(
            console_frame,
            font=("Consolas", 9),
            bg="#060f1a", fg="#00ff88",
            state="disabled",
            wrap="word",
            relief="flat",
            bd=0
        )
        scrollbar = tk.Scrollbar(
            console_frame,
            command=self.console.yview
        )
        self.console.configure(
            yscrollcommand=scrollbar.set
        )
        scrollbar.pack(side="right", fill="y")
        self.console.pack(
            side="left", fill="both", expand=True
        )

        # Elapsed timer
        self._install_start = time.time()
        self.timer_label = tk.Label(
            self.rf, text="⏱ 0s",
            font=("Segoe UI", 10),
            bg="#0b2239", fg="#7aa2d6"
        )
        self.timer_label.place(
            relx=0.5, rely=0.95, anchor="center"
        )
        self._tick_timer()

    def _tick_timer(self):
        elapsed = int(time.time() - self._install_start)
        self.timer_label.config(
            text=f"⏱ {elapsed}s elapsed"
        )
        self.root.after(1000, self._tick_timer)

    # ---- STARTUP FLOW ----

    def _run_startup(self):
        """
        Called once at launch. Decides whether to go
        straight to login or run the install phase.
        """
        # Integrity check
        passed, violations = integrity_check()

        if not passed:
            detail = "\n".join(violations[:10])
            messagebox.showerror(
                "Tamper Detected",
                f"Project integrity check FAILED.\n\n"
                f"{detail}\n\n"
                f"The application cannot start.",
                parent=self.root
            )
            self.root.destroy()
            return

        # Decide if install is needed
        needs_install = not python_is_ok() or (
            not (PROJECT_ROOT / "venv").exists()
            and not _packages_installed()
        )

        if needs_install:
            self._show_install_ui()
            choice = _ask_python_preference(self.root)
            if choice == "cancel":
                self.root.destroy()
                return
            threading.Thread(
                target=self._do_install,
                args=(choice,),
                daemon=True
            ).start()
        else:
            self._show_login_ui()

    def _do_install(self, python_choice: str):
        run_full_install(
            python_choice=python_choice,
            console_widget=self.console,
            progress_var=self.progress_var,
            status_label=self.install_status
        )
        # After install — seal and show login
        self.root.after(1500, self._show_login_ui)

    # ---- LOGIN ----

    def _login(self):
        u = self.username_entry.get().strip()
        p = self.password_entry.get().strip()

        if u == ADMIN_USERNAME and p == ADMIN_PASSWORD:
            self.status_label.config(
                text="Authenticated. Starting server..."
            )
            self.root.after(
                100, self._launch_dashboard
            )
        else:
            messagebox.showerror(
                "Authentication Failed",
                "Invalid username or password.",
                parent=self.root
            )

    def _launch_dashboard(self):
        self.status_label.config(
            text="Starting SOC backend..."
        )

        threading.Thread(
            target=start_server, daemon=True
        ).start()

        self.status_label.config(
            text="Waiting for server..."
        )

        ok = wait_for_server(timeout=30)

        if not ok:
            messagebox.showerror(
                "Server Error",
                "SOC backend did not start in time.",
                parent=self.root
            )
            return

        self.status_label.config(
            text="Launching dashboard..."
        )

        os.system(
            f"start http://{HOST}:{PORT}/dashboard"
        )

        self.root.destroy()

    # ---- UTILITIES ----

    def _clear_right(self):
        for widget in self.rf.winfo_children():
            widget.destroy()

    def _on_close(self):
        global server_process
        try:
            if server_process:
                server_process.terminate()
        except Exception:
            pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def _packages_installed() -> bool:
    """Quick check: can we import fastapi and uvicorn?"""
    try:
        import fastapi  # noqa
        import uvicorn  # noqa
        return True
    except ImportError:
        return False


# =========================================
# ENTRY POINT
# =========================================

if __name__ == "__main__":
    SOCLauncher().run()
