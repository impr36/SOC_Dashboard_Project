import os
import sys
import time
import threading
import subprocess
import webbrowser
import tkinter as tk

from tkinter import messagebox

import ctypes


# =========================================
# AUTO ADMIN ELEVATION
# =========================================

def is_admin():

    try:
        return ctypes.windll.shell32.IsUserAnAdmin()

    except:
        return False


if not is_admin():

    ctypes.windll.shell32.ShellExecuteW(

        None,

        "runas",

        sys.executable,

        os.path.abspath(__file__),

        None,

        1
    )

    sys.exit()


# =========================================
# DEFAULT ADMIN CREDENTIALS
# =========================================

ADMIN_USERNAME = "admin"

ADMIN_PASSWORD = "admin123"


# =========================================
# SERVER CONFIG
# =========================================

HOST = "127.0.0.1"

PORT = 8000


# =========================================
# START FASTAPI SERVER
# =========================================

server_process = None



def start_server():

    global server_process

    try:

        startupinfo = subprocess.STARTUPINFO()

        startupinfo.dwFlags |= \
        subprocess.STARTF_USESHOWWINDOW

        server_process = subprocess.Popen(

            [

                sys.executable,

                "-m",

                "uvicorn",

                "app.main:app",

                "--host",

                HOST,

                "--port",

                str(PORT),

                "--reload"

            ],

            startupinfo=startupinfo,

            # creationflags=subprocess.CREATE_NO_WINDOW
        )

    except Exception as e:

        print(
            f"[LAUNCHER ERROR] {e}"
        )

# =========================================
# OPEN DASHBOARD
# =========================================

def launch_dashboard():

    status_label.config(

        text="Starting SOC Backend...",

        fg="#00ff88"
    )

    server_thread = threading.Thread(

        target=start_server,

        daemon=True
    )

    server_thread.start()

    # Poll until server responds — no fixed sleep
    status_label.config(
        text="Waiting for server...",
        fg="#00ff88"
    )

    import urllib.request

    deadline = time.time() + 30  # max 30s wait

    while time.time() < deadline:

        try:
            urllib.request.urlopen(
                f"http://{HOST}:{PORT}/",
                timeout=1
            )
            break  # server is up

        except Exception:
            time.sleep(0.5)

    status_label.config(
        text="Launching dashboard...",
        fg="#00ff88"
    )

    os.system(
        f'start http://{HOST}:{PORT}/dashboard'
    )

    root.destroy()


# =========================================
# LOGIN FUNCTION
# =========================================

def login():

    username = username_entry.get().strip()

    password = password_entry.get().strip()

    if (

        username == ADMIN_USERNAME

        and

        password == ADMIN_PASSWORD
    ):

        launch_dashboard()

    else:

        messagebox.showerror(

            "Authentication Failed",

            "Invalid Username or Password"
        )


# =========================================
# CLOSE HANDLER
# =========================================

def on_close():

    global server_process

    try:

        if server_process:

            server_process.terminate()

    except:
        pass

    root.destroy()


# =========================================
# MAIN WINDOW
# =========================================

root = tk.Tk()

root.title(
    "SOC Simulator"
)

root.geometry("1000x600")

root.configure(
    bg="#06131f"
)

root.resizable(
    False,
    False
)

root.protocol(
    "WM_DELETE_WINDOW",
    on_close
)


# =========================================
# LEFT PANEL
# =========================================

left_frame = tk.Frame(

    root,

    bg="#021526",

    width=500
)

left_frame.pack(

    side="left",

    fill="both"
)

left_frame.pack_propagate(False)


logo = tk.Label(

    left_frame,

    text="SOC\nSimulator",

    font=("Segoe UI", 36, "bold"),

    bg="#021526",

    fg="white",

    justify="center"
)

logo.place(

    relx=0.5,

    rely=0.22,

    anchor="center"
)


subtitle = tk.Label(

    left_frame,

    text="Host + Network IDS Platform",

    font=("Segoe UI", 16),

    bg="#021526",

    fg="#7aa2d6"
)

subtitle.place(

    relx=0.5,

    rely=0.36,

    anchor="center"
)


features = tk.Label(

    left_frame,

    text=

    "• Real-Time Threat Detection\n\n"

    "• HIDS + NIDS Monitoring\n\n"

    "• MITRE ATT&CK Mapping\n\n"

    "• Threat Hunting Engine\n\n"

    "• Digital Forensics Support",

    font=("Segoe UI", 14),

    bg="#021526",

    fg="white",

    justify="left"
)

features.place(

    relx=0.5,

    rely=0.62,

    anchor="center"
)


# =========================================
# RIGHT PANEL
# =========================================

right_frame = tk.Frame(

    root,

    bg="#0b2239",

    width=500
)

right_frame.pack(

    side="right",

    fill="both",

    expand=True
)

right_frame.pack_propagate(False)


login_title = tk.Label(

    right_frame,

    text="Login",

    font=("Segoe UI", 28, "bold"),

    bg="#0b2239",

    fg="white"
)

login_title.place(

    relx=0.5,

    rely=0.18,

    anchor="center"
)


# =========================================
# USERNAME
# =========================================

username_label = tk.Label(

    right_frame,

    text="Username",

    font=("Segoe UI", 12),

    bg="#0b2239",

    fg="white"
)

username_label.place(

    relx=0.22,

    rely=0.33
)


username_entry = tk.Entry(

    right_frame,

    width=28,

    font=("Segoe UI", 15),

    relief="flat",

    bg="#102b46",

    fg="white",

    insertbackground="white"
)

username_entry.place(

    relx=0.22,

    rely=0.38,

    height=42
)


# =========================================
# PASSWORD
# =========================================

password_label = tk.Label(

    right_frame,

    text="Password",

    font=("Segoe UI", 12),

    bg="#0b2239",

    fg="white"
)

password_label.place(

    relx=0.22,

    rely=0.49
)


password_entry = tk.Entry(

    right_frame,

    width=28,

    font=("Segoe UI", 15),

    show="*",

    relief="flat",

    bg="#102b46",

    fg="white",

    insertbackground="white"
)

password_entry.place(

    relx=0.22,

    rely=0.54,

    height=42
)


# =========================================
# LOGIN BUTTON
# =========================================

login_button = tk.Button(

    right_frame,

    text="LOGIN",

    width=22,

    height=2,

    font=("Segoe UI", 12, "bold"),

    bg="#2563eb",

    fg="white",

    activebackground="#1d4ed8",

    activeforeground="white",

    bd=0,

    cursor="hand2",

    command=login
)

login_button.place(

    relx=0.22,

    rely=0.70
)


# =========================================
# STATUS LABEL
# =========================================

status_label = tk.Label(

    right_frame,

    text="",

    font=("Segoe UI", 10),

    bg="#0b2239",

    fg="#00ff88"
)

status_label.place(

    relx=0.22,

    rely=0.94
)


# =========================================
# RUN
# =========================================

root.mainloop()