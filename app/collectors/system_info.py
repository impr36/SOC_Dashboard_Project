import platform
import socket
import psutil
import os


def get_system_info():

    # ── OS type ───────────────────────────────────────────
    os_name = platform.system()          # "Windows", "Linux", "Darwin"

    # ── Hostname ──────────────────────────────────────────
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = os.environ.get("COMPUTERNAME", "Unknown")

    # ── IP address ────────────────────────────────────────
    # socket.gethostbyname() fails on VMs with no DNS.
    # Connect a UDP socket instead — works offline, no
    # actual packet is sent.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
    except Exception:
        try:
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            ip_address = "127.0.0.1"

    # ── Memory ────────────────────────────────────────────
    try:
        memory = psutil.virtual_memory()
        memory_percent = round(memory.percent)
    except Exception:
        memory_percent = 0

    # ── Disk ──────────────────────────────────────────────
    # On Windows "/" does not exist — use the drive where
    # Python is running, or fall back to C:\ explicitly.
    try:
        if os_name == "Windows":
            # sys.executable is e.g. C:\Python313\python.exe
            import sys
            drive = os.path.splitdrive(sys.executable)[0] + "\\"
            if not os.path.exists(drive):
                drive = "C:\\"
            disk = psutil.disk_usage(drive)
        else:
            disk = psutil.disk_usage("/")
        disk_percent = round(disk.percent)
    except Exception:
        disk_percent = 0

    return {
        "os":              os_name,
        "hostname":        hostname,
        "ip":              ip_address,
        "memory_percent":  memory_percent,
        "disk_percent":    disk_percent,
    }