import platform

import socket

import psutil

# =========================================
# SYSTEM INFO
# =========================================

def get_system_info():

    try:

        os_name = platform.system()

        hostname = socket.gethostname()

        ip_address = socket.gethostbyname(
            hostname
        )

        memory = psutil.virtual_memory()

        disk = psutil.disk_usage("/")

        return {

            "os": os_name,

            "hostname": hostname,

            "ip": ip_address,

            "memory_percent":
                round(memory.percent),

            "disk_percent":
                round(disk.percent)
        }

    except Exception as e:

        print(
            "System info error:",
            e
        )

        return {

            "os":"Unknown",

            "hostname":"Unknown",

            "ip":"0.0.0.0",

            "memory_percent":0,

            "disk_percent":0
        }