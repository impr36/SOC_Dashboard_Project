import os
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from backend import store_alert

MONITORED_EXTENSIONS=[
    ".exe",
    ".dll",
    ".bat",
    ".ps1",
    ".vbs",
    ".js",
    ".zip",
    ".rar"
]

SUSPICIOUS_EXTENSIONS=[
    ".locked",
    ".encrypted",
    ".crypt"
]

class FIMHandler(FileSystemEventHandler):

    def process_event(self,event,event_type):

        try:

            path=event.src_path

            extension=os.path.splitext(path)[1].lower()

            severity="LOW"

            description=f"{event_type}: {path}"

            alert_type="File Activity"

            # ================= EXECUTABLE FILES =================

            if extension in MONITORED_EXTENSIONS:

                severity="MEDIUM"

                alert_type="Executable File Activity"

            # ================= RANSOMWARE EXTENSIONS =================

            if extension in SUSPICIOUS_EXTENSIONS:

                severity="CRITICAL"

                alert_type="Possible Ransomware File Activity"

            # ================= STARTUP FOLDER =================

            startup_keywords=[
                "startup",
                "appdata",
                "programdata"
            ]

            if any(k in path.lower() for k in startup_keywords):

                severity="HIGH"

                alert_type="Startup Folder Modification"

            alert={

                "timestamp":datetime.now().isoformat(),

                "type":alert_type,

                "severity":severity,

                "description":description,

                "explanation":
                    f"Detected {event_type.lower()} activity on monitored filesystem.",

                "log_source":"FIM",

                "status":"New"
            }

            store_alert(alert)

            print(f"[FIM] {alert_type} -> {path}")

        except Exception as e:
            print("FIM error:",e)

    # ================= CREATED =================

    def on_created(self,event):

        if not event.is_directory:
            self.process_event(event,"File Created")

    # ================= DELETED =================

    def on_deleted(self,event):

        if not event.is_directory:
            self.process_event(event,"File Deleted")

    # ================= MODIFIED =================

    def on_modified(self,event):

        if not event.is_directory:
            self.process_event(event,"File Modified")

    # ================= MOVED =================

    def on_moved(self,event):

        if not event.is_directory:
            self.process_event(event,"File Moved")

def start_fim_monitor(path_to_monitor):

    event_handler=FIMHandler()

    observer=Observer()

    observer.schedule(
        event_handler,
        path_to_monitor,
        recursive=True
    )

    observer.start()

    print(f"[FIM] Monitoring started on: {path_to_monitor}")

    return observer