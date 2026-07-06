import os
import hashlib
from datetime import datetime
from app.database.database import (
    get_connection,
    insert_alert
)

from queue import Queue

scan_queue=Queue()
MONITORED_EXTENSIONS=[
    ".exe",
    ".dll",
    ".ps1",
    ".bat",
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

def calculate_file_hash(path):

    try:

        sha256=hashlib.sha256()

        with open(path,"rb") as f:

            while chunk:=f.read(4096):
                sha256.update(chunk)

        return sha256.hexdigest()

    except:
        return None

def store_file_snapshot(file_data):

    conn=get_connection()

    cursor=conn.cursor()

    cursor.execute("""
    INSERT INTO file_snapshots(
        file_path,
        file_hash,
        file_size,
        last_modified,
        extension,
        scan_time
    )
    VALUES(?,?,?,?,?,?)
    """,(
        file_data["file_path"],
        file_data["file_hash"],
        file_data["file_size"],
        file_data["last_modified"],
        file_data["extension"],
        file_data["scan_time"]
    ))

    conn.commit()
    conn.close()

def get_previous_snapshot(path):

    conn=get_connection()

    cursor=conn.cursor()

    cursor.execute("""
    SELECT file_hash,last_modified
    FROM file_snapshots
    WHERE file_path=?
    ORDER BY id DESC
    LIMIT 1
    """,(path,))

    result=cursor.fetchone()

    conn.close()

    return result

def analyze_file(file_path):

    try:

        extension=os.path.splitext(file_path)[1].lower()

        if extension not in MONITORED_EXTENSIONS \
        and extension not in SUSPICIOUS_EXTENSIONS:

            return

        stat=os.stat(file_path)

        file_hash=calculate_file_hash(file_path)

        current_data={

            "file_path":file_path,

            "file_hash":file_hash,

            "file_size":stat.st_size,

            "last_modified":
                datetime.fromtimestamp(
                    stat.st_mtime
                ).isoformat(),

            "extension":extension,

            "scan_time":
                datetime.now().isoformat()
        }

        previous=get_previous_snapshot(file_path)

        # ================= NEW FILE =================

        if not previous:

            severity="MEDIUM"

            alert_type="New File Detected"

            if extension in SUSPICIOUS_EXTENSIONS:

                severity="CRITICAL"

                alert_type="Possible Ransomware File"

            if "startup" in file_path.lower():

                severity="HIGH"

                alert_type="Startup Persistence File"

            insert_alert({

                "timestamp":datetime.now().isoformat(),

                "type":alert_type,

                "severity":severity,

                "category":"File Integrity",

                "description":
                    f"New monitored file detected: {file_path}",

                # "explanation":
                #     "File did not exist in previous forensic snapshot.",

                "log_source":"Forensics",

                "status":"New"
            })

        # ================= MODIFIED FILE =================

        else:

            old_hash=previous[0]

            if old_hash!=file_hash:

                insert_alert({

                    "timestamp":datetime.now().isoformat(),

                    "type":"File Modified",

                    "severity":"HIGH",

                    "category":"File Integrity",

                    "description":
                        f"File hash changed: {file_path}",

                    # "explanation":
                    #     "File contents changed between forensic scans.",

                    "log_source":"Forensics",

                    "status":"New"
                })

        store_file_snapshot(current_data)

    except Exception as e:
        print("File analysis error:",e)

def scan_filesystem(base_path=None):
    if base_path is None:
        from pathlib import Path
        root_dir = Path(__file__).resolve().parents[2]
        base_path = str(root_dir / "monitored_files")

    # Auto-create directory and seed mock forensic files
    os.makedirs(base_path, exist_ok=True)
    mock_files = {
        "invoice.xlsx": "Mock company billing transactions spreadsheet.",
        "winupdater.exe": "Mock system execution payload executable.",
        "financial_records.xlsx.locked": "Simulated ransomware encrypted critical spreadsheet file.",
        "backup_script.ps1": "Simulated PowerShell background administrative script."
    }
    for filename, content in mock_files.items():
        filepath = os.path.join(base_path, filename)
        if not os.path.exists(filepath):
            try:
                with open(filepath, "w") as f:
                    f.write(content)
            except Exception as e:
                print("Error writing mock forensic file:", e)

    print(f"[FORENSICS] Scanning filesystem: {base_path}")

    scanned=0

    for root,dirs,files in os.walk(base_path):
        
        dirs[:]=[
        d for d in dirs
        if d.lower() not in [

            "windows",
            "program files",
            "program files (x86)",
            "programdata",
            "appdata",
            "temp",
            "cache",
            "__pycache__",
            "node_modules",
            "venv",
            ".git",
            ".vscode"

        ]
    ]

        for file in files:

            try:

                path=os.path.join(root,file)

                analyze_file(path)

                scanned+=1

            except Exception as e:
                print("Filesystem scan error:",e)

    print(f"[FORENSICS] Total files analyzed: {scanned}")