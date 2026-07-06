"""
integrity_guard.py
==================
Run this ONCE after you finish your project
to seal it. It will:

  1. Generate a random HMAC key
  2. Hash every protected source file
  3. Sign each hash with the HMAC key
  4. Write  security/manifest.json
  5. Lock the security/ folder permissions
  6. Hide the .seal_key file (Windows hidden+system)

After sealing, every time launcher.py starts it
will re-verify all hashes. If ANY file is changed
the app will refuse to start and show which files
were tampered with.

USAGE:
    python integrity_guard.py          # seal
    python integrity_guard.py verify   # verify only
    python integrity_guard.py reseal   # reseal after intentional change
"""

import os
import sys
import json
import hmac
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime

# =========================================
# CONFIG
# =========================================

PROJECT_ROOT    = Path(__file__).resolve().parent
SECURITY_DIR    = PROJECT_ROOT / "security"
MANIFEST_PATH   = SECURITY_DIR / "manifest.json"
SEAL_KEY_PATH   = SECURITY_DIR / ".seal_key"
SEAL_LOG_PATH   = SECURITY_DIR / "seal_log.txt"

PROTECTED_EXTENSIONS = {
    ".py", ".js", ".html", ".css", ".json"
}

SKIP_DIRS = {
    "__pycache__", ".venv", "venv",
    "database", "forensics_exports",
    "security", ".git", ".vscode",
    "sysmon_temp", "node_modules"
}

SKIP_FILES = {
    "integrity_guard.py",   # guard itself excluded
    "build_exe.py",
}


# =========================================
# HELPERS
# =========================================

def _hmac_sign(data: bytes, key: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _get_or_create_key() -> bytes:
    SECURITY_DIR.mkdir(exist_ok=True)
    if SEAL_KEY_PATH.exists():
        return SEAL_KEY_PATH.read_bytes()
    key = os.urandom(32)
    SEAL_KEY_PATH.write_bytes(key)
    _hide_file(SEAL_KEY_PATH)
    return key


def _hide_file(path: Path):
    """Mark file as Hidden + System on Windows."""
    try:
        subprocess.run(
            ["attrib", "+H", "+S", str(path)],
            capture_output=True
        )
    except Exception:
        pass


def _lock_folder(folder: Path):
    """
    Use icacls to deny Everyone write access.
    Only the current user retains full control.
    """
    username = os.environ.get("USERNAME", "Administrator")
    try:
        subprocess.run([
            "icacls", str(folder),
            "/inheritance:r",
            "/grant:r",
            f"{username}:(OI)(CI)F",
            "/deny",
            "Everyone:(W,D,DC)"
        ], capture_output=True)
        print(f"[LOCK] Permissions locked on: {folder}")
    except Exception as e:
        print(f"[LOCK WARNING] Could not lock permissions: {e}")


def _collect_files() -> list[Path]:
    files = []
    for path in sorted(PROJECT_ROOT.rglob("*")):
        if not path.is_file():
            continue
        # Skip protected dirs
        rel_parts = path.relative_to(PROJECT_ROOT).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        # Skip excluded files
        if path.name in SKIP_FILES:
            continue
        # Only target extensions
        if path.suffix.lower() not in PROTECTED_EXTENSIONS:
            continue
        files.append(path)
    return files


# =========================================
# SEAL
# =========================================

def seal():
    print("\n" + "="*50)
    print("  SOC SIMULATOR — PROJECT SEALER")
    print("="*50)

    key = _get_or_create_key()
    files = _collect_files()

    manifest = {}

    for path in files:
        rel = str(path.relative_to(PROJECT_ROOT))
        file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        signed    = _hmac_sign(file_hash.encode(), key)
        manifest[rel] = signed
        print(f"  [HASH] {rel}")

    MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2)
    )

    # Write seal log
    log_entry = (
        f"Sealed at: {datetime.now().isoformat()}\n"
        f"Files protected: {len(manifest)}\n"
        f"Operator: {os.environ.get('USERNAME', 'unknown')}\n"
        f"{'-'*40}\n"
    )
    with open(SEAL_LOG_PATH, "a") as f:
        f.write(log_entry)

    _lock_folder(SECURITY_DIR)
    _hide_file(SEAL_KEY_PATH)

    print(f"\n[SEAL] ✅ {len(manifest)} files sealed")
    print(f"[SEAL] Manifest: {MANIFEST_PATH}")
    print(
        "[SEAL] Lock applied to security/ folder\n"
    )


# =========================================
# VERIFY
# =========================================

def verify() -> bool:
    print("\n" + "="*50)
    print("  SOC SIMULATOR — INTEGRITY VERIFY")
    print("="*50)

    if not MANIFEST_PATH.exists():
        print("[VERIFY] No manifest found. Run seal first.")
        return False

    if not SEAL_KEY_PATH.exists():
        print("[VERIFY] CRITICAL: Seal key missing!")
        return False

    key      = SEAL_KEY_PATH.read_bytes()
    manifest = json.loads(MANIFEST_PATH.read_text())

    passed   = []
    failed   = []
    missing  = []

    for rel_path, expected_signed in manifest.items():
        full = PROJECT_ROOT / rel_path

        if not full.exists():
            missing.append(rel_path)
            continue

        actual_hash  = hashlib.sha256(full.read_bytes()).hexdigest()
        actual_signed = _hmac_sign(actual_hash.encode(), key)

        if actual_signed == expected_signed:
            passed.append(rel_path)
        else:
            failed.append(rel_path)

    # Report
    print(f"\n  ✅ Passed : {len(passed)}")
    print(f"  ❌ Modified: {len(failed)}")
    print(f"  🚫 Missing : {len(missing)}")

    if failed:
        print("\n[TAMPER DETECTED] Modified files:")
        for f in failed:
            print(f"  ⚠  {f}")

    if missing:
        print("\n[TAMPER DETECTED] Missing files:")
        for m in missing:
            print(f"  🚫 {m}")

    if not failed and not missing:
        print("\n[VERIFY] ✅ All files intact. Project is clean.")
        return True
    else:
        print("\n[VERIFY] ❌ INTEGRITY COMPROMISED.")
        return False


# =========================================
# ENTRY POINT
# =========================================

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "seal"

    if cmd == "verify":
        ok = verify()
        sys.exit(0 if ok else 1)

    elif cmd == "reseal":
        print(
            "[RESEAL] Removing old manifest and resealing..."
        )
        if MANIFEST_PATH.exists():
            MANIFEST_PATH.unlink()
        seal()

    else:
        # Default: seal
        if MANIFEST_PATH.exists():
            print(
                "[SEAL] Manifest already exists.\n"
                "       Use 'reseal' to rebuild it.\n"
                "       Use 'verify' to check integrity."
            )
            sys.exit(0)
        seal()
