#!/usr/bin/env python3
# ================================================================
# APMAC Secure Runner  Setup Wizard
# Run once to store AD credentials securely and register the
# monthly schedule (Task Scheduler on Windows, crontab on Linux).
#
# Credential storage by platform:
#   Windows  Windows DPAPI, machine-scoped (any process on this
#             machine can decrypt; .cred ACL locked to SYSTEM +
#             Administrators via icacls).
#   Linux    AES-256-GCM using a randomly generated key stored in
#             runner.key (chmod 600, owned by the setup user).
#             The cron job must run as the same user.
# ================================================================

import os
import sys
import json
import getpass
import subprocess
from pathlib import Path

HERE        = Path(__file__).parent.resolve()
CONFIG_PATH = HERE / "runner_config.json"
CRED_PATH   = HERE / "runner.cred"
KEY_PATH    = HERE / "runner.key"    # Linux only
RUNNER_PATH = HERE / "runner.py"

IS_WINDOWS = os.name == "nt"
IS_LINUX   = sys.platform.startswith("linux")

# ── Platform crypto ────────────────────────────────────────────────────────────

def _protect(plaintext: bytes) -> bytes:
    if IS_WINDOWS:
        return _dpapi_protect(plaintext)
    return _aes_protect(plaintext)

def _unprotect(ciphertext: bytes) -> bytes:
    if IS_WINDOWS:
        return _dpapi_unprotect(ciphertext)
    return _aes_unprotect(ciphertext)

# ── Windows DPAPI ──────────────────────────────────────────────────────────────

if IS_WINDOWS:
    import ctypes
    import ctypes.wintypes

    CRYPTPROTECT_UI_FORBIDDEN  = 0x01
    CRYPTPROTECT_LOCAL_MACHINE = 0x04

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _dpapi_protect(plaintext: bytes) -> bytes:
        blob_in  = _Blob(len(plaintext),
                         ctypes.cast(ctypes.c_char_p(plaintext), ctypes.POINTER(ctypes.c_char)))
        blob_out = _Blob()
        flags    = CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob_in), "APMAC credential", None, None, None,
            flags, ctypes.byref(blob_out))
        if not ok:
            raise RuntimeError(f"CryptProtectData failed (0x{ctypes.GetLastError():08x})")
        result = bytes(ctypes.string_at(blob_out.pbData, blob_out.cbData))
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return result

    def _dpapi_unprotect(ciphertext: bytes) -> bytes:
        blob_in  = _Blob(len(ciphertext),
                         ctypes.cast(ctypes.c_char_p(ciphertext), ctypes.POINTER(ctypes.c_char)))
        blob_out = _Blob()
        flags    = CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None,
            flags, ctypes.byref(blob_out))
        if not ok:
            raise RuntimeError(f"CryptUnprotectData failed (0x{ctypes.GetLastError():08x})")
        result = bytes(ctypes.string_at(blob_out.pbData, blob_out.cbData))
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return result

# ── Linux AES-256-GCM ──────────────────────────────────────────────────────────
# Key stored in runner.key (chmod 600).
# Wire format: nonce(12 bytes) || ciphertext+tag

else:
    def _dpapi_protect(p):   raise NotImplementedError("DPAPI is Windows-only")
    def _dpapi_unprotect(p): raise NotImplementedError("DPAPI is Windows-only")

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        print("[!] 'cryptography' package is required on Linux.")
        print("    pip install cryptography")
        raise SystemExit(1)

    def _load_or_create_key() -> bytes:
        if KEY_PATH.exists():
            return KEY_PATH.read_bytes()
        key = os.urandom(32)
        KEY_PATH.write_bytes(key)
        KEY_PATH.chmod(0o600)
        return key

    def _aes_protect(plaintext: bytes) -> bytes:
        key   = _load_or_create_key()
        nonce = os.urandom(12)
        ct    = AESGCM(key).encrypt(nonce, plaintext, None)
        return nonce + ct

    def _aes_unprotect(ciphertext: bytes) -> bytes:
        key   = KEY_PATH.read_bytes()
        nonce = ciphertext[:12]
        ct    = ciphertext[12:]
        return AESGCM(key).decrypt(nonce, ct, None)

# ── ACL / permission hardening ─────────────────────────────────────────────────

def _harden():
    if IS_WINDOWS:
        for path in [CRED_PATH]:
            try:
                subprocess.run(
                    ["icacls", str(path), "/inheritance:r",
                     "/grant:r", "SYSTEM:(R)",
                     "/grant:r", "Administrators:(R)"],
                    capture_output=True, check=False)
            except Exception:
                pass
        print("  [✓] ACL: SYSTEM + Administrators read-only (icacls).")
    else:
        for path in [CRED_PATH, KEY_PATH]:
            if path.exists():
                path.chmod(0o600)
        print("  [✓] Permissions set to 600 (owner read/write only).")

# ── Scheduling ─────────────────────────────────────────────────────────────────

def _register_windows_task(day: int, hour: int):
    task_name = "APMAC_Monthly_Audit"
    cmd = [
        "schtasks", "/create", "/f",
        "/tn", task_name,
        "/tr", f'"{sys.executable}" "{RUNNER_PATH}"',
        "/sc", "MONTHLY",
        "/d",  str(day),
        "/st", f"{hour:02d}:00",
        "/ru", "SYSTEM",
        "/rl", "HIGHEST",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode == 0:
        print(f"  [✓] Task '{task_name}' registered  day {day} of each month at {hour:02d}:00")
        print(f"      Runs as: SYSTEM  |  Python: {sys.executable}")
    else:
        print(f"  [!] schtasks failed:\n      {r.stderr.strip()}")
        print("      Re-run setup as Administrator.")

def _register_cron(day: int, hour: int):
    entry   = f"0 {hour} {day} * *  \"{sys.executable}\" \"{RUNNER_PATH}\""
    comment = "# APMAC Monthly Audit (managed by runner_setup.py)"

    r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    existing_lines = r.stdout.splitlines() if r.returncode == 0 else []

    # Drop any previous APMAC entry
    cleaned = [l for l in existing_lines
               if "APMAC Monthly Audit" not in l and str(RUNNER_PATH) not in l]
    cleaned += [comment, entry]

    proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
    proc.communicate(input="\n".join(cleaned) + "\n")

    if proc.returncode == 0:
        print(f"  [✓] Cron job registered:  {entry}")
        print(f"      Runs as: {os.environ.get('USER', os.environ.get('LOGNAME', 'current user'))}")
        print(f"      Note: the cron job must run as this user for decryption to work.")
    else:
        print("  [!] crontab write failed  add the following line manually:")
        print(f"      {entry}")

def _show_manual_schedule(day: int, hour: int):
    if IS_WINDOWS:
        print(f'\n  schtasks /create /f /tn "APMAC_Monthly_Audit" '
              f'/tr \\"{sys.executable}\\" \\"{RUNNER_PATH}\\" '
              f'/sc MONTHLY /d {day} /st {hour:02d}:00 /ru SYSTEM /rl HIGHEST')
    else:
        print(f"\n  Add to crontab (crontab -e):")
        print(f"  0 {hour} {day} * *  \"{sys.executable}\" \"{RUNNER_PATH}\"")

# ── Prompt helpers ─────────────────────────────────────────────────────────────

def _ask(label: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    val  = input(f"  {label}{hint}: ").strip()
    return val or default

def _ask_list(label: str, hint: str = "") -> list:
    note = f" (e.g. {hint})" if hint else ""
    print(f"  {label}{note}")
    print("  One per line  blank line to finish:")
    items = []
    while True:
        v = input("    > ").strip()
        if not v:
            break
        items.append(v)
    return items

def _ask_yn(label: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    v = input(f"  {label} [{d}]: ").strip().lower()
    return v.startswith("y") if v else default

def _h(text: str):
    print(f"\n{'─'*60}\n  {text}\n{'─'*60}")

# ── Main wizard ────────────────────────────────────────────────────────────────

def main():
    platform_label = "Windows (DPAPI)" if IS_WINDOWS else "Linux (AES-256-GCM + key file)"

    print("\n" + "="*60)
    print("  APMAC Secure Runner  Setup Wizard")
    print(f"  Platform: {platform_label}")
    print("="*60)

    if not IS_WINDOWS and not IS_LINUX:
        print(f"[!] Unsupported platform: {sys.platform}")
        raise SystemExit(1)

    # ── Step 1: AD credentials ────────────────────────────────────────────────
    _h("Step 1 of 4  Active Directory Credentials")
    domain   = _ask("Domain (e.g. CORP)")
    username = _ask("Username (e.g. svc_apmac)")
    password = getpass.getpass("  Password: ")
    if not password:
        print("  [!] Password cannot be empty.")
        raise SystemExit(1)

    # Round-trip self-test before writing anything
    try:
        assert _unprotect(_protect(password.encode())) == password.encode()
    except Exception as exc:
        print(f"  [!] Crypto self-test failed: {exc}")
        raise SystemExit(1)
    print("  [✓] Encryption self-test passed.")

    # ── Step 2: Scan targets ──────────────────────────────────────────────────
    _h("Step 2 of 4  Scan Targets")
    shares = _ask_list("UNC shares to scan", r"\\corp.local\DFS")
    if not shares:
        print("  [!] At least one share is required.")
        raise SystemExit(1)

    # ── Step 3: Scan options ──────────────────────────────────────────────────
    _h("Step 3 of 4  Scan Options")
    folders_only   = _ask_yn("Folders-only mode (-Fo)?", default=False)
    custom_folders = []
    if _ask_yn("Flag custom folder names (-Cu)?", default=False):
        custom_folders = _ask_list("Custom folder names", "Payroll Legal Contracts")

    report_dir = _ask(r"Output directory (blank = auto APMAC_Audit-DATE in script folder)") or None
    dns        = _ask("DNS server for resolution fallback (optional)") or None
    dc         = _ask("Domain controller hostname (optional)")         or None
    threads    = int(_ask("Worker threads", default="20"))

    # ── Step 4: Schedule ──────────────────────────────────────────────────────
    _h("Step 4 of 4  Monthly Schedule")
    scheduler_label = "Task Scheduler job" if IS_WINDOWS else "crontab entry"
    schedule   = _ask_yn(f"Register a monthly {scheduler_label}?", default=True)
    sched_day  = 1
    sched_hour = 2
    if schedule:
        sched_day  = int(_ask("Day of month to run (1–28)", default="1"))
        sched_hour = int(_ask("Hour to start (0–23, 24 h clock)", default="2"))

    # ── Persist ───────────────────────────────────────────────────────────────
    _h("Saving")

    config = {
        "domain":         domain,
        "username":       username,
        "shares":         shares,
        "folders_only":   folders_only,
        "custom_folders": custom_folders,
        "report_dir":     report_dir,
        "dns":            dns,
        "dc":             dc,
        "threads":        threads,
        "log_file":       str(HERE / "runner.log"),
    }
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    print(f"  [✓] Config saved:      {CONFIG_PATH}")

    encrypted = _protect(password.encode("utf-8"))
    CRED_PATH.write_bytes(encrypted)
    print(f"  [✓] Credential saved:  {CRED_PATH}  ({len(encrypted)} bytes, encrypted)")

    if not IS_WINDOWS:
        print(f"  [✓] Key file:          {KEY_PATH}  (chmod 600)")

    _harden()

    if schedule:
        if IS_WINDOWS:
            _register_windows_task(sched_day, sched_hour)
        else:
            _register_cron(sched_day, sched_hour)
    else:
        print("  [i] Schedule registration skipped.")
        if _ask_yn("  Show the manual schedule command?", default=True):
            _show_manual_schedule(sched_day, sched_hour)

    print("\n" + "="*60)
    print("  Setup complete.")
    print(f"  Manual test:   python \"{RUNNER_PATH}\"")
    print(f"  Config:        {CONFIG_PATH}")
    print(f"  Credential:    {CRED_PATH}")
    if not IS_WINDOWS:
        print(f"  Key file:      {KEY_PATH}")
        print()
        print("  Linux reminder: the cron job decrypts using runner.key and")
        print("  must run as the same user that ran this setup script.")
        print("  Do not move runner.key off this machine.")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
