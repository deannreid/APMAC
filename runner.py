#!/usr/bin/env python3
# ================================================================
# APMAC Secure Runner  automated executor
# Called by Task Scheduler (Windows) or cron (Linux).
# Decrypts stored AD credentials and runs APMAC.
#
# Prerequisites: run runner_setup.py first.
# ================================================================

import os
import re
import sys
import json
import logging
import subprocess
from pathlib import Path
from datetime import datetime, timezone

HERE        = Path(__file__).parent.resolve()
CONFIG_PATH = HERE / "runner_config.json"
CRED_PATH   = HERE / "runner.cred"
KEY_PATH    = HERE / "runner.key"    # Linux only
APMAC_PATH  = HERE / "APMAC.py"

IS_WINDOWS = os.name == "nt"

# ── Platform crypto ────────────────────────────────────────────────────────────

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

else:
    def _dpapi_unprotect(_): raise NotImplementedError("DPAPI is Windows-only")

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        print("[!] 'cryptography' package is required on Linux.  pip install cryptography")
        raise SystemExit(1)

    def _aes_unprotect(ciphertext: bytes) -> bytes:
        if not KEY_PATH.exists():
            raise FileNotFoundError(f"Key file not found: {KEY_PATH}\nRe-run runner_setup.py.")
        key   = KEY_PATH.read_bytes()
        nonce = ciphertext[:12]
        ct    = ciphertext[12:]
        return AESGCM(key).decrypt(nonce, ct, None)

# ── Logging ────────────────────────────────────────────────────────────────────

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKH]|\r')

def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub('', s)

def _setup_logging(log_path: str) -> logging.Logger:
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    log = logging.getLogger("apmac_runner")
    log.setLevel(logging.DEBUG)
    log.handlers.clear()

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(fmt)
    log.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)

    return log

# ── Build APMAC command ────────────────────────────────────────────────────────

def _build_cmd(config: dict, password: str) -> list:
    cmd = [sys.executable, str(APMAC_PATH)]

    for share in config.get("shares", []):
        cmd += ["--share", share]

    if config.get("domain"):
        cmd += ["--domain", config["domain"]]
    if config.get("username"):
        cmd += ["--user", config["username"]]

    # Password is passed via --pass. On Windows, reading another process's
    # command line requires SeDebugPrivilege. On Linux it is briefly visible
    # in /proc/<pid>/cmdline to root  acceptable for a service account context.
    cmd += ["--pass", password]

    if config.get("folders_only"):
        cmd += ["-Fo"]
    if config.get("flag_sensitive"):
        cmd += ["-Fs"]
    if config.get("custom_folders"):
        cmd += ["-Cu"] + config["custom_folders"]
    if config.get("report_dir"):
        cmd += ["--out-dir", config["report_dir"]]
    if config.get("dns"):
        cmd += ["--dns", config["dns"]]
    if config.get("dc"):
        cmd += ["--dc", config["dc"]]
    if config.get("threads"):
        cmd += ["--threads", str(config["threads"])]
    if config.get("level"):
        cmd += ["--level", str(config["level"])]

    return cmd

# ── Stream APMAC output into log (ANSI stripped) ──────────────────────────────

def _run_streaming(cmd: list, password: str, log: logging.Logger) -> int:
    safe_cmd = [("***" if c == password else c) for c in cmd]
    log.info("Command: %s", " ".join(safe_cmd))

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    for raw in proc.stdout:
        line = _strip_ansi(raw).rstrip()
        if line:
            log.info("[APMAC] %s", line)
    proc.wait()
    return proc.returncode

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    missing = [(p, lbl) for p, lbl in [
        (CONFIG_PATH, "Config (runner_config.json)"),
        (CRED_PATH,   "Credential (runner.cred)"),
        (APMAC_PATH,  "APMAC script (APMAC.py)"),
    ] if not p.exists()]

    if not IS_WINDOWS and not KEY_PATH.exists():
        missing.append((KEY_PATH, "Key file (runner.key)"))

    if missing:
        for _, lbl in missing:
            print(f"[!] Missing: {lbl}")
        if any("Config" in lbl or "Credential" in lbl or "Key" in lbl for _, lbl in missing):
            print("    Run runner_setup.py first.")
        raise SystemExit(1)

    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    log    = _setup_logging(config.get("log_file", str(HERE / "runner.log")))

    sep = "=" * 60
    log.info(sep)
    log.info("APMAC Monthly Runner  %s",
             datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    log.info("Platform: %s", "Windows" if IS_WINDOWS else sys.platform)
    log.info("Config:   %s", CONFIG_PATH)
    log.info("Account:  %s\\%s", config.get("domain", ""), config.get("username", ""))
    log.info("Shares:   %s", ", ".join(config.get("shares", [])))

    # ── Decrypt ───────────────────────────────────────────────────────────────
    try:
        password = _unprotect(CRED_PATH.read_bytes()).decode("utf-8")
    except Exception as exc:
        log.error("Credential decryption failed: %s", exc)
        if IS_WINDOWS:
            log.error("Cause: wrong machine, re-imaged OS, or corrupt .cred file.")
        else:
            log.error("Cause: runner.key missing/replaced, wrong user, or corrupt files.")
        log.error("Fix:   re-run runner_setup.py on this machine as the correct user.")
        raise SystemExit(1)

    log.info("Credentials decrypted OK.")

    # ── Run APMAC ─────────────────────────────────────────────────────────────
    cmd   = _build_cmd(config, password)
    start = datetime.now(timezone.utc)
    log.info("Launching APMAC...")

    try:
        rc = _run_streaming(cmd, password, log)
    except Exception as exc:
        log.error("Failed to launch APMAC: %s", exc)
        raise SystemExit(1)
    finally:
        password = "0" * len(password)   # zero out in local scope

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    h, m, s = int(elapsed // 3600), int((elapsed % 3600) // 60), int(elapsed % 60)

    if rc == 0:
        log.info("APMAC finished OK  (elapsed %02d:%02d:%02d, exit 0)", h, m, s)
    else:
        log.warning("APMAC exited with code %d  (elapsed %02d:%02d:%02d)", rc, h, m, s)

    log.info(sep)
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
