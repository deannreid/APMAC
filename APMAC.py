#!/usr/bin/env python3
# ================================================================
# APMAC v3 - Automated Privileged Material Acquisition Console
# DFS-aware SMB scanner for finding credentials, sensitive data,
# and weak folder permissions across enterprise file shares.
#
# GitHub: https://github.com/deannreid/APMAC
# Author: Dean
# ================================================================

import os
import re
import sys
import csv
import html
import time
import queue
import socket
import signal
import random
import argparse
import getpass
import logging
import warnings
import threading
import subprocess
import traceback
import ctypes
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from colorama import init, Fore
import smbclient
from smbprotocol.exceptions import (
    SMBResponseException,
    SMBException,
    BadNetworkName,
    PathNotCovered,
    NotFound,
)
try:
    from smbprotocol.exceptions import SMBOSError as _SMBOSError
except ImportError:
    _SMBOSError = None

init(autoreset=True)

GLOBAL_TRACKER      = None
GLOBAL_CSV_WRITER   = None
GLOBAL_START_TIME   = None
GLOBAL_OUT_DIR      = None
GLOBAL_SCAN_TS      = None
GLOBAL_TARGETS      = None
GLOBAL_FOLDERS_ONLY = False
GLOBAL_SCAN_USER    = None

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def is_tty() -> bool:
    try:
        return sys.stderr.isatty()
    except Exception:
        return False

# Suppress crypto ARC4 noise from NTLM stack
try:
    from cryptography.utils import CryptographyDeprecationWarning  # type: ignore
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except Exception:
    pass

# Reduce library logging noise
logging.getLogger("smbprotocol").setLevel(logging.ERROR)
logging.getLogger("smbclient").setLevel(logging.ERROR)
logging.getLogger("smbprotocol").propagate = False
logging.getLogger("smbclient").propagate = False

# ───────────── Banner ─────────────
BANNER = r"""
   _____ __________  _____      _____  _________  
  /  _  \\______   \/     \    /  _  \ \_   ___ \ 
 /  /_\  \|     ___/  \ /  \  /  /_\  \/    \  \/ 
/    |    \    |  /    Y    \/    |    \     \____
\____|__  /____|  \____|__  /\____|__  /\______  /
        \/                \/         \/        \/ 
  Automated Privileged Material Acquisition Console
  -------------------------------------------------
 It's just a script, that scans for top secret stuff
 ---------------------------------------------------
"""

BLURBS = [
    "Enumerating services: Like snooping through your neighbour's Wi-Fi, but legal.",
    "Exploring services: The geek's way of saying 'I'm just curious!'",
    "Probing the depths: Finding the juicy bits your network's been hiding.",
    "Shining a torch: Because every network has its dark corners.",
    "Going undercover: Like a ninja, but with packets.",
    "Breaking down barriers: Who said firewalls are impassable?",
    "Looking under the bonnet: What's powering this thing, anyway?",
]

# ───────────── REGEX PATTERNS ─────────────
# Raw strings used here; compiled into COMPILED_PATTERNS below.
#
# Key design: all key=value patterns use ['"]? after the keyword so they match
# three common assignment styles in one shot:
#
#   config / shell:  pass=secret          pass = secret
#   quoted value:    pass="secret"        pass='secret'
#   JSON / YAML:     "pass":"secret"      "pass": "secret"   'pass': 'secret'
#
# The ['"]? consumes the closing quote of a JSON/YAML quoted key before the
# separator, so the value branch can then match the (optionally quoted) value.
#
patterns = {
    # ── Credential assignment patterns ────────────────────────────────────────

    # user=/username=/login=/uid=  (value ≥3 chars, no < > placeholders)
    # Handles: user=alice  user="alice"  "username":"alice"  'uid': 'alice'
    "UserEquals": r'''(?i)\b(?:user(?:name)?|login|uid)['"]?\s*[:=]\s*(?:"([^"<>\s]{3,})"|'([^'<>\s]{3,})'|([A-Za-z0-9][A-Za-z0-9._%+\-]{2,}))''',

    # password=/pass=/pwd=/passwd=/passphrase=  (value ≥6 printable chars)
    # Handles: pass=s3cret  pass="s3cret"  "password":"s3cret"  'passwd': 's3cret'
    "PassEquals": r'''(?i)\b(?:pass(?:word|phrase)?|pwd|passwd)['"]?\s*[:=]\s*(?:"([^"<>\s]{6,})"|'([^'<>\s]{6,})'|([A-Za-z0-9!@#$%^&*()\-_+=.]{6,}))''',

    # ── Enterprise account naming conventions ─────────────────────────────────

    # SVC_/ROL_/ACC_ prefix service accounts + A-prefixed 6-digit employee IDs (A123456)
    "Username": r'(?i)(?<!\S)((?:SVC|ROL|ACC)_[a-z0-9._%+\-]{2,}|A[0-9]{6})(?!\S)',

    # Tiered privileged accounts - require a meaningful prefix (≥3 chars) before tier suffix
    "T0 Account": r'(?i)\b[a-z][a-z0-9._%+\-]{2,}_T0\b',
    "T1 Account": r'(?i)\b[a-z][a-z0-9._%+\-]{2,}_T1\b',
    "T2 Account": r'(?i)\b[a-z][a-z0-9._%+\-]{2,}_T2\b',
    "GMSA Account": r'(?i)\b[a-z][a-z0-9._%+\-]{2,}_GMSA\b',

    # ── High-value credential indicators ──────────────────────────────────────

    # PEM private key blocks (RSA, EC, DSA, OPENSSH, or bare PRIVATE KEY)
    "PrivateKey": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',

    # AWS IAM access key IDs (always start with AKIA)
    "AWSAccessKey": r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])',

    # API/secret/token key assignments (value ≥12 alphanumeric chars)
    # Handles: api_key=abc123...  "secret_key":"abc123..."  'client_secret': 'abc123...'
    "APIKey": r'''(?i)\b(?:api[_\-]?key|access[_\-]?token|secret[_\-]?key|auth[_\-]?token|client[_\-]?secret)['"]?\s*[:=]\s*(?:"([A-Za-z0-9_\-]{12,})"|'([A-Za-z0-9_\-]{12,})'|([A-Za-z0-9_\-]{12,}))''',
}

# Pre-compiled patterns (avoids repeated recompilation in the hot scan loop)
COMPILED_PATTERNS: dict[str, re.Pattern] = {k: re.compile(v) for k, v in patterns.items()}

# Values that are universally recognised as placeholders - skip any match whose
# captured value (lowercased) appears in this set.
PLACEHOLDER_VALUES = frozenset({
    "null", "none", "true", "false", "undefined", "placeholder",
    "example", "changeme", "yourpassword", "your_password", "password",
    "pass", "passwd", "xxxxx", "yyyyy", "n/a", "na", "empty", "blank",
    "todo", "fixme", "test", "admin", "user", "username", "login",
    "value", "default", "secret", "token",
})

# ───────────── SENSITIVE FILENAME PATTERNS ─────────────
# Matched against the full filename (name + extension) of every file found.
# Files matching any of these are access-probed and flagged if readable.
SENSITIVE_FILENAME_PATTERNS: dict[str, re.Pattern] = {
    "NewFile":      re.compile(r'^new\s+file(?:\s*\(\d+\))?(?:\.[^.]+)?$', re.I),
    "PasswordFile": re.compile(r'pass(?:word)?s?|passwd|cred(?:ential)?s?', re.I),
    "SecretFile":   re.compile(r'\bsecrets?\b|\bprivate\b|\bconfidential\b|\bsensitive\b', re.I),
    "KeyFile":      re.compile(r'\bkeys?\b|\bkeystore\b|id_rsa|id_dsa|id_ed25519|\.ppk$|\.pem$', re.I),
    "TokenFile":    re.compile(r'\btoken\b|\boauth\b|\bbearer\b|\bapi[_\-]?key\b', re.I),
    "BackupFile":   re.compile(r'\bbackup\b|\.bak$', re.I),
    "DatabaseDump": re.compile(r'\bdump\b|\.sql$', re.I),
}

EXCLUDED_DIRS = {'node_modules', '.git', '__pycache__', 'vendor', 'venv', '.dfsfolderlink'}

# ───────────── Sensitive folder names ─────────────
DEFAULT_SENSITIVE_FOLDERS = {"confidential", "internal", "secret"}
ONEDRIVE_KEYWORD = "onedrive"

def is_sensitive_folder(name: str, custom_names: set[str]) -> tuple[bool, str]:
    """Returns (is_sensitive, match_reason). Checks default list, OneDrive keyword, and custom names."""
    low = name.lower()
    if ONEDRIVE_KEYWORD in low:
        return True, "OneDrive"
    if low in DEFAULT_SENSITIVE_FOLDERS:
        return True, name.capitalize()
    if low in custom_names:
        return True, f"Custom:{name}"
    return False, ""

FILE_TYPES = (
   # '.txt',
    '.md',
   # '.log',
    '.cfg',
    '.conf',
   # '.ini',
   # '.json',
   # '.json5',
   # '.yaml',
    '.yml',
   # '.xml',
    '.properties',
    '.env',
    '.ps1',
    '.bat',
    '.cmd',
    '.sh',
    '.py',
   # '.js',
   # '.ts',
   # '.tsx',
   # '.rb',
    '.php',
   # '.sql',
)
MAX_SIZE_BYTES_DEFAULT = 10 * 1024 * 1024  # 10MB

# ───────────── DFS quarantine ─────────────
DFS_FAIL_COUNTS: dict[str, int] = {}
DFS_QUARANTINE_UNTIL: dict[str, float] = {}
DFS_FAIL_LOCK = threading.Lock()

def normalise_unc(p: str) -> str:
    return (p or "").replace("/", "\\").rstrip("\\")

def parse_unc_path(unc: str):
    u = normalise_unc(unc)
    if not u.startswith("\\\\"):
        raise ValueError(f"UNC path must start with \\\\ : {unc}")
    parts = [p for p in u.split("\\") if p]
    if not parts:
        raise ValueError("UNC path is empty")
    server = parts[0]
    share = parts[1] if len(parts) >= 2 else None
    subpath = "\\".join(parts[2:]) if len(parts) >= 3 else ""
    return server, share, subpath

def dfs_key(unc: str) -> str:
    u = normalise_unc(unc)
    parts = [p for p in u.split("\\") if p]
    if len(parts) >= 2:
        sub = "\\".join(parts[2:4]).lower() if len(parts) >= 3 else ""
        return f"{parts[0].lower()}\\{parts[1].lower()}\\{sub}"
    return u.lower()

def dfs_is_quarantined(unc: str) -> bool:
    k = dfs_key(unc)
    with DFS_FAIL_LOCK:
        until = DFS_QUARANTINE_UNTIL.get(k, 0.0)
    return time.time() < until

def dfs_record_fail(unc: str, cooldown_sec: int, max_fails: int) -> bool:
    k = dfs_key(unc)
    with DFS_FAIL_LOCK:
        DFS_FAIL_COUNTS[k] = DFS_FAIL_COUNTS.get(k, 0) + 1
        if DFS_FAIL_COUNTS[k] >= max_fails:
            DFS_QUARANTINE_UNTIL[k] = time.time() + cooldown_sec
            DFS_FAIL_COUNTS[k] = 0
            return True
    return False

# ───────────── SMB error helpers ─────────────
def try_get_smb_status(exc: Exception):
    m = re.search(r"(STATUS_[A-Z0-9_]+)\s*:\s*(0x[0-9a-fA-F]+)", str(exc))
    if m:
        return m.group(1), m.group(2).lower()
    # alt forms sometimes show "(STATUS_LOGON_FAILURE 0xc000006d)"
    m = re.search(r"(STATUS_[A-Z0-9_]+)\s*(0x[0-9a-fA-F]+)", str(exc))
    if m:
        return m.group(1), m.group(2).lower()
    return None, None

def is_access_denied(exc: Exception) -> bool:
    return "STATUS_ACCESS_DENIED" in str(exc)

def is_dfs_failover_candidate(exc: Exception) -> bool:
    return isinstance(exc, (PathNotCovered, BadNetworkName, NotFound))

def is_credit_error(exc: Exception) -> bool:
    s = str(exc).lower()
    return "credits" in s and ("only 0" in s or "0 credits" in s)

def is_dfs_object_error(exc: Exception) -> bool:
    if _SMBOSError is not None and isinstance(exc, _SMBOSError):
        return True
    s = str(exc)
    return any(tag in s for tag in (
        "STATUS_NOT_A_REPARSE_POINT",
        "STATUS_IO_REPARSE_TAG_MISMATCH",
        "STATUS_REPARSE_POINT_NOT_RESOLVED",
        "SMBOSError",
    ))

# ───────────── Status bar (SSH-safe) ─────────────
STATUS_LOCK = threading.Lock()
LAST_STATUS_TS = 0.0
STATUS_INTERVAL = 0.75  # reduce flicker over SSH

def fmt_hms(seconds: float) -> str:
    if seconds < 0:
        seconds = 0
    s = int(seconds)
    h = s // 3600
    m = (s % 3600) // 60
    sec = s % 60
    if h:
        return f"{h:02d}:{m:02d}:{sec:02d}"
    return f"{m:02d}:{sec:02d}"

def progress_bar(done: int, total: int, width: int = 24) -> str:
    total = max(1, total)
    frac = max(0.0, min(1.0, done / total))
    filled = int(frac * width)
    return "█" * filled + "░" * (width - filled)

def status_render(tracker, start_time: float) -> str:
    total_q, total_s, total_h, _, denied_n, _readable, total_fh = tracker.snapshot()
    now = time.time()
    elapsed = now - start_time

    folders_only_mode = GLOBAL_FOLDERS_ONLY and total_q == 0

    if folders_only_mode:
        # No file queue in -Fo mode — show folder-centric bar
        line = (
            f"{Fore.GREEN}[SCAN]{Fore.RESET} "
            f"Folders:{Fore.MAGENTA}{total_fh}{Fore.RESET} "
            f"Hits:{Fore.CYAN}{total_h}{Fore.RESET} "
            f"Denied:{Fore.RED}{denied_n}{Fore.RESET} "
            f"Elapsed:{Fore.CYAN}{fmt_hms(elapsed)}{Fore.RESET}"
        )
    else:
        rate = (total_s / elapsed) if elapsed > 0 else 0.0
        remaining = max(0, total_q - total_s)
        eta = (remaining / rate) if rate > 0 else 0.0
        pct = (100.0 * total_s / max(1, total_q))
        bar = progress_bar(total_s, total_q, width=26)
        folder_part = f"Folders:{Fore.MAGENTA}{total_fh}{Fore.RESET} " if total_fh else ""
        line = (
            f"{Fore.GREEN}[PROGRESS]{Fore.RESET} "
            f"{Fore.CYAN}{total_s}{Fore.RESET}/{Fore.CYAN}{total_q}{Fore.RESET} "
            f"{Fore.YELLOW}{bar}{Fore.RESET} "
            f"{Fore.MAGENTA}{pct:5.1f}%{Fore.RESET} "
            f"Rate:{Fore.CYAN}{rate:5.1f}/s{Fore.RESET} "
            f"ETA:{Fore.CYAN}{fmt_hms(eta)}{Fore.RESET} "
            f"Hits:{Fore.CYAN}{total_h}{Fore.RESET} "
            f"{folder_part}"
            f"Denied:{Fore.RED}{denied_n}{Fore.RESET} "
            f"Elapsed:{Fore.CYAN}{fmt_hms(elapsed)}{Fore.RESET}"
        )

    try:
        cols = os.get_terminal_size(sys.stderr.fileno()).columns
        if len(line) > cols - 1:
            line = line[:cols - 1]
    except Exception:
        pass
    return line

def status_update(tracker, start_time: float, force: bool = False):
    global LAST_STATUS_TS
    if not is_tty():
        return
    now = time.time()
    if not force and (now - LAST_STATUS_TS) < STATUS_INTERVAL:
        return
    LAST_STATUS_TS = now
    line = status_render(tracker, start_time)
    with STATUS_LOCK:
        sys.stderr.write("\r" + line + " " * 5)
        sys.stderr.flush()

def status_clear_line():
    if not is_tty():
        return
    with STATUS_LOCK:
        sys.stderr.write("\r\x1b[0K")
        sys.stderr.flush()

def status_clear_hard():
    # used only at the end / exit to avoid leaving partial status
    if not is_tty():
        return
    with STATUS_LOCK:
        sys.stderr.write("\r" + (" " * 220) + "\r")
        sys.stderr.flush()

def safe_print(msg: str):
    """
    Print without flicker:
    - Clear ONLY the current status line (not the whole screen)
    - Print to stdout
    - Redraw status afterwards (forced)
    """
    if is_tty():
        status_clear_line()
        print(msg)
        if GLOBAL_TRACKER and GLOBAL_START_TIME is not None:
            status_update(GLOBAL_TRACKER, GLOBAL_START_TIME, force=True)
    else:
        print(msg)

def describe_smb_error(context: str, exc: Exception, debug: bool):
    status_name, status_hex = try_get_smb_status(exc)

    if is_access_denied(exc):
        safe_print(Fore.RED + f"[DENIED] {context} ({status_name or 'STATUS_ACCESS_DENIED'} {status_hex or ''})".rstrip())
        return

    if is_credit_error(exc):
        safe_print(Fore.RED + f"[!] SMB credit starvation at {context}: {exc}")
        return

    friendly = None
    if isinstance(exc, PathNotCovered):
        friendly = "DFS referral mismatch"
    elif isinstance(exc, BadNetworkName):
        friendly = "Bad share name on referral target"
    elif isinstance(exc, NotFound):
        friendly = "DFS referral object not found"
    elif isinstance(exc, SMBResponseException):
        friendly = "SMB server error"
    elif isinstance(exc, SMBException):
        friendly = "SMB protocol error"

    bits = []
    if status_name:
        bits.append(status_name)
    if status_hex:
        bits.append(status_hex)
    status_txt = " ".join(bits) if bits else type(exc).__name__

    safe_print(Fore.RED + f"[!] SMB/DFS error at {context}: {friendly or 'SMB error'} ({status_txt})")
    if debug:
        safe_print(Fore.YELLOW + f"[DEBUG] Raw error: {exc}")
        safe_print(Fore.YELLOW + traceback.format_exc())

# ───────────── Chunked CSV writer ─────────────
class ChunkedCSVWriter:
    def __init__(self, base_path: str, max_rows: int = 5000):
        self.base_path = base_path
        self.max_rows = max_rows
        self.part = 1
        self.rows_in_part = 0
        self.lock = threading.Lock()
        self.f = None
        self.w = None
        self.current_path = None
        self._open_new_part()

    def _make_part_path(self, part: int) -> str:
        root, ext = os.path.splitext(self.base_path)
        if not ext:
            ext = ".csv"
        return f"{root}_part{part:03d}{ext}"

    def _open_new_part(self):
        if self.f:
            try:
                self.f.flush()
                self.f.close()
            except Exception:
                pass

        self.current_path = self._make_part_path(self.part)
        os.makedirs(os.path.dirname(os.path.abspath(self.current_path)), exist_ok=True)

        self.f = open(self.current_path, "w", newline="", encoding="utf-8")
        self.w = csv.writer(self.f)
        self.w.writerow(["row_type", "timestamp_utc", "path", "line", "pattern", "match", "action", "status"])
        self.rows_in_part = 0
        safe_print(Fore.GREEN + f"[i] CSV writing to: {self.current_path}")

    def _ensure_space(self):
        if self.rows_in_part >= self.max_rows:
            self.part += 1
            self._open_new_part()

    def write_filename_hit(self, ts: str, path: str, pattern: str, match: str):
        with self.lock:
            self._ensure_space()
            self.w.writerow(["FILENAME_HIT", ts, path, "", pattern, match, "READ=YES", "FLAGGED"])
            self.rows_in_part += 1

    def write_folder_hit(self, ts: str, path: str, pattern: str, match: str, can_read: bool, can_write: bool):
        with self.lock:
            self._ensure_space()
            access = f"READ={'YES' if can_read else 'NO'} WRITE={'YES' if can_write else 'NO'}"
            self.w.writerow(["FOLDER_HIT", ts, path, "", pattern, match, access, "FLAGGED"])
            self.rows_in_part += 1

    def write_finding(self, ts: str, path: str, line: int, patt: str, match: str):
        with self.lock:
            self._ensure_space()
            self.w.writerow(["FINDING", ts, path, line, patt, match, "", ""])
            self.rows_in_part += 1

    def write_denied(self, ts: str, path: str, action: str, status: str):
        with self.lock:
            self._ensure_space()
            self.w.writerow(["DENIED", ts, path, "", "", "", action, status])
            self.rows_in_part += 1

    def flush(self):
        with self.lock:
            if self.f:
                self.f.flush()

    def close(self):
        with self.lock:
            if self.f:
                try:
                    self.f.flush()
                    self.f.close()
                finally:
                    self.f = None
                    self.w = None

# ───────────── Finding tracker ─────────────
class FindingTracker:
    def __init__(self, pattern_names: list[str], debug: bool, csv_writer: ChunkedCSVWriter):
        self.debug = debug
        self.csv_writer = csv_writer
        self.lock = threading.Lock()
        self.counts = {k: 0 for k in pattern_names}
        self.total_files_scanned = 0
        self.total_files_queued = 0
        self.total_files_readable = 0
        self.total_hits = 0
        self.denied_count = 0
        self.total_folder_hits = 0
        self.folder_hits: list[dict] = []
        self.filename_hits: list[dict] = []
        self.all_dirs: list[dict] = []
        self._all_dirs_total = 0
        self._ALL_DIRS_CAP   = 50_000

    def inc_queued(self, n=1):
        with self.lock:
            self.total_files_queued += n

    def inc_scanned(self, n=1):
        with self.lock:
            self.total_files_scanned += n

    def inc_readable(self, n=1):
        with self.lock:
            self.total_files_readable += n

    def add_hit(self, filepath: str, lineno: int, patt: str, match: str):
        ts = utc_now_iso()
        with self.lock:
            self.counts[patt] += 1
            self.total_hits += 1
        self.csv_writer.write_finding(ts, filepath, lineno, patt, match)

        if self.debug:
            safe_print(Fore.YELLOW + f"[FOUND] {filepath}")
            safe_print(Fore.CYAN + f"    Pattern: {Fore.RED}{patt}{Fore.YELLOW} - Line {lineno}: {match}")

    def add_filename_hit(self, file_unc: str, filename: str, pattern: str):
        ts = utc_now_iso()
        entry = {"ts": ts, "path": file_unc, "name": filename, "pattern": pattern}
        with self.lock:
            self.filename_hits.append(entry)
        self.csv_writer.write_filename_hit(ts, file_unc, pattern, filename)

    def add_folder_hit(self, folder_unc: str, folder_name: str, match_reason: str, can_read: bool, can_write: bool):
        ts = utc_now_iso()
        entry = {
            "ts": ts,
            "path": folder_unc,
            "name": folder_name,
            "reason": match_reason,
            "read": can_read,
            "write": can_write,
        }
        with self.lock:
            self.folder_hits.append(entry)
            self.total_folder_hits += 1
        self.csv_writer.write_folder_hit(ts, folder_unc, match_reason, folder_name, can_read, can_write)

    def add_dir(self, path: str, accessible: bool, write: bool | None = None):
        with self.lock:
            self._all_dirs_total += 1
            if len(self.all_dirs) < self._ALL_DIRS_CAP:
                self.all_dirs.append({"path": path, "accessible": accessible, "write": write})

    def add_denied(self, path: str, action: str, exc: Exception):
        ts = utc_now_iso()
        status_name, status_hex = try_get_smb_status(exc)
        status = f"{status_name or 'STATUS_ACCESS_DENIED'} {status_hex or ''}".strip()
        with self.lock:
            self.denied_count += 1
        self.csv_writer.write_denied(ts, path, action, status)

    def snapshot(self):
        with self.lock:
            return (
                self.total_files_queued,
                self.total_files_scanned,
                self.total_hits,
                dict(self.counts),
                self.denied_count,
                self.total_files_readable,
                self.total_folder_hits,
            )

# ───────────── DNS fallback and hosts update ─────────────
def try_socket_resolve(host: str):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def nslookup_resolve(host: str, dns_server: str | None):
    cmd = ["nslookup", host]
    if dns_server:
        cmd.append(dns_server)
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=10)
    except Exception:
        return None
    ips = re.findall(r"Address:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out)
    return ips[-1] if ips else None

def _is_admin() -> bool:
    """Cross-platform admin/root check."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False

def _hosts_path() -> str:
    """Return platform-appropriate hosts file path."""
    if os.name == "nt":
        return r"C:\Windows\System32\drivers\etc\hosts"
    return "/etc/hosts"

def ensure_hosts_entry(host: str, ip: str, debug: bool):
    if not _is_admin():
        if debug:
            safe_print(Fore.YELLOW + f"[DEBUG] Not admin/root: cannot write hosts file for {host}->{ip}")
        return False
    hosts_path = _hosts_path()
    try:
        with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            if re.search(rf"^\s*{re.escape(ip)}\s+{re.escape(host)}(\s|$)", content, flags=re.M):
                return True
            if re.search(rf"^\s*[0-9.]+\s+{re.escape(host)}(\s|$)", content, flags=re.M):
                return True
        with open(hosts_path, "a", encoding="utf-8") as f:
            f.write(f"\n{ip}\t{host}\n")
        safe_print(Fore.GREEN + f"[✓] Added hosts entry: {host} -> {ip}")
        return True
    except Exception as e:
        if debug:
            safe_print(Fore.YELLOW + f"[DEBUG] Failed writing hosts file: {e}")
        return False

def resolve_host_with_fallback(host: str, dns_server: str | None, debug: bool):
    ip = try_socket_resolve(host)
    if ip:
        return ip
    if debug:
        safe_print(Fore.YELLOW + f"[DEBUG] Resolver failed for {host}, trying nslookup...")
    ip = nslookup_resolve(host, dns_server)
    if ip:
        ensure_hosts_entry(host, ip, debug)
        return ip
    return None

# ───────────── SMB auth configuration ─────────────
def fmt_user(domain: str | None, user: str | None) -> str:
    if not user:
        return "<anonymous>"
    if "\\" in user or "@" in user:
        return user
    return f"{domain}\\{user}" if domain else user

def smb_register_defaults(domain: str | None, username: str | None, password: str | None, dc: str | None, debug: bool):
    smb_user = fmt_user(domain, username)
    kwargs = {}
    if smb_user != "<anonymous>":
        kwargs["username"] = smb_user
        kwargs["password"] = password or ""
    if dc:
        kwargs["domain_controller"] = dc
    if debug and kwargs:
        safe_print(Fore.YELLOW + f"[DEBUG] ClientConfig({', '.join([f'{k}={v!r}' for k, v in kwargs.items()])})")
    if kwargs:
        smbclient.ClientConfig(**kwargs)

# ───────────── Share enumeration (when UNC missing share) ─────────────
def smbclient_list_shares(server: str, domain: str | None, username: str | None, password: str | None, debug: bool):
    target = f"//{server}"
    cmd = ["smbclient", "-L", target, "-g"]

    if username:
        cmd += ["-U", f"{username}%{password or ''}"]
        if domain:
            cmd += ["-W", domain]
    else:
        cmd += ["-N"]

    if debug:
        safe_print(Fore.YELLOW + f"[DEBUG] Share enum cmd: {' '.join(cmd)}")

    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=25)
    except FileNotFoundError:
        safe_print(Fore.RED + "[!] smbclient not found. Install it (apt install smbclient) to enumerate shares from \\\\server.")
        return []
    except Exception as e:
        if debug:
            safe_print(Fore.YELLOW + f"[DEBUG] Share enum failed: {e}")
        return []

    shares = []
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) < 2:
            continue
        entry_type = parts[0].strip()
        share_name = parts[1].strip()
        if entry_type.lower() != "disk":
            continue
        if share_name.upper() in {"IPC$", "PRINT$", "ADMIN$"}:
            continue
        if share_name.startswith("."):
            continue
        shares.append(share_name)

    return shares

# ───────────── Breadcrumb output with coloured counts ─────────────
def format_segment(name: str, count: int | None):
    if count is None:
        return name
    return f"{name}{Fore.MAGENTA}({count}){Fore.GREEN}"

def print_scan_line(segments: list[tuple[str, int | None]]):
    out = [format_segment(n, c) for n, c in segments]
    safe_print(Fore.GREEN + "[SCAN] " + " > ".join(out))

def update_last_count(segments: list[tuple[str, int | None]], count: int):
    if not segments:
        return segments
    name, _ = segments[-1]
    segments[-1] = (name, count)
    return segments

# ───────────── Credit limiter (avoid SMB credit starvation) ─────────────
class CreditLimiter:
    def __init__(self, per_target_limit: int):
        self.per_target_limit = max(1, per_target_limit)
        self._locks = defaultdict(lambda: threading.Semaphore(self.per_target_limit))

    def key_for_unc(self, unc: str) -> str:
        try:
            srv, sh, _ = parse_unc_path(unc)
        except Exception:
            return "unknown"
        return f"{srv.lower()}\\{(sh or '').lower()}"

    def acquire(self, unc: str):
        self._locks[self.key_for_unc(unc)].acquire()

    def release(self, unc: str):
        self._locks[self.key_for_unc(unc)].release()

# ───────────── Scan file content ─────────────
def is_binary_blob(data: bytes) -> bool:
    return b"\0" in data

def first_non_empty_group(m: re.Match) -> str:
    if m.lastindex:
        for i in range(1, m.lastindex + 1):
            g = m.group(i)
            if g:
                return g
    return m.group(0)

def scan_text_lines(lines_iterable, filepath: str, tracker: FindingTracker):
    for lineno, line in enumerate(lines_iterable, 1):
        for key, compiled in COMPILED_PATTERNS.items():
            m = compiled.search(line)
            if m:
                val = first_non_empty_group(m)
                if val.lower().strip() in PLACEHOLDER_VALUES:
                    continue
                tracker.add_hit(filepath, lineno, key, val)

# ───────────── Folder permission probes ─────────────
def check_smb_folder_read(folder_unc: str, limiter: CreditLimiter, conn_timeout: int) -> bool:
    """Returns True if the current user can list the folder."""
    limiter.acquire(folder_unc)
    try:
        for _ in smbclient.scandir(folder_unc, connection_timeout=conn_timeout):
            break  # one SMB query is enough to prove read access
        return True
    except Exception:
        return False
    finally:
        limiter.release(folder_unc)

def check_smb_folder_write(folder_unc: str, limiter: CreditLimiter, conn_timeout: int) -> bool:
    """Returns True if the current user can write to the folder (creates+deletes a probe file)."""
    probe_unc = folder_unc + f"\\.apmac_probe_{int(time.time())}"
    limiter.acquire(folder_unc)
    try:
        fd = smbclient.open_file(probe_unc, mode="wb", connection_timeout=conn_timeout)
        try:
            fd.close()
        except Exception:
            pass
        try:
            smbclient.remove(probe_unc)
        except Exception:
            pass
        return True
    except Exception as e:
        if is_access_denied(e):
            return False
        return False
    finally:
        limiter.release(folder_unc)

def check_smb_file_readable(file_unc: str, limiter: CreditLimiter, conn_timeout: int) -> bool:
    """Returns True if the current user can open the file for reading."""
    limiter.acquire(file_unc)
    try:
        fd = smbclient.open_file(file_unc, mode="rb", connection_timeout=conn_timeout)
        try:
            fd.close()
        except Exception:
            pass
        return True
    except Exception:
        return False
    finally:
        limiter.release(file_unc)

# ───────────── SMB wrappers ─────────────
def smb_scandir_with_retry(path_unc: str,
                           debug: bool,
                           tracker: FindingTracker,
                           limiter: CreditLimiter,
                           conn_timeout: int,
                           dfs_quarantine_maxfails: int,
                           dfs_quarantine_secs: int,
                           retries: int = 3):
    if dfs_is_quarantined(path_unc):
        if debug:
            safe_print(Fore.YELLOW + f"[DEBUG] DFS quarantine skip: {path_unc}")
        return None

    attempt = 0
    while attempt <= retries:
        limiter.acquire(path_unc)
        try:
            return list(smbclient.scandir(path_unc, connection_timeout=conn_timeout))
        except (SMBResponseException, SMBException, OSError) as e:
            if is_access_denied(e):
                describe_smb_error(path_unc, e, debug)
                tracker.add_denied(path_unc, "LISTDIR", e)
                return None

            if is_dfs_object_error(e):
                if debug:
                    safe_print(Fore.YELLOW + f"[DEBUG] DFS reparse/object skip: {path_unc}")
                return None

            if (is_dfs_failover_candidate(e) or is_credit_error(e)) and attempt < retries:
                quarantined = dfs_record_fail(path_unc, dfs_quarantine_secs, dfs_quarantine_maxfails) if is_dfs_failover_candidate(e) else False
                if quarantined:
                    safe_print(Fore.RED + f"[!] DFS path repeatedly failing, skipping for {dfs_quarantine_secs}s: {path_unc}")
                    return None

                if debug:
                    safe_print(Fore.YELLOW + f"[DEBUG] scandir retry {attempt+1}/{retries} for {path_unc} due to: {e}")

                smbclient.reset_connection_cache()
                time.sleep(0.25 * (attempt + 1))
                attempt += 1
                continue

            describe_smb_error(path_unc, e, debug)
            return None
        finally:
            limiter.release(path_unc)

    return None

def scan_smb_file_unc(file_unc: str,
                      max_read: int,
                      tracker: FindingTracker,
                      debug: bool,
                      limiter: CreditLimiter,
                      conn_timeout: int,
                      dfs_quarantine_maxfails: int,
                      dfs_quarantine_secs: int,
                      retries: int = 2):

    if dfs_is_quarantined(file_unc):
        return

    tracker.inc_scanned(1)
    if debug:
        safe_print(Fore.CYAN + f"[FILE] {file_unc}")

    attempt = 0
    while attempt <= retries:
        limiter.acquire(file_unc)
        fd = None
        try:
            fd = smbclient.open_file(file_unc, mode="rb", connection_timeout=conn_timeout)
            data = fd.read(max_read)
            try:
                fd.close()
            except Exception:
                pass

            if not data:
                tracker.inc_readable()
                return
            if is_binary_blob(data[:2048]):
                tracker.inc_readable()
                return

            text = data.decode("utf-8", errors="ignore")
            scan_text_lines(text.splitlines(), file_unc, tracker)
            tracker.inc_readable()
            return

        except (SMBResponseException, SMBException, OSError) as e:
            if is_access_denied(e):
                describe_smb_error(file_unc, e, debug)
                tracker.add_denied(file_unc, "READ", e)
                return

            if is_dfs_object_error(e):
                if debug:
                    safe_print(Fore.YELLOW + f"[DEBUG] DFS reparse/object skip: {file_unc}")
                return

            if (is_dfs_failover_candidate(e) or is_credit_error(e)) and attempt < retries:
                quarantined = dfs_record_fail(file_unc, dfs_quarantine_secs, dfs_quarantine_maxfails) if is_dfs_failover_candidate(e) else False
                if quarantined:
                    safe_print(Fore.RED + f"[!] DFS path repeatedly failing, skipping for {dfs_quarantine_secs}s: {file_unc}")
                    return

                if debug:
                    safe_print(Fore.YELLOW + f"[DEBUG] read retry {attempt+1}/{retries} for {file_unc} due to: {e}")

                smbclient.reset_connection_cache()
                time.sleep(0.25 * (attempt + 1))
                attempt += 1
                continue

            describe_smb_error(file_unc, e, debug)
            return

        finally:
            try:
                if fd is not None:
                    fd.close()
            except Exception:
                pass
            limiter.release(file_unc)

# ───────────── DFS-aware walk ─────────────
def smb_walk_files_with_dfs(root_unc: str,
                            tracker: FindingTracker,
                            debug: bool,
                            max_size: int,
                            limiter: CreditLimiter,
                            conn_timeout: int,
                            dfs_quarantine_maxfails: int,
                            dfs_quarantine_secs: int,
                            start_time: float,
                            sensitive_folders: set[str] | None = None,
                            folders_only: bool = False,
                            max_depth: int = 0):
    root_unc = normalise_unc(root_unc)
    parts = [p for p in root_unc.split("\\") if p]
    _custom = sensitive_folders or set()
    root_depth = len([p for p in root_unc.split("\\") if p])

    segments: list[tuple[str, int | None]] = [("(share-root)", None)]
    if len(parts) >= 3:
        segments = [("(share-root)", None)] + [(p, None) for p in parts[2:]]

    def walk_dir(dir_unc: str, segs: list[tuple[str, int | None]]):
        entries = smb_scandir_with_retry(
            dir_unc, debug, tracker, limiter, conn_timeout,
            dfs_quarantine_maxfails, dfs_quarantine_secs,
            retries=3
        )
        if entries is None:
            tracker.add_dir(dir_unc, accessible=False)
            return

        tracker.add_dir(dir_unc, accessible=True)
        segs = update_last_count(segs, len(entries))
        print_scan_line(segs)

        dirs = []
        files = []

        for ent in entries:
            try:
                name = ent.name
                if ent.is_dir():
                    if name.lower() in EXCLUDED_DIRS:
                        continue
                    dirs.append(ent)
                elif not folders_only and ent.is_file():
                    files.append(ent)
            except Exception:
                continue

        # ── Filename pattern check (all files, any extension) ──
        if not folders_only:
            for f in files:
                file_unc = dir_unc + "\\" + f.name
                for pat_name, pat_re in SENSITIVE_FILENAME_PATTERNS.items():
                    if pat_re.search(f.name):
                        if check_smb_file_readable(file_unc, limiter, conn_timeout):
                            safe_print(Fore.YELLOW + f"[FILENAME] {pat_name}: {file_unc}")
                            tracker.add_filename_hit(file_unc, f.name, pat_name)
                        break  # one label per file is enough

        if not folders_only:
            for f in files:
                low = f.name.lower()
                if not low.endswith(FILE_TYPES):
                    continue
                try:
                    st = f.stat()
                    if st.st_size > max_size:
                        continue
                except Exception:
                    continue

                file_unc = dir_unc + "\\" + f.name
                tracker.inc_queued(1)
                yield file_unc
                status_update(tracker, start_time)

        cur_depth = len([p for p in dir_unc.split("\\") if p]) - root_depth
        for d in sorted(dirs, key=lambda x: x.name.lower()):
            next_unc = dir_unc + "\\" + d.name

            is_sens, reason = is_sensitive_folder(d.name, _custom)
            if is_sens:
                can_read = check_smb_folder_read(next_unc, limiter, conn_timeout)
                can_write = check_smb_folder_write(next_unc, limiter, conn_timeout)
                if can_read or can_write:
                    rw_label = f"READ={'YES' if can_read else 'NO'} WRITE={'YES' if can_write else 'NO'}"
                    safe_print(Fore.MAGENTA + f"[FOLDER] {reason}: {next_unc} [{rw_label}]")
                    tracker.add_folder_hit(next_unc, d.name, reason, can_read, can_write)

            if max_depth and cur_depth >= max_depth:
                continue

            next_segs = segs[:] + [(d.name, None)]
            yield from walk_dir(next_unc, next_segs)

    yield from walk_dir(root_unc, segments)

# ───────────── Clean shutdown (Ctrl+C flush) ─────────────
def flush_and_exit(code: int = 0):
    global GLOBAL_CSV_WRITER, GLOBAL_TRACKER, GLOBAL_OUT_DIR, GLOBAL_SCAN_TS, GLOBAL_START_TIME, GLOBAL_TARGETS, GLOBAL_FOLDERS_ONLY, GLOBAL_SCAN_USER
    status_clear_hard()

    # Flush and close CSV files so nothing is lost
    if GLOBAL_CSV_WRITER is not None:
        safe_print(Fore.YELLOW + "\n[i] Interrupt received  flushing CSV files...")
        try:
            GLOBAL_CSV_WRITER.close()
            safe_print(Fore.GREEN + "[✓] CSV flushed and closed.")
        except Exception as exc:
            safe_print(Fore.RED + f"[!] Failed to flush CSV on exit: {exc}")

    # Generate filtered CSVs + HTML from whatever was collected in memory
    if GLOBAL_TRACKER is not None and GLOBAL_OUT_DIR and GLOBAL_SCAN_TS:
        elapsed      = (time.time() - GLOBAL_START_TIME) if GLOBAL_START_TIME else 0.0
        _, total_s, total_h, pattern_counts, denied_n, total_r, _ = GLOBAL_TRACKER.snapshot()
        folder_hits   = GLOBAL_TRACKER.folder_hits
        filename_hits = GLOBAL_TRACKER.filename_hits
        targets       = GLOBAL_TARGETS or []
        folders_only  = GLOBAL_FOLDERS_ONLY

        try:
            filtered = write_filtered_csvs(GLOBAL_OUT_DIR, folder_hits, GLOBAL_SCAN_TS)
            for fp in filtered:
                safe_print(Fore.GREEN + f"[✓] Filtered CSV:  {fp}")
        except Exception as exc:
            safe_print(Fore.RED + f"[!] Failed to write filtered CSVs: {exc}")

        try:
            html_path = generate_html_report(
                GLOBAL_OUT_DIR, folder_hits, filename_hits,
                pattern_counts, total_s, total_r,
                denied_n, total_h, elapsed,
                GLOBAL_SCAN_TS, targets, folders_only,
                scan_user=GLOBAL_SCAN_USER or "<anonymous>",
                all_dirs=GLOBAL_TRACKER.all_dirs,
                all_dirs_total=GLOBAL_TRACKER._all_dirs_total,
            )
            safe_print(Fore.GREEN + f"[✓] HTML report (partial): {html_path}")
        except Exception as exc:
            safe_print(Fore.RED + f"[!] Failed to generate HTML report: {exc}")

    raise SystemExit(code)

def signal_handler(sig, frame):
    safe_print(Fore.RED + "\n[!] Interrupted by user.")
    flush_and_exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ───────────── Folder-only threaded BFS walker ─────────────
def smb_walk_folders_threaded(root_unc: str,
                               tracker: FindingTracker,
                               debug: bool,
                               limiter: CreditLimiter,
                               conn_timeout: int,
                               dfs_qmax: int,
                               dfs_qsecs: int,
                               start_time: float,
                               sensitive_folders: set,
                               max_workers: int,
                               max_depth: int = 0,
                               flag_sensitive: bool = False):
    """BFS directory walk using a thread pool. Only probes folder ACLs - no file work.
    max_depth:      max levels below root to recurse (0 = unlimited).
    flag_sensitive: only add folder_hit entries for FIXED_SENSITIVE matches;
                    all other folders appear only in the All Directories table.
    """
    _custom = sensitive_folders or set()
    work_q  = queue.Queue()
    work_q.put((root_unc, 0))  # (path, depth)

    def process_dir():
        while True:
            dir_unc, depth = work_q.get()
            try:
                entries = smb_scandir_with_retry(
                    dir_unc, debug, tracker, limiter, conn_timeout, dfs_qmax, dfs_qsecs)
                if entries is None:
                    if not flag_sensitive:
                        tracker.add_dir(dir_unc, accessible=False, write=False)
                    continue

                # Confirmed readable - probe write access for this directory
                can_write = check_smb_folder_write(dir_unc, limiter, conn_timeout)

                # Sensitive-name check drives the terminal badge/folder_hit
                folder_name = dir_unc.rsplit("\\", 1)[-1] if "\\" in dir_unc else dir_unc
                is_sens, reason = is_sensitive_folder(folder_name, _custom)

                should_flag = is_sens or not flag_sensitive
                if not flag_sensitive:
                    tracker.add_dir(dir_unc, accessible=True, write=can_write)

                if should_flag:
                    label = reason if is_sens else folder_name
                    rw    = f"READ=YES WRITE={'YES' if can_write else 'NO'}"
                    safe_print(Fore.MAGENTA + f"[FOLDER] {label}: {dir_unc} [{rw}]")
                    tracker.add_folder_hit(dir_unc, folder_name, label, True, can_write)

                status_update(tracker, start_time)

                # Respect depth limit - depth 0 is the root itself
                if max_depth and depth >= max_depth:
                    if debug:
                        safe_print(Fore.YELLOW + f"[DEBUG] Depth limit ({max_depth}) reached at: {dir_unc}")
                    continue

                for ent in entries:
                    try:
                        if not ent.is_dir():
                            continue
                        if ent.name.lower() in EXCLUDED_DIRS:
                            continue
                    except Exception:
                        continue
                    work_q.put((dir_unc + "\\" + ent.name, depth + 1))
            finally:
                work_q.task_done()

    workers = [threading.Thread(target=process_dir, daemon=True) for _ in range(max_workers)]
    for w in workers:
        w.start()
    work_q.join()


# ───────────── Main SMB/DFS scan logic ─────────────
def scan_smb_target(unc: str, args, tracker: FindingTracker, start_time: float):
    unc = normalise_unc(unc)
    server, share, subpath = parse_unc_path(unc)

    resolve_host_with_fallback(server, args.dns, args.debug)
    smb_register_defaults(args.domain, args.user, args.password, args.dc, args.debug)

    targets = []
    if not share:
        safe_print(Fore.GREEN + f"[i] No share provided for \\\\{server}. Enumerating shares...")
        shares = smbclient_list_shares(server, args.domain, args.user, args.password, args.debug)
        if not shares:
            safe_print(Fore.RED + f"[!] No shares found or enumeration failed on \\\\{server}")
            return
        for sh in shares:
            targets.append(fr"\\{server}\{sh}")
    else:
        targets.append(fr"\\{server}\{share}" + (fr"\{subpath}" if subpath else ""))

    limiter = CreditLimiter(args.per_target)

    try:
        smb_user = fmt_user(args.domain, args.user)
        smbclient.register_session(server, username="" if smb_user == "<anonymous>" else smb_user, password=args.password or "")
    except Exception as e:
        if args.debug:
            safe_print(Fore.YELLOW + f"[DEBUG] register_session({server}) failed: {e}")

    for root_unc in targets:
        safe_print(Fore.GREEN + f"\n[i] DFS-aware SMB scan starting at: {root_unc}")
        status_update(tracker, start_time, force=True)

        custom_folders = {n.lower() for n in (args.custom_folders or [])}
        folders_only = getattr(args, "folders_only", False)

        max_depth      = getattr(args, "level", 0)
        flag_sensitive = getattr(args, "flag_sensitive", False)

        if folders_only:
            depth_note = f", depth limit: {max_depth}" if max_depth else ""
            sens_note  = ", sensitive-only flagging" if flag_sensitive else ""
            safe_print(Fore.CYAN + f"[i] {root_unc}: Folder-only mode - {args.threads} threads{depth_note}{sens_note}")
            smb_walk_folders_threaded(
                root_unc, tracker, args.debug,
                limiter, args.conn_timeout,
                args.dfs_quarantine_maxfails, args.dfs_quarantine_secs,
                start_time, custom_folders, args.threads,
                max_depth=max_depth,
                flag_sensitive=flag_sensitive,
            )
        else:
            candidates = list(smb_walk_files_with_dfs(
                root_unc, tracker, args.debug, args.max_size,
                limiter, args.conn_timeout,
                args.dfs_quarantine_maxfails, args.dfs_quarantine_secs,
                start_time,
                sensitive_folders=custom_folders,
                folders_only=False,
                max_depth=max_depth,
            ))
            safe_print(Fore.GREEN + f"[i] {root_unc}: {len(candidates)} candidate files queued for scanning")
            status_update(tracker, start_time, force=True)

            with ThreadPoolExecutor(max_workers=args.threads) as ex:
                fut_map = {
                    ex.submit(
                        scan_smb_file_unc,
                        f, args.max_read,
                        tracker, args.debug,
                        limiter, args.conn_timeout,
                        args.dfs_quarantine_maxfails, args.dfs_quarantine_secs
                    ): f
                    for f in candidates
                }
                for fut in as_completed(fut_map):
                    try:
                        fut.result()
                    except KeyboardInterrupt:
                        flush_and_exit(0)
                    except Exception as e:
                        safe_print(Fore.RED + f"[!] Worker error: {e}")
                        if args.debug:
                            safe_print(traceback.format_exc())
                    status_update(tracker, start_time)

# ───────────── HTML report assets (not f-strings – braces are literal) ─────────────
_REPORT_CSS = """
    :root {
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
      --green: #3fb950; --red: #f85149; --yellow: #d29922;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: 'Courier New', Courier, monospace; font-size: 14px; line-height: 1.6; padding: 24px; }
    h1 { color: var(--accent); font-size: 24px; margin-bottom: 4px; }
    h2 { color: var(--accent); font-size: 18px; margin: 24px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
    .subtitle { color: var(--muted); font-size: 12px; margin-bottom: 24px; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 8px; }
    .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 16px; }
    .stat-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }
    .stat-value { font-size: 28px; font-weight: bold; color: var(--accent); margin: 4px 0; }
    .stat-value.danger { color: var(--red); }
    .stat-value.warn { color: var(--yellow); }
    .stat-value.ok { color: var(--green); }
    table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 6px; overflow: hidden; border: 1px solid var(--border); }
    thead th { background: #1c2128; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
    tbody tr.folder-row { cursor: pointer; transition: background 0.15s; }
    tbody tr.folder-row:hover { background: #1c2128; }
    tbody td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; font-size: 13px; }
    .path-cell { word-break: break-all; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }
    .badge-confidential { background: #3d1a1a; color: #f85149; border: 1px solid #6a2020; }
    .badge-secret { background: #3a1a3d; color: #d2a8ff; border: 1px solid #5a2060; }
    .badge-internal { background: #2a2a1a; color: #e3b341; border: 1px solid #4a3a1a; }
    .badge-onedrive { background: #1a2a3a; color: #79c0ff; border: 1px solid #1a3a5a; }
    .badge-custom { background: #1a2a3d; color: #58a6ff; border: 1px solid #1a3a5a; }
    .access-yes { color: var(--red); font-weight: bold; }
    .access-no { color: var(--muted); }
    tr.acl-detail { display: none; }
    tr.acl-detail td { background: #0a0e13; padding: 16px 24px; }
    tr.acl-detail.open { display: table-row; }
    .acl-table { width: auto; background: transparent; border: none; margin-top: 8px; }
    .acl-table td { padding: 4px 16px 4px 0; border: none; font-size: 13px; color: var(--muted); }
    .acl-table td:first-child { color: var(--text); font-weight: bold; min-width: 160px; }
    .expand-icon { float: right; color: var(--muted); font-style: normal; font-size: 10px; }
    .filter-bar { margin-bottom: 12px; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    .filter-bar input { background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 6px 10px; border-radius: 4px; font-family: inherit; font-size: 12px; width: 260px; }
    .filter-bar input:focus { outline: none; border-color: var(--accent); }
    .filter-btn { background: var(--surface); border: 1px solid var(--border); color: var(--muted); padding: 5px 12px; border-radius: 4px; cursor: pointer; font-size: 11px; font-family: inherit; }
    .filter-btn:hover, .filter-btn.active { border-color: var(--accent); color: var(--accent); }
    .no-data { color: var(--muted); padding: 24px; text-align: center; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; }
    .account-block { background: #111820; border: 1px solid #1e3a5f; border-left: 3px solid var(--accent); border-radius: 6px; padding: 14px 18px; margin-bottom: 24px; }
    .account-label { color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 4px; }
    .account-user  { color: var(--accent); font-size: 17px; font-weight: bold; margin-bottom: 6px; letter-spacing: 0.02em; }
    .account-meta  { font-size: 13px; color: var(--text); margin-bottom: 6px; }
    .account-note  { font-size: 11px; color: var(--muted); font-style: italic; }
    footer { margin-top: 32px; color: var(--muted); font-size: 11px; border-top: 1px solid var(--border); padding-top: 12px; }
    a { color: var(--accent); }
"""

_REPORT_JS = r"""
    function toggleAcl(idx) {
      var detail = document.getElementById('acl-' + idx);
      var icon   = document.getElementById('row-' + idx).querySelector('.expand-icon');
      if (detail.classList.contains('open')) {
        detail.classList.remove('open');
        icon.textContent = '▶';
      } else {
        detail.classList.add('open');
        icon.textContent = '▼';
      }
    }
    var filterInput  = document.getElementById('folder-filter');
    var filterBtns   = document.querySelectorAll('.filter-btn[data-reason]');
    var activeReason = '';
    if (filterBtns.length) {
      filterBtns.forEach(function(btn) {
        btn.addEventListener('click', function() {
          if (activeReason === btn.dataset.reason) {
            activeReason = '';
            filterBtns.forEach(function(b) { b.classList.remove('active'); });
          } else {
            activeReason = btn.dataset.reason;
            filterBtns.forEach(function(b) { b.classList.remove('active'); });
            btn.classList.add('active');
          }
          applyFilters();
        });
      });
    }
    if (filterInput) { filterInput.addEventListener('input', applyFilters); }
    function applyFilters() {
      var text = filterInput ? filterInput.value.toLowerCase() : '';
      document.querySelectorAll('tr.folder-row').forEach(function(row) {
        var match = (!text || row.dataset.path.toLowerCase().includes(text))
                 && (!activeReason || row.dataset.reason === activeReason);
        row.style.display = match ? '' : 'none';
        if (!match) {
          var d = document.getElementById(row.id.replace('row-', 'acl-'));
          if (d) d.classList.remove('open');
        }
      });
    }
    var allDirFilter = document.getElementById('alldir-filter');
    if (allDirFilter) {
      allDirFilter.addEventListener('input', function() {
        var text = allDirFilter.value.toLowerCase();
        document.querySelectorAll('tr.alldir-row').forEach(function(row) {
          row.style.display = (!text || row.dataset.path.toLowerCase().includes(text)) ? '' : 'none';
        });
      });
    }
"""


def _html_badge(reason: str) -> str:
    r = reason.lower()
    if r.startswith("custom:"):
        css = "badge-custom"
    elif r == "onedrive":
        css = "badge-onedrive"
    elif r == "confidential":
        css = "badge-confidential"
    elif r == "secret":
        css = "badge-secret"
    elif r == "internal":
        css = "badge-internal"
    else:
        css = "badge-custom"
    return f'<span class="badge {css}">{html.escape(reason)}</span>'


def write_filtered_csvs(out_dir: str, folder_hits: list, scan_ts: str) -> list:
    """Write per-category CSVs for Confidential and Secret folder hits."""
    headers = ["timestamp_utc", "path", "folder_name", "reason", "read_access", "write_access"]
    filters = {
        "confidential": lambda h: h["reason"].lower() == "confidential",
        "secret":       lambda h: h["reason"].lower() == "secret",
    }
    created = []
    for label, predicate in filters.items():
        hits = [h for h in folder_hits if predicate(h)]
        if not hits:
            continue
        csv_path = os.path.join(out_dir, f"{label}_folders_{scan_ts}.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(headers)
            for h in hits:
                w.writerow([
                    h["ts"], h["path"], h["name"], h["reason"],
                    "YES" if h["read"] else "NO",
                    "YES" if h["write"] else "NO",
                ])
        created.append(csv_path)
    return created


def generate_html_report(out_dir: str, folder_hits: list, filename_hits: list,
                          pattern_counts: dict, total_s: int, total_r: int,
                          denied_n: int, total_h: int, elapsed: float,
                          scan_ts: str, targets: list, folders_only: bool,
                          scan_user: str = "<anonymous>",
                          all_dirs: list | None = None,
                          all_dirs_total: int = 0) -> str:
    date_str    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    targets_str = html.escape(", ".join(targets)) if targets else "N/A"
    user_esc    = html.escape(scan_user or "<anonymous>")

    def _fmt(secs: float) -> str:
        s = int(secs); h = s // 3600; m = (s % 3600) // 60; sc = s % 60
        return f"{h:02d}:{m:02d}:{sc:02d}" if h else f"{m:02d}:{sc:02d}"

    # ── Folder rows ──
    folder_rows_html = []
    for idx, hit in enumerate(folder_hits):
        p_esc  = html.escape(hit["path"])
        r_esc  = html.escape(hit["reason"])
        badge  = _html_badge(hit["reason"])
        r_cls  = "access-yes" if hit["read"]  else "access-no"
        w_cls  = "access-yes" if hit["write"] else "access-no"
        r_lbl  = "YES" if hit["read"]  else "NO"
        w_lbl  = "YES" if hit["write"] else "NO"
        r_desc = "&#x2714; folder listing permitted"  if hit["read"]  else "&#x2718; access denied"
        w_desc = "&#x2714; probe file create/delete succeeded" if hit["write"] else "&#x2718; write probe failed"
        ts_esc = html.escape(hit["ts"])
        folder_rows_html.append(f"""
        <tr class="folder-row" id="row-{idx}" data-path="{p_esc}" data-reason="{r_esc}" onclick="toggleAcl({idx})">
          <td class="path-cell">{p_esc} <i class="expand-icon">&#x25B6;</i></td>
          <td>{badge}</td>
          <td class="{r_cls}">{r_lbl}</td>
          <td class="{w_cls}">{w_lbl}</td>
          <td style="color:var(--muted);font-size:12px">{ts_esc}</td>
        </tr>
        <tr class="acl-detail" id="acl-{idx}">
          <td colspan="5">
            <strong style="color:var(--accent)">Access Probe Results</strong>
            <table class="acl-table">
              <tr><td>Path</td><td style="color:var(--text)">{p_esc}</td></tr>
              <tr><td>Match Reason</td><td>{badge}</td></tr>
              <tr><td>Tested As</td><td style="color:var(--accent)">{user_esc}</td></tr>
              <tr><td>Read Access</td><td class="{r_cls}">{r_desc}</td></tr>
              <tr><td>Write Access</td><td class="{w_cls}">{w_desc}</td></tr>
              <tr><td>Detected At</td><td>{ts_esc}</td></tr>
            </table>
          </td>
        </tr>""")

    if folder_rows_html:
        FIXED_SENSITIVE = {"Confidential", "Secret", "Internal", "OneDrive"}
        reasons = sorted(
            r for r in {h["reason"] for h in folder_hits}
            if r in FIXED_SENSITIVE or r.lower().startswith("custom:")
        )
        filter_btns  = "".join(
            f'<button class="filter-btn" data-reason="{html.escape(r)}">{html.escape(r)}</button>'
            for r in reasons
        )
        folder_section = f"""
  <div class="filter-bar">
    <input id="folder-filter" type="text" placeholder="Filter by path...">
    {filter_btns}
  </div>
  <table>
    <thead><tr>
      <th>Path</th><th>Reason</th><th>Read</th><th>Write</th><th>Detected At</th>
    </tr></thead>
    <tbody>{"".join(folder_rows_html)}</tbody>
  </table>"""
    else:
        folder_section = '<p class="no-data">No sensitive folders detected.</p>'

    # ── Filename hits section ──
    fname_section = ""
    if not folders_only and filename_hits:
        fname_rows = "".join(
            f'<tr><td class="path-cell">{html.escape(h["path"])}</td>'
            f'<td><span class="badge badge-custom">{html.escape(h["pattern"])}</span></td>'
            f'<td style="color:var(--muted);font-size:12px">{html.escape(h["ts"])}</td></tr>'
            for h in filename_hits
        )
        fname_section = f"""
  <h2>Sensitive Filenames <span style="color:var(--muted);font-size:14px;font-weight:normal">({len(filename_hits)} found)</span></h2>
  <table>
    <thead><tr><th>Path</th><th>Pattern</th><th>Detected At</th></tr></thead>
    <tbody>{fname_rows}</tbody>
  </table>"""

    # ── Pattern breakdown section ──
    patt_section = ""
    if not folders_only and pattern_counts and any(v > 0 for v in pattern_counts.values()):
        patt_rows = "".join(
            f'<tr><td>{html.escape(k)}</td>'
            f'<td style="color:var(--{"red" if v > 0 else "muted"})">{v}</td></tr>'
            for k, v in sorted(pattern_counts.items(), key=lambda x: (-x[1], x[0]))
        )
        patt_section = f"""
  <h2>Pattern Breakdown</h2>
  <table style="width:auto">
    <thead><tr><th>Pattern</th><th>Hits</th></tr></thead>
    <tbody>{patt_rows}</tbody>
  </table>"""

    # ── All Directories section ──
    all_dirs_section = ""
    if all_dirs:
        sensitive_lookup = {h["path"]: h for h in folder_hits}
        actual_total = all_dirs_total if all_dirs_total > 0 else len(all_dirs)
        truncated_note = (
            f'<p style="color:var(--muted);font-size:12px">'
            f'Showing first {len(all_dirs):,} of {actual_total:,} discovered directories.</p>'
        ) if actual_total > len(all_dirs) else ""

        all_dir_rows = []
        for d in all_dirs:
            p     = d["path"]
            p_esc = html.escape(p)
            acc   = d["accessible"]
            st_cls = "access-yes" if acc else "access-no"
            st_lbl = "&#x2714; Accessible" if acc else "&#x2718; Denied"

            if p in sensitive_lookup:
                hit   = sensitive_lookup[p]
                badge = _html_badge(hit["reason"])
                r_cls = "access-yes" if hit["read"]  else "access-no"
                w_cls = "access-yes" if hit["write"] else "access-no"
                r_lbl = "YES" if hit["read"]  else "NO"
                w_lbl = "YES" if hit["write"] else "NO"
            else:
                badge   = "&#x2014;"
                r_cls   = st_cls
                r_lbl   = "YES" if acc else "NO"
                wr      = d.get("write")
                w_cls   = ("access-yes" if wr else "access-no") if wr is not None else ""
                w_lbl   = ("YES" if wr else "NO") if wr is not None else "&#x2014;"

            all_dir_rows.append(
                f'<tr class="alldir-row" data-path="{p_esc}">'
                f'<td class="path-cell">{p_esc}</td>'
                f'<td class="{st_cls}">{st_lbl}</td>'
                f'<td>{badge}</td>'
                f'<td class="{r_cls}">{r_lbl}</td>'
                f'<td class="{w_cls}">{w_lbl}</td>'
                f'</tr>'
            )

        all_dirs_section = f"""
  <h2>All Directories <span style="color:var(--muted);font-size:14px;font-weight:normal">({actual_total:,} discovered)</span></h2>
  {truncated_note}
  <div class="filter-bar">
    <input id="alldir-filter" type="text" placeholder="Filter by path...">
  </div>
  <table>
    <thead><tr><th>Path</th><th>Status</th><th>Sensitive</th><th>Read</th><th>Write</th></tr></thead>
    <tbody>{"".join(all_dir_rows)}</tbody>
  </table>"""

    hit_class    = "danger" if total_h      else "ok"
    folder_class = "danger" if folder_hits  else "ok"
    fname_class  = "warn"   if filename_hits else "ok"

    readable_count = sum(1 for h in folder_hits if h["read"])
    writable_count = sum(1 for h in folder_hits if h["write"])
    total_folders  = len(folder_hits)
    rw_class = "danger" if writable_count else "ok"

    report = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>APMAC Audit Report &#8211; {html.escape(scan_ts)}</title>
  <style>{_REPORT_CSS}</style>
</head>
<body>
  <h1>&#x1F50D; APMAC Audit Report</h1>
  <div class="subtitle">
    Generated: {date_str} &nbsp;&bull;&nbsp; Target(s): {targets_str} &nbsp;&bull;&nbsp; Elapsed: {_fmt(elapsed)}
  </div>

  <div class="account-block">
    <div class="account-label">Scanning Account</div>
    <div class="account-user">{user_esc}</div>
    <div class="account-meta">
      <span>Folders readable:&nbsp;<strong style="color:var(--red)">{readable_count}</strong> / {total_folders}</span>
      <span style="margin-left:24px">Folders writable:&nbsp;<strong class="{rw_class}">{writable_count}</strong> / {total_folders}</span>
    </div>
    <div class="account-note">All access probe results in this report reflect the permissions held by the account above.</div>
  </div>

  <h2>Summary</h2>
  <div class="stats-grid">
    <div class="stat-card"><div class="stat-label">Files Scanned</div><div class="stat-value">{total_s:,}</div></div>
    <div class="stat-card"><div class="stat-label">Files Readable</div><div class="stat-value ok">{total_r:,}</div></div>
    <div class="stat-card"><div class="stat-label">Files Denied</div><div class="stat-value warn">{denied_n:,}</div></div>
    <div class="stat-card"><div class="stat-label">Content Hits</div><div class="stat-value {hit_class}">{total_h:,}</div></div>
    <div class="stat-card"><div class="stat-label">Sensitive Folders</div><div class="stat-value {folder_class}">{len(folder_hits):,}</div></div>
    <div class="stat-card"><div class="stat-label">Filename Hits</div><div class="stat-value {fname_class}">{len(filename_hits):,}</div></div>
  </div>

  {patt_section}

  <h2>{"Folder Scan Results" if folders_only else "Sensitive Folders"} <span style="color:var(--muted);font-size:14px;font-weight:normal">({len(folder_hits)} found &#8212; click row for ACL details)</span></h2>
  {folder_section}

  {all_dirs_section}

  {fname_section}

  <footer>
    APMAC v3 &mdash; Automated Privileged Material Acquisition Console &mdash;
    <a href="https://github.com/deannreid/APMAC">github.com/deannreid/APMAC</a>
  </footer>
  <script>{_REPORT_JS}</script>
</body>
</html>"""

    out_path = os.path.join(out_dir, f"APMAC_Report_{scan_ts}.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)
    return out_path


# ───────────── Args ─────────────
def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Scan SMB/DFS shares for sensitive patterns (DFS-aware) with multithreading + chunked CSV.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    p.add_argument("--share", action="append", default=[],
                   help=r"UNC target. Repeatable. Examples: \\server OR \\server\share OR \\domain\dfsroot\link\path")
    p.add_argument("--domain", default=None, help="SMB domain (optional).")
    p.add_argument("--user", default=None, help="SMB username (optional).")
    p.add_argument("--pass", dest="password", default=None, help="SMB password (omit to prompt if --user is set).")
    p.add_argument("--dns", default=None, help="DNS server IP for nslookup fallback + /etc/hosts injection (optional).")
    p.add_argument("--dc", default=None, help="Domain controller hostname (optional).")

    p.add_argument("--threads", type=int, default=20, help="Worker threads for file scanning.")
    p.add_argument("--per-target", type=int, default=4,
                   help="Max concurrent SMB ops per server/share (prevents SMB credit starvation).")
    p.add_argument("--conn-timeout", type=int, default=10,
                   help="SMB connect timeout seconds during DFS/referral attempts (reduces stalls).")

    p.add_argument("--dfs-quarantine-secs", type=int, default=120,
                   help="How long to skip a repeatedly failing DFS path.")
    p.add_argument("--dfs-quarantine-maxfails", type=int, default=3,
                   help="How many DFS failures before quarantining a path.")

    p.add_argument("--max-size", type=int, default=MAX_SIZE_BYTES_DEFAULT, help="Skip files larger than this (bytes).")
    p.add_argument("--max-read", type=int, default=512 * 1024,
                   help="Max bytes to read from SMB file for scanning (bytes). Lower helps credit pressure.")
    p.add_argument("--debug", action="store_true", help="Verbose debug output (each file scanned + findings list).")

    p.add_argument("--FoldersOnly", "-Fo", dest="folders_only", action="store_true",
                   help="Only scan for sensitive folder names; skip file content scanning.")
    p.add_argument("--FlagSensitive", "-Fs", dest="flag_sensitive", action="store_true",
                   help="Only flag/report folders whose names match the sensitive list "
                        "(Confidential, Secret, Internal, OneDrive, or -Cu names). "
                        "All folders are still traversed; non-matching folders appear only "
                        "in the All Directories table, not as flagged hits.")
    p.add_argument("--level", type=int, default=0, metavar="N",
                   help="Maximum folder depth to scan below the share root (0 = unlimited). "
                        "E.g. --level 2 stops after two directory levels.")
    p.add_argument("--Custom", "-Cu", dest="custom_folders", nargs="+", default=[], metavar="NAME",
                   help="Additional folder names to flag (e.g. -Cu Test1 Test2). Case-insensitive.")

    p.add_argument("--out-dir", default=None, metavar="PATH",
                   help="Output directory for the HTML report and all CSVs. "
                        "Default: ./APMAC_Audit-TIMESTAMP in the current directory. "
                        "Can be a local path or a UNC network share (e.g. \\\\server\\share\\reports).")
    p.add_argument("--out-csv", default="apmac_findings.csv",
                   help="CSV filename placed inside --out-dir (auto-splits into _partXXX.csv).")
    p.add_argument("--csv-max-rows", type=int, default=5000, help="Max rows per CSV part before rotating.")
    return p

def main():
    global GLOBAL_TRACKER, GLOBAL_CSV_WRITER, GLOBAL_START_TIME, GLOBAL_OUT_DIR, GLOBAL_SCAN_TS, GLOBAL_TARGETS, GLOBAL_FOLDERS_ONLY, GLOBAL_SCAN_USER

    args = build_arg_parser().parse_args()
    scan_ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%SZ')

    if args.user and args.password is None:
        args.password = getpass.getpass("SMB Password: ")

    print(Fore.CYAN + BANNER)
    print(Fore.GREEN + random.choice(BLURBS) + "\n")

    if not args.share:
        safe_print(Fore.RED + "[!] Provide at least one --share target.")
        raise SystemExit(1)

    out_dir = args.out_dir if args.out_dir else os.path.join(os.getcwd(), f"APMAC_Audit-{scan_ts}")
    os.makedirs(out_dir, exist_ok=True)
    safe_print(Fore.GREEN + f"[i] Output directory: {out_dir}")

    GLOBAL_OUT_DIR      = out_dir
    GLOBAL_SCAN_TS      = scan_ts
    GLOBAL_TARGETS      = list(args.share)
    GLOBAL_FOLDERS_ONLY = getattr(args, "folders_only", False)
    GLOBAL_SCAN_USER    = fmt_user(args.domain, args.user)

    csv_name = os.path.basename(args.out_csv) or "apmac_findings.csv"
    csv_path = os.path.join(out_dir, csv_name)
    csv_writer = ChunkedCSVWriter(csv_path, max_rows=args.csv_max_rows)
    GLOBAL_CSV_WRITER = csv_writer

    tracker = FindingTracker(pattern_names=list(patterns.keys()), debug=args.debug, csv_writer=csv_writer)
    GLOBAL_TRACKER = tracker

    start_time = time.time()
    GLOBAL_START_TIME = start_time

    status_update(tracker, start_time, force=True)

    try:
        for s in args.share:
            safe_print(Fore.GREEN + f"[i] Scanning SMB/DFS target: {s}")
            scan_smb_target(s, args, tracker, start_time)
    except KeyboardInterrupt:
        flush_and_exit(0)

    status_clear_hard()
    csv_writer.close()

    elapsed = time.time() - start_time
    _, total_s, total_h, pattern_counts, denied_n, total_r, _ = tracker.snapshot()
    folder_hits  = tracker.folder_hits
    filename_hits = tracker.filename_hits

    # ── Final Report ──────────────────────────────────────────────────────────
    W = 66  # inner width (between ║ and ║)

    def box_top():    safe_print(Fore.CYAN + "╔" + "═" * W + "╗")
    def box_mid():    safe_print(Fore.CYAN + "╠" + "═" * W + "╣")
    def box_bot():    safe_print(Fore.CYAN + "╚" + "═" * W + "╝")
    def box_title(t): safe_print(Fore.CYAN + "║" + Fore.WHITE + t.center(W) + Fore.CYAN + "║")
    def box_blank():  safe_print(Fore.CYAN + "║" + " " * W + "║")

    def box_kv(label: str, value: str, note: str = ""):
        lbl = f"  {label:<26}"
        val_note = value + (f"  {note}" if note else "")
        pad = W - len(lbl) - len(val_note)
        safe_print(Fore.CYAN + "║" + Fore.GREEN + lbl + Fore.YELLOW + val_note + " " * max(0, pad) + Fore.CYAN + "║")

    pct_readable = (100.0 * total_r / max(1, total_s)) if total_s else 0.0
    pct_denied   = (100.0 * denied_n / max(1, total_s)) if total_s else 0.0

    safe_print("")
    box_top()
    box_title("SCAN COMPLETE - SUMMARY")
    box_mid()
    box_blank()
    box_kv("Files Scanned",      f"{total_s:,}")
    box_kv("Files Readable",     f"{total_r:,}",    f"({pct_readable:.1f}%)")
    box_kv("Files Denied",       f"{denied_n:,}",   f"({pct_denied:.1f}%)")
    box_kv("Content Hits",       f"{total_h:,}")
    box_kv("Filename Hits",      f"{len(filename_hits):,}")
    box_kv("Sensitive Folders",  f"{len(folder_hits):,}")
    box_kv("Elapsed",            fmt_hms(elapsed))
    box_blank()

    # Pattern breakdown (two per row)
    if pattern_counts:
        box_mid()
        box_title("PATTERN BREAKDOWN")
        box_mid()
        items = sorted(pattern_counts.items(), key=lambda x: (-x[1], x[0]))
        pairs = [(f"{k}:", str(v)) for k, v in items]
        # render two columns
        for i in range(0, len(pairs), 2):
            left  = pairs[i]
            right = pairs[i + 1] if i + 1 < len(pairs) else ("", "")
            half  = W // 2
            left_cell  = f"  {left[0]:<22}{left[1]:>6}".ljust(half)
            right_cell = (f"  {right[0]:<22}{right[1]:>6}".ljust(half) if right[0] else " " * half)
            safe_print(Fore.CYAN + "║" + Fore.GREEN + left_cell[:26] + Fore.YELLOW + left_cell[26:half]
                       + Fore.GREEN + right_cell[:26] + Fore.YELLOW + right_cell[26:half] + Fore.CYAN + "║")
        box_blank()

    # Sensitive folders
    if folder_hits:
        box_mid()
        box_title("SENSITIVE FOLDERS")
        box_mid()
        for hit in folder_hits:
            rw  = f"READ={'YES' if hit['read'] else 'NO '}  WRITE={'YES' if hit['write'] else 'NO '}"
            tag = hit['reason']
            path = hit['path']
            avail = W - len(tag) - 6
            disp_path = path if len(path) <= avail else "…" + path[-(avail - 1):]
            pad1 = max(0, W - 4 - len(tag) - len(disp_path))
            safe_print(Fore.CYAN + "║" + Fore.MAGENTA + f"  [{tag}]  " + Fore.YELLOW + disp_path
                       + " " * pad1 + Fore.CYAN + "║")
            indent = len(tag) + 6
            pad2 = max(0, W - indent - len(rw))
            safe_print(Fore.CYAN + "║" + " " * indent + Fore.CYAN + rw + " " * pad2 + Fore.CYAN + "║")
        box_blank()

    # Filename hits
    if filename_hits:
        box_mid()
        box_title("SENSITIVE FILENAMES")
        box_mid()
        for hit in filename_hits:
            tag  = hit['pattern']
            path = hit['path']
            avail = W - len(tag) - 6
            disp_path = path if len(path) <= avail else "…" + path[-(avail - 1):]
            pad = max(0, W - 4 - len(tag) - len(disp_path))
            safe_print(Fore.CYAN + "║" + Fore.MAGENTA + f"  [{tag}]  " + Fore.YELLOW + disp_path
                       + " " * pad + Fore.CYAN + "║")
        box_blank()

    box_bot()
    safe_print("")

    # Generate filtered CSVs (Confidential + Secret folders)
    filtered = write_filtered_csvs(out_dir, folder_hits, scan_ts)
    for fp in filtered:
        safe_print(Fore.GREEN + f"[✓] Filtered CSV:  {fp}")

    # Generate HTML report
    folders_only = getattr(args, "folders_only", False)
    html_path = generate_html_report(
        out_dir, folder_hits, filename_hits,
        pattern_counts, total_s, total_r,
        denied_n, total_h, elapsed,
        scan_ts, args.share, folders_only,
        scan_user=fmt_user(args.domain, args.user),
        all_dirs=tracker.all_dirs,
        all_dirs_total=tracker._all_dirs_total,
    )
    safe_print(Fore.GREEN + f"[✓] HTML report:   {html_path}")

    csv_root, csv_ext = os.path.splitext(csv_path)
    if not csv_ext:
        csv_ext = ".csv"
    safe_print(Fore.YELLOW + f"[✓] Output dir:    {out_dir}")
    safe_print(Fore.YELLOW + f"[✓] CSV exported:  {csv_root}_partXXX{csv_ext}")

if __name__ == "__main__":
    main()
