# APMAC Secure Runner

Automates monthly APMAC scans using encrypted AD credentials.  
Two scripts - run `runner_setup.py` once to configure, then `runner.py` is called automatically by the scheduler.

---

## Files

| File                 | Purpose                                          |
| -------------------- | ------------------------------------------------ |
| `runner_setup.py`    | Interactive setup wizard - run once              |
| `runner.py`          | Automated executor - called by scheduler         |
| `runner_config.json` | Scan targets and options (plaintext, no secrets) |
| `runner.cred`        | Encrypted AD password                            |
| `runner.key`         | AES encryption key - **Linux only**              |
| `runner.log`         | Execution log, appended on each run              |

---

## Prerequisites

- Python 3.10+
- All APMAC dependencies installed (`pip install -r requirements.txt`)
- On Linux: `cryptography` package (already required by APMAC via `smbprotocol`)
- On Windows: run `runner_setup.py` as **Administrator** to register the Task Scheduler job and apply ACL hardening

---

## Setup

### Windows

```powershell
# Run as Administrator (required for Task Scheduler registration + icacls)
python runner_setup.py
```

### Linux

```bash
# Recommended: create a dedicated low-privilege service account
sudo useradd -r -s /bin/false svc_apmac

# Run setup as that account
sudo -u svc_apmac python3 runner_setup.py
```

The wizard walks through four steps:

1. **AD Credentials** - domain, username, password (hidden input). A round-trip encryption self-test runs before anything is written to disk.
2. **Scan Targets** - one UNC share per line.
3. **Scan Options** - folders-only mode, custom folder names, output directory, DNS server, domain controller, thread count.
4. **Schedule** - day of month and hour; registers the job automatically or prints the manual command.

---

## Platform differences

|                     | Windows                                      | Linux                                         |
| ------------------- | -------------------------------------------- | --------------------------------------------- |
| **Encryption**      | Windows DPAPI (`CryptProtectData`)           | AES-256-GCM using `runner.key`                |
| **Key management**  | OS-managed, bound to the machine             | Random 32-byte key in `runner.key`            |
| **File hardening**  | `icacls` - SYSTEM + Administrators read-only | `chmod 600` on `runner.cred` and `runner.key` |
| **Scheduling**      | Windows Task Scheduler (`schtasks`)          | `crontab`                                     |
| **Runs as**         | SYSTEM                                       | The user who ran `runner_setup.py`            |
| **Who can decrypt** | Any process on this machine                  | Only the owning user on this machine          |

---

## Credential storage

### Windows - DPAPI (machine-scoped)

The AD password is encrypted using the Windows Data Protection API with the `CRYPTPROTECT_LOCAL_MACHINE` flag.  
Any process running on **this machine** can decrypt it - no master password is required.  
The `runner.cred` file ACL is locked to SYSTEM and Administrators via `icacls`, so standard users cannot read the blob even though DPAPI would allow it.

Decryption will fail if:
- The machine is re-imaged (DPAPI keys are regenerated)
- The `runner.cred` file is copied to a different machine

**Fix:** re-run `runner_setup.py` after any of the above.

### Linux - AES-256-GCM + key file

A random 32-byte AES key is generated during setup and saved to `runner.key` (`chmod 600`).  
The password is encrypted with AES-256-GCM; the 12-byte nonce is prepended to the ciphertext in `runner.cred`.  
Security depends entirely on file permissions - only the owning user can read the key.

The cron job **must run as the same user** that ran `runner_setup.py`, otherwise decryption will fail with a permission error on `runner.key`.

Decryption will fail if:
- `runner.key` is deleted or replaced
- The job is run as a different user
- The files are moved to a different machine (the key travels with them, so keep `runner.key` and `runner.cred` together and restrict access appropriately)

**Fix:** re-run `runner_setup.py` as the correct user.

---

## Scheduling

### Windows - Task Scheduler

Setup registers a task named `APMAC_Monthly_Audit` that runs as SYSTEM at the configured day and time.  
To register manually (run as Administrator):

```powershell
schtasks /create /f /tn "APMAC_Monthly_Audit" `
  /tr "\"C:\Python313\python.exe\" \"R:\APMAC\runner.py\"" `
  /sc MONTHLY /d 1 /st 02:00 /ru SYSTEM /rl HIGHEST
```

To view or remove the task:

```powershell
schtasks /query /tn "APMAC_Monthly_Audit"
schtasks /delete /tn "APMAC_Monthly_Audit" /f
```

### Linux - crontab

Setup writes an entry to the current user's crontab.  
To register manually:

```bash
crontab -e
```

Add:

```
0 2 1 * *  "/usr/bin/python3" "/opt/apmac/runner.py"
```

This example runs at 02:00 on the 1st of each month. Adjust the path to match your installation.

To view or remove the entry:

```bash
crontab -l               # view
crontab -e               # edit to remove
```

---

## Manual test

```bash
python runner.py
# or
python3 runner.py
```

Output streams to both stdout and `runner.log`. The password is redacted in all log output.

---

## Log format

Each run appends to `runner.log`:

```
2026-05-01 02:00:01  INFO      ============================================================
2026-05-01 02:00:01  INFO      APMAC Monthly Runner - 2026-05-01 02:00:01 UTC
2026-05-01 02:00:01  INFO      Platform: Windows
2026-05-01 02:00:01  INFO      Account:  CORP\svc_apmac
2026-05-01 02:00:01  INFO      Shares:   \\corp.local\DFS
2026-05-01 02:00:01  INFO      Credentials decrypted OK.
2026-05-01 02:00:01  INFO      Command:  ... --pass ***  ...
2026-05-01 02:00:01  INFO      [APMAC] [i] Output directory: R:\APMAC\APMAC_Audit-20260501_020001Z
...
2026-05-01 02:03:44  INFO      APMAC finished OK  (elapsed 00:03:43, exit 0)
2026-05-01 02:03:44  INFO      ============================================================
```

ANSI colour codes are stripped before writing so the log file is clean plain text.

---

## Troubleshooting

| Symptom                             | Likely cause                                              | Fix                                                             |
| ----------------------------------- | --------------------------------------------------------- | --------------------------------------------------------------- |
| `CryptUnprotectData failed`         | Machine re-imaged or wrong machine (Windows)              | Re-run `runner_setup.py`                                        |
| `runner.key not found`              | Key file deleted or wrong directory (Linux)               | Re-run `runner_setup.py`                                        |
| `Permission denied` on `runner.key` | Cron running as wrong user (Linux)                        | Ensure crontab is registered under the same user that ran setup |
| `Config not found`                  | `runner_config.json` missing                              | Re-run `runner_setup.py`                                        |
| `APMAC exited with code 1`          | Bad credentials, unreachable share, or missing dependency | Check `runner.log` for the `[APMAC]` lines around the failure   |
| Task Scheduler job not appearing    | Setup not run as Administrator                            | Re-run `runner_setup.py` as Administrator                       |

---

## Re-running setup

Running `runner_setup.py` again overwrites `runner_config.json`, `runner.cred`, and (on Linux) `runner.key`, and re-registers the schedule.  
No manual cleanup is needed.
