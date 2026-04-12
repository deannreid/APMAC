# 🧠 APMAC v3

**Automated Privileged Material Acquisition Console**

DFS-aware SMB scanner for finding:

* 🔐 credentials in files
* 🗂️ sensitive filenames
* 📁 writable / exposed folders

Built for large enterprise shares where DFS and permissions are messy.

---

## ⚙️ What it does

* 🌐 Traverses SMB + DFS paths safely
* 🔍 Scans files for credential patterns
* 🧾 Flags sensitive filenames (keys, backups, dumps)
* 📁 Identifies sensitive folders
* ✏️ Checks folder permissions (read/write)
* 🔁 Handles DFS failures and unstable paths
* 📊 Outputs results to chunked CSV

---

## 🚀 Key capabilities

* ⚡ Multi-threaded scanning
* 🧠 Per-target SMB throttling (prevents credit exhaustion)
* 🔄 DFS retry + quarantine logic
* 📉 Partial file reads (performance)
* 🚫 Skips binary junk
* 🖥️ SSH-safe progress output

---

## 📦 Installation

```bash id="tsw2s1"
pip install smbprotocol smbclient colorama
```

Optional (for share enumeration):

```bash id="6p9q9o"
sudo apt install smbclient
```

---

## ▶️ Usage

### Basic

```bash id="0hmpnb"
python3 apmac.py --share \\server\share --user DOMAIN\\user
```

---

### Multiple targets

```bash id="ru3l9d"
python3 apmac.py \
  --share \\server1 \
  --share \\server2\finance \
  --user DOMAIN\\user
```

---

### DFS root (auto-enumerates shares)

```bash id="sj4rr1"
python3 apmac.py --share \\domain.local
```

---

### ⚡ Folder-only mode (fast wins)

```bash id="0l7y2k"
python3 apmac.py --share \\server\share -Fo
```

* 🚫 skips file scanning
* 📁 only checks folders
* ✏️ reports write access

---

### 🎯 Custom sensitive folders

```bash id="j1x4os"
python3 apmac.py --share \\server -Fo -Cu Finance HR Legal
```

---

## 🔧 Important flags

| Flag              | Description                  |
| ----------------- | ---------------------------- |
| `--share`         | Target UNC path (repeatable) |
| `--user / --pass` | SMB credentials              |
| `--domain`        | Domain                       |
| `--threads`       | Worker threads               |
| `--per-target`    | SMB concurrency limit        |
| `--max-read`      | Bytes read per file          |
| `--max-size`      | Skip large files             |
| `-Fo`             | Folder-only mode             |
| `-Cu`             | Custom folder names          |
| `--debug`         | Verbose output               |

---

## 📊 Output

### 📁 CSV (auto-split)

```id="y0c8qj"
apmac_findings_part001.csv
apmac_findings_part002.csv
```

---

### 📌 Row types

* 🔍 `FINDING` → regex match in file
* 🧾 `FILENAME_HIT` → sensitive filename
* 📁 `FOLDER_HIT` → folder + permissions
* 🚫 `DENIED` → access denied

---

## 🧪 Typical workflow

```bash id="4z0e5y"
# 1. Quick sweep for writable folders
python3 apmac.py --share \\corp.local -Fo

# 2. Scan interesting areas
python3 apmac.py --share \\corp.local\finance --user user

# 3. Add business-specific folders
python3 apmac.py --share \\corp.local -Fo -Cu Payroll Legal
```

---

## ⚠️ Notes

* 🔑 Requires valid SMB access
* 📊 Large scans = multiple CSV parts
* 🌐 DFS paths can be unstable (handled automatically)

---

## 👨‍💻 Author
Author: Dean
GitHub: https://github.com/deannreid/APMAC
