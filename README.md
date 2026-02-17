# 🔍 Linux Forensics

> A growing collection of Python scripts for Linux process and system forensics.
> No external dependencies — everything reads directly from the kernel via `/proc`.

---

## Scripts

### `process_scan.py` — Open File Scanner (lsof clone)

Enumerate all running processes and their open file descriptors by reading `/proc` directly.
Supports filtering by process name, network connection inspection, and more.

**Features**
- Lists every open file descriptor per process (files, pipes, devices, sockets)
- Resolves socket inodes against `/proc/net/tcp`, `tcp6`, `udp`, `udp6` to show real connection details
- Filter by process name — substring or exact match
- Resolves UIDs to usernames via `/etc/passwd`
- Zero dependencies — pure Python standard library

**Usage**

```bash
# Scan all processes and list open files
sudo python3 process_scan.py

# Find all processes whose name contains 'nc' (e.g. netcat)
sudo python3 process_scan.py -p nc

# Exact name match
sudo python3 process_scan.py -p nc --exact

# Include network connections (TCP/UDP sockets)
sudo python3 process_scan.py -p nc --conns

# Just list matching PIDs
sudo python3 process_scan.py -p python --pids
```

**Example output**

```
[*] Processes matching 'nc' — 1 PID(s), 3 entries

PID    PROCESS  USER  FD  TYPE / PATH
--------------------------------------------------------------
14532  nc       root  0   /dev/pts/1
14532  nc       root  1   /dev/pts/1
14532  nc       root  3   TCP 0.0.0.0:4444 -> 0.0.0.0:0 [LISTEN]
```

---

## Requirements

- Linux (relies on `/proc`)
- Python 3.6+
- Run as **root** for full visibility across all processes

---

