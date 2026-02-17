#!/usr/bin/env python3
"""
process_scan.py - List open files for all processes, similar to lsof.
Reads directly from /proc — no external dependencies.

Usage:
    python process_scan.py                  # scan all processes
    python process_scan.py -p nc            # processes whose name contains 'nc'
    python process_scan.py -p nc --exact    # exact name match only
    python process_scan.py -p nc --conns    # also show network connections
    python process_scan.py --conns          # all processes + connections

Tip: run as root for full visibility across all processes.
"""

import argparse
import os
import pwd
import socket
import sys

# ---------------------------------------------------------------------------
# /proc/net TCP/UDP state codes
# ---------------------------------------------------------------------------
_SOCK_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT",  "03": "SYN_RECV",
    "04": "FIN_WAIT1",   "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE",       "08": "CLOSE_WAIT","09": "LAST_ACK",
    "0A": "LISTEN",      "0B": "CLOSING",
}


def _decode_ipv4(hex_addr):
    """Convert little-endian hex address '0100007F' -> '127.0.0.1'."""
    packed = bytes.fromhex(hex_addr)          # little-endian bytes
    return socket.inet_ntop(socket.AF_INET, packed[::-1])


def _decode_ipv6(hex_addr):
    """Convert /proc/net/tcp6 32-char hex address to standard IPv6 notation."""
    # Each 4-byte word is stored in little-endian order.
    words = [hex_addr[i:i+8] for i in range(0, 32, 8)]
    be_bytes = b"".join(bytes.fromhex(w)[::-1] for w in words)
    return socket.inet_ntop(socket.AF_INET6, be_bytes)


def _parse_net_file(path, proto):
    """
    Parse a /proc/net/{tcp,tcp6,udp,udp6} file.
    Returns a dict  inode -> "PROTO local_addr:port -> remote_addr:port [STATE]"
    """
    inode_map = {}
    try:
        with open(path) as fh:
            next(fh)                          # skip header
            for line in fh:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local_raw, rem_raw = parts[1], parts[2]
                state_hex          = parts[3].upper()
                inode              = parts[9]

                is_v6 = len(local_raw.split(":")[0]) == 32
                decode = _decode_ipv6 if is_v6 else _decode_ipv4

                l_ip,  l_port = local_raw.rsplit(":", 1)
                r_ip,  r_port = rem_raw.rsplit(":", 1)

                try:
                    l_addr = f"{decode(l_ip)}:{int(l_port, 16)}"
                    r_addr = f"{decode(r_ip)}:{int(r_port, 16)}"
                except Exception:
                    l_addr = local_raw
                    r_addr = rem_raw

                state = _SOCK_STATES.get(state_hex, state_hex)
                inode_map[inode] = f"{proto} {l_addr} -> {r_addr} [{state}]"
    except OSError:
        pass
    return inode_map


def build_socket_map():
    """Build a combined inode -> connection-string map from all /proc/net sources."""
    inode_map = {}
    for filename, proto in (
        ("/proc/net/tcp",  "TCP"),
        ("/proc/net/tcp6", "TCP6"),
        ("/proc/net/udp",  "UDP"),
        ("/proc/net/udp6", "UDP6"),
    ):
        inode_map.update(_parse_net_file(filename, proto))
    return inode_map


# ---------------------------------------------------------------------------
# /proc helpers
# ---------------------------------------------------------------------------

def get_pids():
    """Yield integer PIDs from /proc."""
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                yield int(entry)
    except OSError:
        pass


def proc_comm(pid):
    """Return the process name from /proc/<pid>/comm, or '' on error."""
    try:
        with open(f"/proc/{pid}/comm") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def proc_user(pid):
    """Return the username for the process owner, or the UID string."""
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])   # real UID
                    try:
                        return pwd.getpwuid(uid).pw_name
                    except KeyError:
                        return str(uid)
    except OSError:
        pass
    return "?"


def proc_open_fds(pid, socket_map):
    """
    Yield (fd_num, description) for each open file descriptor of pid.
    socket_map: inode -> connection string from build_socket_map().
    """
    fd_dir = f"/proc/{pid}/fd"
    try:
        fds = os.listdir(fd_dir)
    except OSError:
        yield ("?", "<access denied>")
        return

    for fd in sorted(fds, key=lambda x: int(x) if x.isdigit() else 0):
        fd_path = f"{fd_dir}/{fd}"
        try:
            target = os.readlink(fd_path)
        except OSError:
            continue

        if target.startswith("socket:["):
            inode = target[8:-1]              # strip 'socket:[' and ']'
            description = socket_map.get(inode, f"socket:[{inode}] (no match)")
        else:
            description = target              # regular file path, pipe, etc.

        yield (fd, description)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_table(rows, header):
    if not rows:
        print("  (no results)")
        return
    all_rows = [header] + rows
    widths = [max(len(str(r[i])) for r in all_rows) for i in range(len(header))]
    sep = "  "
    fmt = sep.join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*header))
    print("-" * (sum(widths) + len(sep) * (len(header) - 1)))
    for row in rows:
        print(fmt.format(*[str(c) for c in row]))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="List open files for processes (reads /proc directly, like lsof).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-p", "--process", metavar="NAME",
                        help="Filter by process name (substring match by default)")
    parser.add_argument("--exact", action="store_true",
                        help="Use exact name match instead of substring")
    parser.add_argument("--conns", action="store_true",
                        help="Include network connections (sockets)")
    parser.add_argument("--pids", action="store_true",
                        help="Show only matching process names and PIDs, no file details")
    args = parser.parse_args()

    socket_map = build_socket_map() if args.conns else {}

    header = ("PID", "PROCESS", "USER", "FD", "TYPE / PATH")
    rows = []

    for pid in get_pids():
        name = proc_comm(pid)
        if not name:
            continue

        # apply name filter
        if args.process:
            if args.exact:
                if name.lower() != args.process.lower():
                    continue
            else:
                if args.process.lower() not in name.lower():
                    continue

        user = proc_user(pid)

        if args.pids:
            rows.append((pid, name, user, "", ""))
            continue

        fds = list(proc_open_fds(pid, socket_map))

        for fd, description in fds:
            # skip pure socket entries unless --conns is set
            if not args.conns and description.startswith(("TCP", "TCP6", "UDP", "UDP6", "socket:")):
                continue
            rows.append((pid, name, user, fd, description))

    if args.process:
        label = f"exact '{args.process}'" if args.exact else f"matching '{args.process}'"
        print(f"\n[*] Processes {label} — {len({r[0] for r in rows})} PID(s), {len(rows)} entries\n")
    else:
        print(f"\n[*] All processes — {len({r[0] for r in rows})} PID(s), {len(rows)} entries\n")

    print_table(rows, header)
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
