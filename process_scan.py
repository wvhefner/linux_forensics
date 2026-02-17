#!/usr/bin/env python3
"""
process_scan.py - List open files for all processes, similar to lsof.
Optionally filter by process name.

Usage:
    python process_scan.py                     # scan all processes
    python process_scan.py -p nc               # scan processes named 'nc'
    python process_scan.py -p nc --exact       # exact name match only
    python process_scan.py -p nc --conns       # include network connections
    python process_scan.py --conns             # all processes + connections

Requires: pip install psutil
Tip: run as root/admin for full visibility across all processes.
"""

import argparse
import sys
import psutil


def format_connection(conn):
    """Return a human-readable string for a network connection."""
    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "*"
    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "*"
    return f"{conn.type.name} {laddr} -> {raddr} [{conn.status}]"


def scan_process(proc, include_conns=False):
    """
    Yield rows of (pid, name, user, fd_or_type, path_or_detail) for a process.
    Silently skips entries that raise access/no-such-process errors.
    """
    try:
        pid  = proc.pid
        name = proc.name()
        try:
            user = proc.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            user = "<denied>"

        # --- open files ---
        try:
            for f in proc.open_files():
                fd   = str(f.fd) if f.fd != -1 else "?"
                mode = f.mode   if hasattr(f, "mode") else "?"
                yield (pid, name, user, f"fd={fd} mode={mode}", f.path)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            yield (pid, name, user, "<access denied>", "<open files not available>")

        # --- network connections (optional) ---
        if include_conns:
            try:
                for conn in proc.net_connections(kind="all"):
                    yield (pid, name, user, "conn", format_connection(conn))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                yield (pid, name, user, "<access denied>", "<connections not available>")

    except psutil.NoSuchProcess:
        pass


def match_process(proc, filter_name, exact):
    """Return True if the process name matches the filter."""
    try:
        name = proc.name()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return False
    if exact:
        return name.lower() == filter_name.lower()
    return filter_name.lower() in name.lower()


def print_table(rows, header):
    """Print rows as a fixed-width table."""
    if not rows:
        print("  (no results)")
        return

    all_rows = [header] + rows
    col_widths = [max(len(str(r[i])) for r in all_rows) for i in range(len(header))]

    sep = "  "
    fmt = sep.join(f"{{:<{w}}}" for w in col_widths)
    print(fmt.format(*header))
    print("-" * (sum(col_widths) + len(sep) * (len(header) - 1)))
    for row in rows:
        print(fmt.format(*[str(c) for c in row]))


def main():
    parser = argparse.ArgumentParser(
        description="List open files for processes (like lsof).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-p", "--process",
        metavar="NAME",
        help="Filter by process name (substring match by default)",
    )
    parser.add_argument(
        "--exact",
        action="store_true",
        help="Use exact name match instead of substring match",
    )
    parser.add_argument(
        "--conns",
        action="store_true",
        help="Also show network connections",
    )
    parser.add_argument(
        "--pids",
        action="store_true",
        help="Show only matching PIDs (no file details)",
    )
    args = parser.parse_args()

    header = ("PID", "PROCESS", "USER", "FD / TYPE", "PATH / CONNECTION")
    rows   = []

    processes = psutil.process_iter(attrs=["pid", "name"])

    for proc in processes:
        if args.process and not match_process(proc, args.process, args.exact):
            continue

        if args.pids:
            try:
                rows.append((proc.pid, proc.name(), "", "", ""))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            continue

        for row in scan_process(proc, include_conns=args.conns):
            rows.append(row)

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
