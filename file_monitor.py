#!/usr/bin/env python3
"""
File Integrity Monitor
======================

Creates a snapshot (baseline) of critical system folders and files — focusing on
locations commonly documented as malware targets — and, on subsequent (daily)
runs, compares the current state against the baseline to produce ALERT and
WARNING reports for any file or folder modified without direct consent.

Designed to be run once to build the snapshot, then scheduled (e.g. via cron)
to run daily for change detection.

Usage:
    sudo python3 file_monitor.py --snapshot   # create initial baseline snapshot (system-wide)
    sudo python3 file_monitor.py --check      # compare against baseline and report (daily)

Run as root for full system coverage. Without root, only user-readable files are hashed;
inaccessible system files are reported as WARNINGS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Default paths commonly targeted by malware / ransomware / persistence.
# Each entry is a path to include in the snapshot. Directories are walked
# recursively (subject to MAX_FILES / exclusions); single files are hashed
# directly.
DEFAULT_PATHS: List[str] = [
    # Shell / profile persistence (all users)
    "/etc/profile",
    "/etc/profile.d",
    "/etc/bash.bashrc",
    "/etc/zsh/zshrc",
    # SSH server config / authorized_keys (credential theft / backdoor access)
    "/etc/ssh",
    "/root/.ssh",
    # Cron / scheduled tasks persistence (Linux)
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    # System passwd/shadow / group (credential targeting)
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    # Hosts file (redirection / C2 blocking bypass)
    "/etc/hosts",
    # Systemd / init persistence
    "/etc/systemd/system",
    "/etc/init.d",
    "/etc/rc.local",
    # Binaries / libraries (rootkit / binary replacement)
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    # Kernel modules / boot
    "/etc/modprobe.d",
    "/etc/modules-load.d",
    "/boot",
    # Common user data folders (ransomware targets) - all users
    "/home",
    "/root",
]

# Paths to skip entirely (noisy, transient, pseudo-filesystems).
DEFAULT_EXCLUDES: List[str] = [
    "/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp",
    "/var/lib/file_monitor",
    os.path.expanduser("~/.bash_history"),
]

MAX_FILES_PER_SNAPSHOT = 50000   # safety cap so a single run stays bounded
HASH_CHUNK_SIZE = 65536          # bytes read at a time when hashing

BASELINE_DIR_SYSTEM = "/var/lib/file_monitor"
BASELINE_DIR_USER = os.path.join(os.path.expanduser("~"), ".file_monitor")


def _writable_dir(candidate: str) -> bool:
    try:
        os.makedirs(candidate, exist_ok=True)
        test = os.path.join(candidate, ".write_test")
        with open(test, "w"):
            pass
        os.remove(test)
        return True
    except OSError:
        return False


def baseline_dir() -> str:
    return BASELINE_DIR_SYSTEM if _writable_dir(BASELINE_DIR_SYSTEM) else BASELINE_DIR_USER


BASELINE_FILE = os.path.join(baseline_dir(), "baseline.json")
REPORT_DIR = os.path.join(baseline_dir(), "reports")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_excluded(path: str, excludes: List[str]) -> bool:
    """Return True if *path* is under any excluded prefix."""
    norm = os.path.normpath(path)
    for exc in excludes:
        exc_norm = os.path.normpath(exc)
        if norm == exc_norm or norm.startswith(exc_norm + os.sep):
            return True
    return False


def hash_file(path: str) -> Optional[str]:
    """Return SHA-256 hex digest of *path*, or None if unreadable."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def stat_info(path: str) -> Dict:
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return {}
    return {
        "size": st.st_size,
        "mtime": st.st_mtime,
        "mode": oct(st.st_mode & 0o7777),
        "uid": st.st_uid,
        "gid": st.st_gid,
    }


def collect_entries(
    roots: List[str],
    excludes: List[str],
    max_files: int,
) -> Tuple[Dict[str, Dict], List[str]]:
    """Walk *roots* and return ({path: {sha256, stat}}, [inaccessible_paths])."""
    entries: Dict[str, Dict] = {}
    inaccessible: List[str] = []
    count = 0

    def add_file(path: str) -> None:
        nonlocal count
        if count >= max_files:
            return
        digest = hash_file(path)
        if digest is None:
            inaccessible.append(path)
            return
        entries[path] = {"sha256": digest, "stat": stat_info(path)}
        count += 1

    for root in roots:
        if not os.path.exists(root):
            continue
        if os.path.isfile(root):
            if not is_excluded(root, excludes):
                add_file(root)
            continue
        # directory: walk recursively
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # prune excluded directories in-place
            pruned = []
            for d in dirnames:
                full = os.path.join(dirpath, d)
                if is_excluded(full, excludes):
                    pruned.append(d)
                    continue
                try:
                    os.scandir(full)
                except PermissionError:
                    inaccessible.append(full)
                    pruned.append(d)
            for d in pruned:
                dirnames.remove(d)
            for name in filenames:
                full = os.path.join(dirpath, name)
                if is_excluded(full, excludes):
                    continue
                add_file(full)
                if count >= max_files:
                    break
            if count >= max_files:
                break

    return entries, inaccessible


def save_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def load_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


# ---------------------------------------------------------------------------
# Snapshot / Check
# ---------------------------------------------------------------------------

def create_snapshot(args: argparse.Namespace) -> int:
    roots = args.paths or DEFAULT_PATHS
    excludes = args.excludes or DEFAULT_EXCLUDES
    print(f"[*] Creating snapshot at {utc_now()}")
    print(f"[*] Roots: {len(roots)}  Excludes: {len(excludes)}  Max files: {args.max_files}")

    entries, inaccessible = collect_entries(roots, excludes, args.max_files)

    snapshot = {
        "created_at": utc_now(),
        "roots": roots,
        "excludes": excludes,
        "max_files": args.max_files,
        "file_count": len(entries),
        "inaccessible_count": len(inaccessible),
        "inaccessible": inaccessible,
        "entries": entries,
    }
    save_json(BASELINE_FILE, snapshot)
    print(f"[+] Snapshot saved to {BASELINE_FILE} ({len(entries)} files, {len(inaccessible)} inaccessible)")
    return 0


def classify_severity(path: str) -> str:
    """CRITICAL -> ALERT, user data -> WARNING."""
    low = path.lower()
    critical_markers = [
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
        "/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
        "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
        "/etc/hosts",
        ".ssh/authorized_keys", ".ssh/id_rsa", ".ssh/id_ed25519",
        ".bashrc", ".bash_profile", ".profile", ".zshrc",
        "autostart",
    ]
    for marker in critical_markers:
        if marker in low:
            return "ALERT"
    return "WARNING"


def run_check(args: argparse.Namespace) -> int:
    baseline = load_json(BASELINE_FILE)
    if baseline is None:
        print(f"[!] No baseline found at {BASELINE_FILE}. Run with --snapshot first.", file=sys.stderr)
        return 1

    roots = args.paths or baseline.get("roots", DEFAULT_PATHS)
    excludes = args.excludes or baseline.get("excludes", DEFAULT_EXCLUDES)
    max_files = args.max_files or baseline.get("max_files", MAX_FILES_PER_SNAPSHOT)

    print(f"[*] Checking integrity against baseline ({baseline.get('created_at')})")
    current, inaccessible = collect_entries(roots, excludes, max_files)

    old_entries: Dict[str, Dict] = baseline.get("entries", {})

    added: List[Tuple[str, Dict]] = []
    modified: List[Tuple[str, Dict, Dict]] = []   # path, old, new
    removed: List[Tuple[str, Dict]] = []

    old_paths = set(old_entries.keys())
    new_paths = set(current.keys())

    for path in sorted(new_paths - old_paths):
        added.append((path, current[path]))
    for path in sorted(old_paths - new_paths):
        removed.append((path, old_entries[path]))
    for path in sorted(old_paths & new_paths):
        old_e = old_entries[path]
        new_e = current[path]
        if old_e.get("sha256") != new_e.get("sha256") or old_e.get("stat") != new_e.get("stat"):
            modified.append((path, old_e, new_e))

    # Build report
    alerts: List[dict] = []
    warnings: List[dict] = []

    def record(severity: str, change_type: str, path: str, entry: Dict, old: Optional[Dict] = None) -> None:
        item = {
            "path": path,
            "change_type": change_type,   # added / modified / removed / inaccessible
            "severity": severity,
            "checked_at": utc_now(),
            "entry": entry,
            "old_entry": old,
        }
        if severity == "ALERT":
            alerts.append(item)
        else:
            warnings.append(item)

    for path, entry in added:
        record(classify_severity(path), "added", path, entry)
    for path, old_e, new_e in modified:
        record(classify_severity(path), "modified", path, new_e, old_e)
    for path, entry in removed:
        record(classify_severity(path), "removed", path, entry)

    # Inaccessible files (permission denied) — only flag if newly inaccessible
    old_inaccessible = set(baseline.get("inaccessible", []))
    for path in inaccessible:
        if path not in old_inaccessible:
            record("WARNING", "inaccessible", path, {"sha256": None, "stat": {}})

    # Sort by severity then path
    alerts.sort(key=lambda x: x["path"])
    warnings.sort(key=lambda x: x["path"])

    report = {
        "generated_at": utc_now(),
        "baseline_created_at": baseline.get("created_at"),
        "summary": {
            "added": len(added),
            "modified": len(modified),
            "removed": len(removed),
            "inaccessible_new": len([w for w in warnings if w["change_type"] == "inaccessible"]),
            "alerts": len(alerts),
            "warnings": len(warnings),
        },
        "alerts": alerts,
        "warnings": warnings,
    }

    os.makedirs(REPORT_DIR, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(REPORT_DIR, f"report_{stamp}.json")
    save_json(report_file, report)

    # Human-readable console output
    print("\n" + "=" * 60)
    print("INTEGRITY CHECK REPORT")
    print("=" * 60)
    print(f"Generated : {report['generated_at']}")
    print(f"Baseline  : {report['baseline_created_at']}")
    print(f"Added     : {len(added)}")
    print(f"Modified  : {len(modified)}")
    print(f"Removed   : {len(removed)}")
    print(f"ALERTS    : {len(alerts)}")
    print(f"WARNINGS  : {len(warnings)}")
    print(f"Report    : {report_file}")
    print("=" * 60)

    if alerts:
        print("\n--- ALERTS (critical system files) ---")
        for a in alerts:
            print(f"  [{a['change_type'].upper()}] {a['path']}")
    if warnings:
        print("\n--- WARNINGS (user data / other) ---")
        for w in warnings[:50]:
            print(f"  [{w['change_type'].upper()}] {w['path']}")
        if len(warnings) > 50:
            print(f"  ... and {len(warnings) - 50} more")

    if not added and not modified and not removed:
        print("\n[OK] No changes detected since baseline.")
    else:
        print("\n[!] Changes detected. Review the full JSON report above.")

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="File Integrity Monitor — snapshot and detect unauthorized changes.",
    )
    p.add_argument(
        "--snapshot",
        action="store_true",
        help="Create a baseline snapshot of critical files.",
    )
    p.add_argument(
        "--check",
        action="store_true",
        help="Compare current state against baseline and report changes.",
    )
    p.add_argument(
        "--paths",
        nargs="*",
        help="Custom list of files/folders to monitor (overrides defaults).",
    )
    p.add_argument(
        "--excludes",
        nargs="*",
        help="Custom list of paths to exclude.",
    )
    p.add_argument(
        "--max-files",
        type=int,
        default=MAX_FILES_PER_SNAPSHOT,
        help=f"Maximum number of files to hash per run (default {MAX_FILES_PER_SNAPSHOT}).",
    )
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.snapshot and args.check:
        parser.error("Use either --snapshot or --check, not both.")
    if not args.snapshot and not args.check:
        parser.error("Specify --snapshot (first run) or --check (daily run).")

    if os.geteuid() != 0:
        print("[!] Warning: not running as root. System-wide files may be inaccessible; "
              "run with sudo for full coverage.\n", file=sys.stderr)

    if args.snapshot:
        return create_snapshot(args)
    return run_check(args)


if __name__ == "__main__":
    sys.exit(main())
