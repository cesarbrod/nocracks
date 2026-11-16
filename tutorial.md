# Tutorial — nocracks File Integrity Monitor

## 1. Why actively monitor your system

Malware, ransomware, and intruders rarely announce themselves. Instead, they quietly alter a small set of well-known locations to:

- **Gain persistence** — modify shell profiles (`~/.bashrc`, `/etc/profile.d`), cron jobs (`/etc/crontab`, `/var/spool/cron`), systemd units, or SSH `authorized_keys` so they run again after reboot.
- **Steal credentials** — read or modify `/etc/passwd`, `/etc/shadow`, `/etc/group`, SSH private keys.
- **Redirect traffic** — edit `/etc/hosts` to point your system at attacker-controlled domains or block security updates.
- **Replace binaries** — trojanize `/bin`, `/sbin`, `/usr/bin` binaries or kernel modules (`/etc/modprobe.d`).
- **Encrypt or destroy data** — target `/home`, `~/Documents`, `~/Desktop` with ransomware.

A single unauthorized change to any of these locations can mean your system is already compromised. Because these changes are silent, you need an **active, repeatable baseline**: snapshot the known-good state once, then compare against it daily. Any deviation is either expected (you made the change) or a potential intrusion.

This project (`nocracks`) automates exactly that workflow: it hashes critical files, stores a baseline, and on each subsequent run reports every added, modified, removed, or newly inaccessible file as an **ALERT** (critical system/persistence files) or **WARNING** (user data / other).

> **Educational use only.** This project is for learning systems security and defensive file-integrity monitoring. It is not a substitute for a professional endpoint-detection-and-response (EDR) solution, and it must not be used to monitor systems you do not own or have explicit authorization to administer.

---

## 2. What the code does — line by line

The program is a single file, `file_monitor.py` (469 lines). It uses only the Python standard library.

### 1–20 — Module docstring and usage

Documents purpose (baseline + daily change detection), intended schedule (once for snapshot, daily for check), and that root is needed for full coverage.

### 22–31 — Imports

Standard-library imports only: `argparse` (CLI), `hashlib` (SHA-256), `json` (baseline/reports), `os`/`sys` (filesystem/exit), `datetime` (timestamps), `pathlib`, `typing` (type hints). No external dependencies.

### 37–83 — `DEFAULT_PATHS`

The default list of system locations commonly targeted by malware, grouped by threat type:

| Group | Paths | Why monitored |
|-------|-------|---------------|
| Shell/profile persistence | `/etc/profile`, `/etc/profile.d`, `/etc/bash.bashrc`, `/etc/zsh/zshrc` | Attackers insert malicious commands executed on login |
| SSH | `/etc/ssh`, `/root/.ssh` | Backdoor SSH config or steal host/user keys |
| Cron/scheduled tasks | `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron` | Persistence via scheduled execution |
| Credential files | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` | Credential theft or account manipulation |
| Network redirection | `/etc/hosts` | C2 redirection or blocking security sites |
| Systemd/init persistence | `/etc/systemd/system`, `/etc/init.d`, `/etc/rc.local` | Boot-time persistence |
| Binaries/libraries | `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin` | Binary replacement / rootkits |
| Kernel modules/boot | `/etc/modprobe.d`, `/etc/modules-load.d`, `/boot` | Kernel-level persistence |
| User data (ransomware targets) | `/home`, `/root` | Data encryption / exfiltration targets |

Edit this list to add or remove monitored locations.

### 85–98 — `DEFAULT_EXCLUDES` and `EXCLUDED_BASENAMES`

- `DEFAULT_EXCLUDES`: noisy or dangerous filesystem trees to skip entirely (`/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp`, `/var/lib/file_monitor`).
- `EXCLUDED_BASENAMES`: filenames skipped in *any* directory — shell history files (`.bash_history`, `.zsh_history`, `.sh_history`, `.lesshst`, `.python_history`) that change every session and would otherwise cause false alarms.

### 100–101 — Limits

- `MAX_FILES_PER_SNAPSHOT = 50000`: safety cap so a single run stays bounded.
- `HASH_CHUNK_SIZE = 65536`: bytes read per chunk when hashing (keeps memory low for large files).

### 103–124 — Baseline/report storage locations

- `BASELINE_DIR_SYSTEM = "/var/lib/file_monitor"` (used when run as root).
- `BASELINE_DIR_USER = ~/.file_monitor` (fallback for non-root).
- `_writable_dir()` tests whether a directory can be created/written; `baseline_dir()` picks the system dir if writable, otherwise the user dir.
- `BASELINE_FILE` and `REPORT_DIR` point to `baseline.json` and the `reports/` subdirectory under whichever baseline dir is active.

### 131–132 — `utc_now()`

Returns the current UTC time as an ISO-8601 string for timestamps in snapshots and reports.

### 135–144 — `is_excluded()`

Returns `True` if a path is under any `DEFAULT_EXCLUDES` prefix **or** its basename is in `EXCLUDED_BASENAMES`. This makes `.bash_history` exclusion work for *every* user, not just the current user.

### 147–156 — `hash_file()`

Reads a file in binary chunks and returns its SHA-256 hex digest, or `None` if the file is unreadable (permissions, missing, etc.).

### 159–170 — `stat_info()`

Calls `os.stat(follow_symlinks=False)` and returns a dict with size, mtime, mode, uid, gid. Used alongside the hash to detect permission/metadata changes even if content is identical.

### 173–227 — `collect_entries()`

The core scanner. Walks every root in `DEFAULT_PATHS`:

- Skips roots that don't exist.
- Hashes single-file roots directly.
- For directories, walks recursively with `os.walk(followlinks=False)`.
- Prunes excluded directories in-place (and records any it can't even `scandir` as inaccessible).
- Skips excluded filenames and history basenames.
- Stops at `MAX_FILES_PER_SNAPSHOT` to avoid runaway runs.
- Returns `(entries_dict, inaccessible_list)` where each entry maps path → `{sha256, stat}`.

### 230–241 — `save_json()` / `load_json()`

Small helpers to read/write JSON files safely (missing or malformed JSON returns `None`).

### 248–272 — `create_snapshot()`

The `--snapshot` path:
1. Collects current entries and inaccessible files.
2. Writes `baseline.json` with created time, roots, excludes, counts, and entries.
3. Prints how many files were hashed and how many were inaccessible.
4. **Lists each inaccessible file** so you know what root couldn't see (usually permission-related; fix by running as root).

### 275–290 — `classify_severity()`

Decides ALERT vs WARNING for a changed path. Paths containing critical markers (`/etc/passwd`, `/etc/shadow`, cron dirs, `/etc/hosts`, SSH keys/authorized_keys, shell rc files, autostart) return `"ALERT"`; everything else returns `"WARNING"`.

### 293–410 — `run_check()`

The `--check` path:
1. Loads the baseline; errors if none exists.
2. Collects current state (`collect_entries`).
3. Compares old vs new path sets:
   - **added**: in current, not in baseline
   - **removed**: in baseline, not in current
   - **modified**: in both, but sha256 or stat differs
4. Flags **newly inaccessible** files (were readable before, now not) as WARNING.
5. Classifies each change via `classify_severity()` into `alerts` or `warnings`.
6. Writes a dated JSON report to `reports/report_YYYYMMDD_HHMMSS.json`.
7. Prints a human-readable summary: counts of added/modified/removed, ALERTS, WARNINGS, and lists them.

### 417–447 — `build_parser()`

Defines CLI flags: `--snapshot`, `--check`, `--paths`, `--excludes`, `--max-files`.

### 450–469 — `main()`

Validates that exactly one of `--snapshot`/`--check` is given. Warns if not running as root (system files may be inaccessible). Dispatches to `create_snapshot()` or `run_check()` and exits with its return code.

---

## 3. Recommended actions based on responses

### Run 1 — `sudo python3 file_monitor.py --snapshot`

| Observation | Meaning | Action |
|-------------|---------|--------|
| Snapshot saved, `0 inaccessible` | Full coverage achieved | Schedule daily `--check` via cron |
| Snapshot saved, `N inaccessible` | Some files unreadable (likely running as non-root, or protected files) | Re-run with `sudo` for full system coverage; or add those paths to `--excludes` if intentional |

### Daily run — `sudo python3 file_monitor.py --check`

#### `[OK] No changes detected since baseline.`

- **Meaning:** Nothing monitored has changed since the snapshot.
- **Action:** No action required. Continue daily monitoring.

#### ALERTS printed (critical system files)

Example:
```
--- ALERTS (critical system files) ---
  [MODIFIED] /etc/crontab
  [ADDED] /etc/systemd/system/evil.service
```

- **Meaning:** A persistence- or credential-related file changed without your consent. High probability of compromise.
- **Action:**
  1. **Do not panic; do not reboot yet** (rebooting may destroy volatile evidence).
  2. Open the full JSON report referenced at the end of the output and compare `old_entry` vs `entry` (hash, size, mtime, mode, uid/gid).
  3. Verify whether you (or an authorized admin/script) made the change. If not:
     - Isolate the host from the network.
     - Investigate the file contents and related logs (`/var/log/auth.log`, `/var/log/syslog`, journalctl).
     - Restore the file from a known-good backup or reinstall the package (`apt-get install --reinstall <package>` on Debian/Ubuntu).
     - Remove any unknown cron jobs, systemd units, or SSH keys.
     - Consider the host compromised; rotate credentials (SSH keys, user passwords) that were exposed on it.
  4. Once remediated, take a fresh baseline: `sudo python3 file_monitor.py --snapshot`.

#### WARNINGS printed (user data / other)

Example:
```
--- WARNINGS (user data / other) ---
  [MODIFIED] /home/brod/Documents/sensitive.docx
  [INACCESSIBLE] /root/.ssh/id_rsa
```

- **Meaning:** User data changed, or a file became unreadable. Lower severity but still worth verifying.
- **Action:**
  1. Confirm the change was intentional (you or a backup/sync tool edited the file).
  2. For `INACCESSIBLE`: if you expected root access, re-run with `sudo`; otherwise investigate permission changes.
  3. If unintended, restore from backup and scan for ransomware indicators.

#### Baseline missing

- **Meaning:** `--check` was run before `--snapshot`.
- **Action:** Run `sudo python3 file_monitor.py --snapshot` first, then schedule `--check` daily.

---

## 4. Automating daily checks (cron)

As root:

```bash
sudo crontab -e
```

Add:

```cron
0 9 * * * /usr/bin/python3 /opt/nocracks/file_monitor.py --check >> /var/log/nocracks.log 2>&1
```

This runs every day at 09:00 and appends output to `/var/log/nocracks.log`. Review the log or the JSON reports under `/var/lib/file_monitor/reports/` regularly.

---

## 5. Customizing

Edit the top of `file_monitor.py`:

- `DEFAULT_PATHS` — add folders/files you want watched.
- `DEFAULT_EXCLUDES` — add directory prefixes to skip entirely.
- `EXCLUDED_BASENAMES` — add filenames to skip in any directory.
- `MAX_FILES_PER_SNAPSHOT` — raise or lower the safety cap.

Or override at runtime:

```bash
sudo python3 file_monitor.py --snapshot --paths /etc /home --max-files 100000
sudo python3 file_monitor.py --check --excludes /var/log
```

---

## 6. License

GPL v3 or later. See [LICENSE](LICENSE) for the full text.
