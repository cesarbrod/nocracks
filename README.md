# nocracks — File Integrity Monitor

System-wide file integrity monitoring to detect unauthorized changes to
critical system folders and files — especially those commonly documented as
malware, ransomware, and persistence targets.

> **Educational use only.** This project is for learning systems security and
> defensive file-integrity monitoring. It is not a substitute for a professional
> endpoint-detection-and-response (EDR) solution, and it must not be used to
> monitor systems you do not own or have explicit authorization to administer.

## Why this exists

Malware and ransomware routinely modify a small set of well-known locations
to gain persistence, steal credentials, hide command-and-control traffic, or
encrypt user data. Examples:

- Shell/profile persistence: `~/.bashrc`, `~/.profile`, `/etc/profile.d`
- SSH backdoors: `/etc/ssh`, `~/.ssh/authorized_keys`
- Scheduled tasks: `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron`
- Credential files: `/etc/passwd`, `/etc/shadow`, `/etc/group`
- Traffic redirection: `/etc/hosts`
- Systemd/init persistence: `/etc/systemd/system`, `/etc/init.d`
- Binary replacement (rootkits): `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`
- Ransomware targets: `/home`, `/root`, `~/Desktop`, `~/Documents`, `~/Downloads`

This tool takes a **snapshot (baseline)** of those locations, then — on a
daily schedule — compares the current state against the baseline and produces
an **ALERT / WARNING report** of anything added, modified, removed, or newly
inaccessible without your direct consent.

## Usage

Run once to build the baseline, then daily (e.g. via cron) to check for changes.

### First run — create the snapshot

Run as root for full system-wide coverage:

```bash
sudo python3 file_monitor.py --snapshot
```

If run as a non-root user, only user-readable files are hashed; protected
system files are recorded as inaccessible and reported as warnings.

### Daily check — produce ALERT / WARNING report

```bash
sudo python3 file_monitor.py --check
```

### Automate with cron (daily)

```bash
sudo crontab -e
# example: every day at 09:00
0 9 * * * /usr/bin/python3 /opt/nocracks/file_monitor.py --check >> /var/log/nocracks.log 2>&1
```

### CLI options

| Option | Meaning |
|--------|---------|
| `--snapshot` | Create the baseline snapshot (first run) |
| `--check` | Compare current state vs baseline and report changes |
| `--paths PATH [PATH ...]` | Custom list of files/folders to monitor (overrides defaults) |
| `--excludes PATH [PATH ...]` | Custom list of paths to exclude (overrides defaults) |
| `--max-files N` | Maximum number of files to hash per run (default 50000) |

You must specify either `--snapshot` or `--check`, not both.

## Configuration

Default monitored paths (system-wide malware targets) live in
`DEFAULT_PATHS` at the top of `file_monitor.py`. Edit this list to add or
remove locations.

Default exclusions (noisy/transient files) live in `DEFAULT_EXCLUDES`.
Notably, `~/.bash_history` is excluded because it changes every session.

By default the baseline and reports are stored in:

- `/var/lib/file_monitor/` — when run as root (system-wide)
- `~/.file_monitor/` — fallback when run as a non-root user

Reports are written as dated JSON files under the `reports/` subdirectory.

## Severity classification

| Severity | Trigger |
|----------|---------|
| **ALERT** | Critical system/persistence files changed (`/etc/*`, SSH keys/authorized_keys, shell rc files, cron, hosts, autostart, systemd/init) |
| **WARNING** | User data folders changed, or a previously accessible file becomes inaccessible |

## Output

Each `--check` run prints a summary and writes a JSON report:

```
INTEGRITY CHECK REPORT
============================================================
Generated : 2026-11-15T09:00:00+00:00
Baseline  : 2026-11-14T08:00:00+00:00
Added     : 0
Modified  : 2
Removed   : 0
ALERTS    : 1
WARNINGS  : 1
Report    : /var/lib/file_monitor/reports/report_20261115_090000.json
============================================================

--- ALERTS (critical system files) ---
  [MODIFIED] /etc/crontab

--- WARNINGS (user data / other) ---
  [MODIFIED] /home/brod/Documents/sensitive.docx

[!] Changes detected. Review the full JSON report above.
```

## Requirements

- Python 3.6+ (standard library only — no external dependencies)

## Tutorial

See [`tutorial.md`](tutorial.md) for an in-depth explanation of why active file-integrity monitoring matters, a line-by-line walkthrough of the code, and recommended actions for each type of report response.

## License

GPL v3 or later. See [LICENSE](LICENSE) for the full text.
