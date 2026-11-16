# Running nocracks on Windows Server

nocracks has been written for **Debian-based Linux servers**. It assumes a
POSIX filesystem layout (`/etc`, `/bin`, `/sbin`, `/usr/bin`, `/home`,
`/root`, `/proc`, `/sys`, etc.), root-owned protected files, `os.stat`
metadata semantics, and cron for scheduling.

If you genuinely believe a Windows Server can be properly secured and want to
port nocracks to it, here are the things that would need to be implemented —
none of which exist in this project yet:

## Platform differences to address

1. **Filesystem paths**
   - Replace Linux paths (`/etc/passwd`, `/etc/shadow`, `/etc/hosts`,
     `/bin`, `/sbin`, `/etc/cron.*`, `/etc/systemd/system`, `/home`, `/root`)
   - with Windows equivalents (`C:\Windows\System32\config\SAM`,
     `C:\Windows\System32\drivers\etc\hosts`, `C:\Windows`,
     `C:\Program Files`, `C:\Users`, `C:\Windows\System32\Tasks`,
     registry hives such as `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
     etc.)

2. **Hashing and stat metadata**
   - The current `stat_info()` records Unix `uid`, `gid`, `mode`, `mtime`,
     `size`. On Windows you would need file owner (SID), ACLs, attributes
     (read-only, hidden, system), creation/access/modification timestamps, and
     alternate data streams.

3. **File access and locking**
   - Windows keeps many system files exclusively locked by the kernel or
     services. `open(path, "rb")` will fail with `sharing violations` on files
     that Linux would read freely. You would need to handle `ERROR_SHARING_VIOLATION`
     and possibly use Windows backup-read APIs or Volume Shadow Copy to snapshot
     locked files.

4. **Registry monitoring**
   - Much of Windows persistence lives in the registry (`Run` keys, services,
     WMI event consumers, scheduled tasks). A file-only monitor misses most
     Windows malware. You would need a registry change detector in addition to
     file hashing.

5. **Permissions model**
   - The script assumes root (`os.geteuid() == 0`) for full coverage. On
     Windows you would need to check for Administrator elevation and possibly
     `SeBackupPrivilege` / `SeRestorePrivilege` to read ACL-protected system
     hives and files.

6. **Scheduling**
   - Replace cron with Windows Task Scheduler for daily execution.

7. **Storage location**
   - Replace `/var/lib/file_monitor` with a location under
     `%PROGRAMDATA%\file_monitor` or `%APPDATA%\file_monitor`.

8. **Excluded paths**
   - Replace `/proc`, `/sys`, `/dev`, `/run`, `/tmp` with Windows equivalents
   - (`C:\Windows\Temp`, `C:\Users\*\AppData\Local\Temp`, pagefile, hibernation
   - file, etc.) and exclude NTFS metadata files (`$MFT`, `$LogFile`, etc.).

9. **Shell history exclusions**
   - Replace `.bash_history` exclusions with `PSReadLine` history,
     `ConsoleHost_history.txt`, etc.

## Honest disclaimer

This suggestion list is provided for someone who really believes Windows
Servers can be properly secured. The current nocracks codebase makes no
attempt to support Windows, and no Windows implementation is included or
planned here. If you want Windows coverage, you would effectively be writing a
new tool that borrows the baseline/compare concept from nocracks but targets a
completely different operating system with a completely different security
model.
