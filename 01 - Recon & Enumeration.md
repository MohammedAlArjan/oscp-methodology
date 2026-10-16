---
tags: [methodology, recon, enumeration]
---

# 01 — Recon & Enumeration

> Back to [[00 - Index (MOC)]]. Enumeration wins boxes. Be thorough, take notes per service, always re-scan after finding new access.

## Setup
```bash
export IP=10.10.x.x
export LHOST=$(ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
mkdir -p ~/HTB/<box>/{nmap,loot,www,exploits}; cd ~/HTB/<box>
```
⚠️ Always confirm `$LHOST` is **tun0** — wrong IP = "exploit ran, no shell." (Lesson learned repeatedly.)

---

## Port scanning — the right order
```bash
# 1) Fast full TCP — NEVER trust the top-1000 default
nmap -p- --min-rate 5000 -oN nmap/allports.txt $IP
# 2) Deep dive on the open ports
nmap -sC -sV -p<PORTS> -oA nmap/detailed $IP
# 3) UDP top ports (SNMP/DNS/TFTP/IKE hide here)
sudo nmap -sU --top-ports 100 -oN nmap/udp.txt $IP
```
> **Lesson (Chatterbox):** AChat on 9255/9256 was invisible to the default scan. `-p-` first, always.
> `tcpwrapped` / silent banner = custom binary protocol → confirm by *exploiting*, not fingerprinting.

> **NSE scripts:** how the Scripting Engine works, category flags, and — critically — **how to read a blank vuln-script result (inconclusive ≠ safe)** live in [[Nmap-NSE]].

> **Lesson (Sunday):** enumeration named a service that had **no matching open port** — finger showed users with TTY `ssh`, but 22 was closed in the top-1000. A service that provably runs but isn't in your scan = it's on a **non-standard port**, so `-p-`. Found SSH on **22022**.
> Generalise: whenever loot (logs, `.bash_history`, config, finger/mail output) references a service you haven't scanned open, that's a full-sweep trigger, not a contradiction.

**Relocated-port tells** — a high port whose digits echo the standard one is almost always that service: `22022`/`2222`/`22222` → SSH · `8080`/`8000`/`8443` → HTTP(S) · `33060` → MySQL. Confirm with `-sV`, never assume.

`Not shown: 997 closed tcp ports` in your output = **you only scanned the top 1000.** 997 + open ports ≈ 1000 is the giveaway.

**Add to `/etc/hosts`** whenever a hostname/domain shows up (LDAP cert, redirect, SMB):
```bash
echo "$IP dc01.domain.htb domain.htb" | sudo tee -a /etc/hosts
```

---

## Service → what to do

| Port       | Service        | First moves                                                                          | Deep note                                    |
| ---------- | -------------- | ------------------------------------------------------------------------------------ | -------------------------------------------- |
| 21         | FTP            | anon login `ftp $IP` (user `anonymous`), `ls -la`, check writable + web-root overlap |                                              |
| 22         | SSH            | version → CVE; note for later cred reuse; key auth                                   |                                              |
| 25/110/143 | SMTP/POP3/IMAP | user enum `VRFY`, read mail, creds                                                   | [[SMTP]] [[POP3]] [[IMAP]] [[Mail-Workflow]] |
| 53         | DNS            | zone transfer `dig axfr @$IP domain`                                                 |                                              |
| 79         | finger         | `finger @$IP`, query a **bogus** user, then wordlist enum                            | ↓ below · [[Finger]]                         |
| 80/443     | HTTP(S)        | full web enum                                                                        | [[02 - Web Attacks]]                         |
| 111/2049   | RPC/NFS        | `showmount -e $IP`, mount exports                                                    | [[rpcbind-NFS]]                              |
| 139/445    | SMB            | null session, shares, users                                                          | ↓ below                                      |
| 161        | SNMP           | `snmpwalk -v2c -c public $IP` / `onesixtyone` / `snmp-check`                         | [[SNMP]]                                     |
| 389/636    | LDAP           | anon bind dump                                                                       | ↓ [[05 - Active Directory]]                  |
| 515        | LPD            | `lpq -h $IP -P <queue>`, raw `\x03`/`\x04` queue probe                               | ↓ below · [[LPD]]                            |
| 1433       | MSSQL          | `impacket-mssqlclient`, `xp_cmdshell`                                                | [[MSSQL]]                                    |
| 3306       | MySQL          | `mysql -u root -p'root' -h $IP`; hashes; `INTO OUTFILE` webshell                     | [[MySQL]]                                    |
| 5432       | PostgreSQL     | `psql -h $IP -U postgres`, cred reuse, `COPY FROM PROGRAM`                           | [[PostgreSQL]]                               |
| 3389       | RDP            | `xfreerdp` once creds found                                                          |                                              |
| 5985/5986  | WinRM          | [[evil-winrm]] once creds found                                                      |                                              |

---

## finger (79) — free username list

Cleartext legacy Unix service: "who is on this host and what are they doing." Leaks real names, login/idle times, home dirs, shells, and `.plan`/`.project` contents. **Any open 79 = free `users.txt`.**

```bash
nmap -sV -p 79 --script finger $IP    # banner + version
finger @$IP                            # currently-logged-in users ONLY
finger root@$IP                        # query a specific user
finger admin@$IP                       # query a BOGUS user ← the good one
nc -nv $IP 79                          # raw
finger @intermediate@$IP               # bounce/relay through a host
```

**The bogus-username oracle.** `finger @$IP` alone only shows *active sessions* — often "No one logged on", which reads like a dead end. Querying a username that **doesn't exist** makes many daemons fall back to dumping the account list instead of erroring. Always try both.

Wordlist enumeration once you know it leaks:
```bash
finger_user_enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t $IP -m 50
# or
msfconsole -q -x "use auxiliary/scanner/finger/finger_users; set RHOSTS $IP; \
  set USERS_FILE /usr/share/wordlists/metasploit/unix_users.txt; run"
```

**Reading the output — separating signal from noise:**

| Pattern | Meaning | Action |
|---|---|---|
| `???` in the Name column | Wordlist entry contained a **space** → finger split it into two queries, neither resolved | False positive, ignore |
| Same default account dump on every miss | The bogus-user fallback firing | Noise — this is your baseline |
| OS role accounts (`adm`, `lp`, `netadm`, `dladm`, `nobody4`, `bin`, `smmsp`) | Built-in service accounts | Not users, but they **fingerprint the OS** |
| **TTY = `ssh`/`console` + a real date + source IP** | A human logged in from somewhere | ← **THE FINDING** |

Source IP in the VPN range (`10.10.14.x`) = another operator's login → confirms a genuine, usable account.

⚠️ **Worker count / false negatives.** finger runs under `inetd`, which rate-limits and will start refusing connections if hammered. Refusals get read as "user doesn't exist" — you silently **miss the account you're hunting**. Keep `-m` ≤ 50 (100 max). Run a shortlist first (`top-usernames-shortlist.txt`, ~17 names, instant) before committing to a 10k list.

> **Lesson (Sunday):** `finger @$IP` → "No one logged on". Looked dead. `finger admin@$IP` → full account dump. The service was leaking the whole time; the *empty* query was the misleading one.

---

## LPD / line printer daemon (515) — RFC 1179

Cleartext, no auth, hostname-only ACL. Solaris `in.lpd`, LPRng, BSD `lpd`, or CUPS's `cups-lpd` shim. Queue queries can leak usernames, hostnames, filenames, and document contents.

**It is not a banner protocol** — `nc` connects and sits silent because the *client* must speak first. Silence ≠ dead.

```bash
nmap -sV -p 515 $IP
lpq -h $IP -P <queue>                       # read queue, unauthenticated
printf '\x03default\n' | nc -q2 $IP 515     # raw queue state (short)
printf '\x04default\n' | nc -q2 $IP 515     # raw queue state (long)
lpr -H $IP -P <queue> testfile.txt          # submit a job
```

**Command bytes — use the right one:**

| Byte | Meaning | Enumeration use |
|---|---|---|
| `\x01` | Print any waiting jobs | ❌ **returns nothing** — not an enum command |
| `\x02` | Receive a printer job | — |
| `\x03` | Send queue state (**short**) | ✅ start here |
| `\x04` | Send queue state (**long**) | ✅ more detail |
| `\x05` | Remove jobs | destructive |

Queue-name guesses: `default`, `lp`, `raw`, `text`, `printer`.
Always add `-q2` to `nc` — without it netcat holds the socket open after stdin EOF and you can't tell "no reply" from "still waiting."

**Known exploits (version-gate first — these are old):**

| CVE | Target | Impact |
|---|---|---|
| CVE-2000-0917 | LPRng ≤ 3.6.24 `use_syslog()` format string | pre-auth **remote root** (10.0) |
| CVE-2001-0353 | Solaris `in.lpd` transfer job overflow | **remote root** (10.0) |
| CVE-2001-0670 | BSD `lpd`/`in.lpd` overflow | RCE (7.5) |
| CVE-2005-4797 | Solaris `printd` directory traversal | arbitrary file deletion |

```
exploit/linux/misc/lprng_format_string
exploit/solaris/lpd/sendmail_exec
```
LPD often fronts a physical printer — also check **9100** (raw/JetDirect) and **631** (IPP). [[PRET]]: `python pret.py $IP pjl`

> **Lesson (Sunday):** sent `\x01` and read the silence as "queue doesn't exist", then abandoned 515 entirely. `\x01` means *start printing* — it was never going to reply. Check the protocol's command table before concluding a service is a rabbit hole.

---

## SMB (139/445) — always check
```bash
nxc smb $IP                                  # host/domain/signing (netexec)
nxc smb $IP -u '' -p '' --shares             # null session shares
nxc smb $IP -u guest -p '' --shares          # guest fallback
smbclient -N -L //$IP                        # list shares no-cred
smbclient -N //$IP/<share>                   # connect; recurse; mget *
enum4linux-ng -A $IP                          # everything
```
Detail: [[smbclient]] · [[SMBMap]] · [[enum4linux]] · [[CrackMapExec]]

> **Lesson (DanglingTree):** on a hardened DC, a truly **blank username** (`-u '' -p ''`) can report `Null Auth: True` on the banner but still hit `STATUS_ACCESS_DENIED` on every share. Don't stop there — try **any non-existent username** with a blank password (`-u 'g' -p ''` or `-u 'guest' -p ''`). If Guest is enabled, unknown-username auth falls back to it and can succeed where the truly-empty session didn't, surfacing shares (including non-default ones) the blank session couldn't see. Always try both forms; they are not equivalent.

**Free username list from a `profiles$`/`Users`-style share** — folder names under a roaming-profile share are usernames, no auth beyond guest/anon needed:
```bash
smbclient -N \\\\$IP\\profiles$ -c ls | awk '{ print $1 }' > users.txt
```
Feed straight into AS-REP roasting ([[05 - Active Directory]]) even before you have any credentials.

> **Lesson (Blackfield):** `smbmap -u guest -H $IP` showed a `forensic`/audit share with NO ACCESS as guest, but the unrelated `profiles$` share was READ — don't stop at the first denied share, enumerate every listed share individually per identity.

---

## Web quick-start (full playbook in [[02 - Web Attacks]])
```bash
whatweb http://$IP; curl -sI http://$IP           # tech + headers + VERSION
gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,aspx
ffuf -u http://$IP -H "Host: FUZZ.domain.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <size>   # vhosts
```
Detail: [[Gobuster]] · [[ffuf]]

---

## From a Windows host (no tools) — LOLBAS

When you land on a client-provided workstation, an assumed-breach box, or any shell where you cannot drop tooling, enumerate with what ships in the OS. Full command tables: [[6- Deeper Down the Rabbit Hole]] (CPTS AD enum).

```
:: Shares on a remote host — /all includes the $ admin shares (ADMIN$, C$, IPC$)
net view \\dc01 /all
net view /domain                             :: domains visible
net view /all /domain:<domain>               :: shares across a domain
net use                                      :: existing mapped drives / sessions
```

```
:: DNS — nslookup is the host/dig replacement
nslookup <host>
nslookup -type=TXT <host> <dns-server>       :: any record type, any server
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>   :: find DCs without tooling
```

```powershell
# Single-port check (ICMP + TCP connect)
Test-NetConnection -Port 445 <ip>            # TcpTestSucceeded : True = open

# Port sweep 1-1024 — raw TcpClient, quieter than Test-NetConnection
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("<ip>", $_)) "TCP port $_ is open"} 2>$null
```

**Local context first** — cheap, and it scopes everything after it:
```
whoami /all                                  :: SID, groups, privileges
ipconfig /all                                :: subnets + DNS server = your DC
route print & arp -a                         :: reachable segments / neighbours
netstat -ano                                 :: local-only listeners scanning cannot see
systeminfo                                   :: OS build, hotfixes, domain
```

> **Why this matters:** these are signed, trusted binaries already present, so they generate no download, no AV event, and traffic that blends into normal enterprise activity. The LOLBAS project catalogues binaries abused for *unintended* execution — but for pure enumeration the native tools used as intended are the quieter option.

Same enumeration from Kali once you have a pivot: [[07 - Shells & File Transfers]] for getting tooling across, or proxy `nxc`/`smbclient` through the foothold rather than running anything on the host.

> **Note:** `smb-os-discovery` and other SMBv1-era NSE scripts fail against modern Windows, but `net view` and `nslookup` work regardless of SMB version — on-host enumeration often succeeds where remote scanning is blocked or lies. See [[06-information-gathering]] (OSCP Module 6).

---

## The enumeration mindset (checklist)
- [ ] Every service: identify **exact version** → `searchsploit <svc> <version>`
- [ ] Every login: try **default creds** and creds already found elsewhere
- [ ] Read **everything readable** — configs, shares, source, comments, mail
- [ ] Note every **username** (build `users.txt`) and every **password** (build `pass.txt`)
- [ ] After ANY new access → **re-run** enum as that identity
- [ ] Screenshot each key finding (report evidence) → [[09 - Reporting]]

> **Observation / Reasoning** habit from [[HTB Methodology Template]]: after each service, write *what stood out* and *why it matters*. Forces you to actually think, not just dump output.

---

## References
- HackTricks pentesting ports: https://book.hacktricks.xyz/network-services-pentesting
- 0xdf cheatsheets: https://0xdf.gitlab.io/cheatsheets/
- SecLists: https://github.com/danielmiessler/SecLists
- PentestPad — port 79 / finger: https://www.pentestpad.com/port-exploit/port-79-finger-finger-protocol
- PentestPad — port 515 / LPD: https://www.pentestpad.com/port-exploit/port-515-lpd-line-printer-daemon
- RFC 1179 (LPD protocol): https://www.rfc-editor.org/rfc/rfc1179
