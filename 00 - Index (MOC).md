---
tags: [methodology, moc, oscp, pentest]
---

# 🧭 Methodology — Map of Content

Central hub for my pentest methodology. Built for **OSCP** but kept vendor-neutral so it carries into the job. Each page is a **playbook**: what to do, in what order, linking out to my detailed [[#Linked notes|Methods & Tools notes]] instead of repeating them.

> **Golden rule:** *Enumeration is 80% of the box.* When stuck, you haven't enumerated enough — go wider, not deeper. Re-enumerate every time you gain a new user or credential.

---

## ▶ Start here → follow the flow

```
RECON (always) ──► identify surface ──► EXPLOIT ──► FOOTHOLD (low-priv shell)
                                                        │
                              ┌─────────────────────────┤ re-enumerate as new user
                              ▼                          ▼
                       PRIVILEGE ESCALATION      LATERAL MOVEMENT / PIVOT
                              │                          │
                              ▼                          ▼
                         root / SYSTEM            next host / Domain Admin
```

## Where do I go next?

| What I'm looking at | Playbook |
|---------------------|----------|
| Any box — first contact | [[01 - Recon & Enumeration]] |
| Ports 80/443/8080, CMS, login page | [[02 - Web Attacks]] |
| Shell on a **Windows** host | [[03 - Windows Privilege Escalation]] |
| Shell on a **Linux** host | [[04 - Linux Privilege Escalation]] |
| Ports 88/389/445/636, a DC, `.htb`/`.local` domain | [[05 - Active Directory]] |
| Hashes/creds to crack, brute force, spraying | [[06 - Password Attacks]] |
| Catching shells, upgrading TTY, moving files | [[07 - Shells & File Transfers]] |
| Second NIC / internal subnet to reach | [[Pivoting-Tunneling]] |
| A vulnerable binary / SEH crash (OSCP) | [[08 - Buffer Overflow (OSCP)]] |
| Time to write it up | [[09 - Reporting]] |
| **Stuck / no progress / out of ideas** | [[10 - When Stuck (Unstick Checklist)]] |

---

## OSCP exam frame (keep this in view)

| Component | Points | Notes |
|-----------|-------:|-------|
| Active Directory set (3 chained hosts) | 40 | Assumed-breach creds given; must fully chain to DA |
| Standalone machine #1 | 20 | local.txt + proof.txt |
| Standalone machine #2 | 20 | local.txt + proof.txt |
| Standalone machine #3 | 20 | local.txt + proof.txt |
| **Pass** | **70/100** | +10 bonus for 80%+ of exercises & 30 lab machines |

**Rules of thumb:** Metasploit on **one** machine only. Document *everything* as you go (screenshots + commands + copy-paste of flags). No commercial/automated exploitation tools.

---

## The universal loop (every host)

1. **Scan** — full TCP (`-p-`), then targeted `-sV -sC`, then UDP top ports → [[01 - Recon & Enumeration]]
2. **Enumerate each service** — version → `searchsploit` → default creds → misconfig
3. **Get a foothold** — exploit / creds / web shell
4. **Stabilize** the shell → [[07 - Shells & File Transfers]]
5. **Local enum** — `whoami /priv` (Win) or `id` + `sudo -l` (Linux) → run PEAS
6. **Privesc** → [[03 - Windows Privilege Escalation]] / [[04 - Linux Privilege Escalation]]
7. **Loot** — creds, hashes, keys → try everywhere (password reuse is king)
8. **Pivot / lateral** if there's more network → [[Pivoting-Tunneling]] / [[05 - Active Directory]]
9. **Document** the finding immediately → [[09 - Reporting]]

---

## Linked notes

**Methods:** [[Pivoting-Tunneling]] · [[SQLi]] · [[XSS]] · [[WordPress]] · [[MSSQL]] · [[SMTP]] · [[POP3]] · [[IMAP]] · [[SNMP]] · [[MySQL]] · [[rpcbind-NFS]] · [[gopher]] · [[PDF-Injection]]
**Recon tools:** [[Gobuster]] · [[ffuf]] · [[enum4linux]] · [[smbclient]] · [[SMBMap]] · [[rpcclient]] · [[ldapsearch]] · [[Windapsearch]]
**AD tools:** [[BloodHound]] · [[Bloodhound-Python]] · [[Rusthound]] · [[BloodyAD]] · [[Certipy]] · [[CrackMapExec]] · [[kerbrute]] · [[Rubeus]] · [[Responder]] · [[Inveigh]] · [[secretsdump.py]] · [[impacket-psexec]] · [[psexec.py]] · [[Wmiexec.py]] · [[evil-winrm]]
**Privesc/misc:** [[LinPEAS]] · [[LinEnum]] · [[PrintSpoofer]] · [[PowerShell]] · [[Keepass2]] · [[Ligolo-ng]] · [[penelope]] · [[pypykatz]] · [[SeBackupPrivilege]]
**Templates:** [[HTB Methodology Template]]

> Related exam workflow: [[CPTS report]] · [[CPTS Report Methodology]]
