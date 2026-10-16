---
tags: [methodology, oscp, stuck, troubleshooting]
---

# 10 — When Stuck (Unstick Checklist)

> Back to [[00 - Index (MOC)]]. **Golden rule:** *when stuck, you haven't enumerated enough — go wider, not deeper.* Being stuck = a false assumption or an un-enumerated surface. This page breaks the assumption.

> **Before anything: re-read the task.** What *exactly* does it ask for, and what tech does it name? The ADMIN capstone literally said "leverage **Windows library and shortcut files**" — the technique was in the prompt. Don't invent a harder path than the one you were handed.

---

## The 60-second reset (run top to bottom)

1. **Did I scan ALL ports?** Re-run `nmap -p- --min-rate=1000` — a service on a high port changes everything. Then targeted `-sV -sC` on what's open. Add **UDP top 100** (`nmap -sU --top-ports 100`).
2. **Did I enumerate every service, not just the shiny one?** Every open port is a door. List them and ask "have I actually tried this one?"
3. **Am I fuzzing web with the right extensions?** Default page ≠ empty. Add **document types**: `-x pdf,docx,xlsx,txt,aspx,asp,php,config,bak`. → *the ADMIN box hid a `.pdf` behind a default IIS page.* See [[02 - Web Attacks]].
4. **Did I try creds EVERYWHERE?** One credential → test it on SMB, WinRM, RDP, SMTP-AUTH, SSH, MSSQL, the web login. **Password reuse is king.** (And: student/VPN creds like `offsec:lab` are usually **not** target creds — don't assume they log in.)
5. **Did I re-enumerate after every new user/cred?** New access = new surface. Restart the loop as that user.
6. **Am I fighting the wrong channel?** If delivery/upload is "access denied" one way, the intended channel is probably another port (SMB share vs. WebDAV `PUT` vs. email). Enumerate *all* writable locations before forcing one.

---

## Assumption-buster table

| I'm assuming… | Break it by… |
|---|---|
| "The web server is empty" | Fuzz with **more extensions** (docs, configs, bak); check source, `/robots.txt`, headers, vhosts |
| "There's no domain" | `nmap --script smb-os-discovery`; SMTP `EHLO` banner; TLS cert CN on 443/5986 |
| "I need to send email" | Is there a **writable SMB share** or **WebDAV PUT** instead? Delivery ≠ always mail |
| "These creds don't work" | Test them on **every** service, both `user` and `user@HOST` forms; they may be student creds, not target creds |
| "The share is read-only" | List **all** shares with `nxc --shares` (shows READ/WRITE per share) — you may be on the wrong one |
| "The exploit failed" | Wrong payload/arch/port? Re-read output. Did a rate-limit / **auto-ban** kick in (hMailServer bans on flooding)? Slow down |
| "Nothing on this port" | Grab the **exact version** → `searchsploit` + Google `"<product> <version>" exploit` |
| "I've tried everything" | You haven't. Diff what you *know* vs. what you *assumed*. Enumerate the assumption |

---

## Service-specific "did I actually try…"

- **SMB (445):** null + guest sessions, `nxc --shares` (READ/WRITE flags), `--users --rid-brute`, `enum4linux-ng`, spider readable shares for creds/configs.
- **Web (80/443):** extensions (see above), vhosts, headers-as-input, source/comments, default creds, exact version → CVE.
- **SMTP (25/587):** `EHLO` banner for hostname/domain; `VRFY`/`RCPT` user enum; is it a **delivery channel** for a client-side payload? Watch for auto-ban — go gentle.
- **RPC (135/139):** `rpcclient -U "" -N` → `enumdomusers`, `querydispinfo`.
- **WinRM (5985/5986):** the moment you have *any* cred → `nxc winrm` then `evil-winrm`.

---

## Behavioural rules (the stuff that actually wastes hours)

- **Timebox it.** ~30–45 min with zero progress → step back, re-enumerate, or move to another box and return.
- **Read your own notes FIRST.** The ADMIN capstone answer (SMB-delivered library+shortcut, flag on Administrator's desktop) was already written in *12 — Client-side Attacks*. Search the vault before improvising.
- **One variable at a time.** Changing three things and getting a new error tells you nothing.
- **Watch for self-inflicted blocks.** Aggressive `-T5 --min-rate` scans trip rate-limits and auto-bans (mail servers especially) → "closed connection" looks like the target changed, but it's you.
- **Note what you ruled OUT**, not just what worked — stops you re-walking dead ends.

---

_Related: [[00 - Index (MOC)]] · [[01 - Recon & Enumeration]] · [[02 - Web Attacks]] · OSCP note: 12 — Client-side Attacks._
