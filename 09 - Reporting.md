---
tags: [methodology, reporting, oscp, documentation]
---

# 09 — Reporting

> Back to [[00 - Index (MOC)]]. The exam is **failed if the report is bad**, no matter how many roots. Document *as you go*, not at the end. This habit carries straight into the job.

## Golden rules
- **Screenshot every step**: the command AND its output, with the target IP visible.
- Capture `local.txt`/`proof.txt` **in a shell that shows `type flag.txt` + `whoami` + `ipconfig`** — a bare flag string isn't accepted.
- Copy every command into your notes live (use [[HTB Methodology Template]] per box).
- Track creds/vulns in tables as you find them (see template).

## OSCP report structure
1. **Cover / high-level summary** — scope, dates, result.
2. **Per-host walkthrough** — for each machine:
   - Enumeration (nmap + service findings, with screenshots)
   - Foothold: vuln → exploit → proof of `local.txt`
   - Privesc: vuln → exploit → proof of `proof.txt`
   - Every command reproducible; every screenshot captioned.
3. **AD set** — show the full chain host→host→DA, including pivots.
4. (Bonus) Lab + exercises appendix for the +10.

## Per-finding write-up (from CPTS habit)
For each vuln record: **Description · Affected component · CVE (if any) · Reproduction steps · Impact · Remediation**.
Deeper methodology: [[CPTS Report Methodology]] · example: [[CPTS report]].

## Severity quick-ref
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  ≈ 9.8 (Critical)  — e.g. unauth RCE / SQLi
Use S:C when impact escapes the vulnerable component's scope (e.g. LFI → host files).
```
Common CWEs: SQLi **CWE-89** · Cmd Injection **CWE-78** · LFI **CWE-98** · Weak/Default creds **CWE-521/1392** · Priv mgmt **CWE-269**.

## Tooling
- **Notes as you hack:** Obsidian (this vault) with the per-box [[HTB Methodology Template]].
- **Report:** SysReptor (matches CPTS workflow) or the OffSec template.
- Keep a `loot/` folder per box: hashes, creds, keys, screenshots.

## Pre-submit checklist
- [ ] Every machine has enumeration → foothold → privesc sections
- [ ] `local.txt` + `proof.txt` shown with context (whoami/ip)
- [ ] All commands reproducible (no missing steps)
- [ ] AD chain fully documented incl. pivots
- [ ] No placeholder screenshots / broken images
- [ ] Exported to PDF, correct filename, submitted before deadline

---

## References
- OffSec exam report template & guide (read the current version before exam)
- SysReptor: https://docs.sysreptor.com
