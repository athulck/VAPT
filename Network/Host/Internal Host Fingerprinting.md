# Internal VAPT — Host Fingerprinting Module
### Stealth Collection: NetBIOS Name · DNS Name · MAC Address · OS Version
> **Context:** You have initial foothold on one internal host. All targets are RFC-1918 private IPs. Goal is to fingerprint every reachable host as quietly as possible — leveraging passive observation and protocol-native queries before resorting to active probing.

---

## Noise-Dial Overview for This Module

| db Level | Approach | Packets Sent | Detectable? |
|----------|----------|-------------|-------------|
| db:0 | Read local OS cache — ARP table, DNS cache, NetBIOS cache | 0 | Never |
| db:1 | Passive sniffing — listen, don't transmit | 0 | Never |
| db:2 | Single targeted ARP request per host | 1 per host | Very Low |
| db:3 | Single NetBIOS Name Service query per host | 1–2 per host | Low |
| db:4 | Nmap targeted fingerprint — 1 host, paranoid timing | ~50–200 | Low |
| db:5 | Nmap subnet sweep — SMB/NetBIOS/OS scripts | ~5,000–20,000 | Medium–High |

---

---

## db:0 — Read What's Already There (Zero Packets)

> Your foothold OS has already been talking to the network. Its caches hold gold. No packets needed — this is pure memory read.

### 0.1 — ARP Cache (MAC Addresses of Recently-Contacted Hosts)

**Packets sent:** `0` | **Type:** None — OS memory read | **Detectable:** Never

```bash
# Linux — full ARP table (IP → MAC, already cached)
arp -a
arp -n                     # Numeric only, no reverse DNS lookups (faster, quieter)
ip neigh show              # Modern iproute2 version — shows state (REACHABLE, STALE, etc.)
ip neigh show nud reachable  # Only entries confirmed alive recently

# Windows
arp -a                     # All interfaces
arp -a -v                  # Verbose
Get-NetNeighbor            # PowerShell — richer output, includes LinkLayerAddress (MAC)
Get-NetNeighbor | Where-Object { $_.State -eq "Reachable" }
```

**What you collect:**
- `IP Address` → `MAC Address` for every host your foothold machine talked to recently
- MAC OUI prefix → vendor lookup → OS hint (e.g., `00:50:56` = VMware, `B8:27:EB` = Raspberry Pi, `2C:54:91` = Apple)

```bash
# OUI lookup from MAC (offline)
# Linux — macchanger or manuf file
grep -i "00:50:56" /usr/share/nmap/nmap-mac-prefixes
# Or use wireshark's manuf file
grep -i "b8:27:eb" /usr/share/wireshark/manuf
```

---

### 0.2 — DNS Cache (Hostnames Already Resolved)

**Packets sent:** `0` | **Type:** None — OS memory read | **Detectable:** Never

```bash
# Linux — systemd-resolved cache
sudo systemd-resolve --statistics
sudo systemd-resolve --dump-cache 2>/dev/null | grep -E "A|PTR|CNAME"

# Linux — nscd cache (if running)
nscd -g

# Windows — DNS resolver cache (goldmine for internal hostnames)
ipconfig /displaydns
ipconfig /displaydns | findstr "Record Name"

# PowerShell — structured output
Get-DnsClientCache
Get-DnsClientCache | Select-Object Entry, RecordName, Data | Format-Table -AutoSize
Get-DnsClientCache | Where-Object { $_.Data -match "^10\.|^192\.168\.|^172\." }
# Filters for RFC-1918 addresses only
```

**What you collect:**
- DNS names ↔ IP mappings that your foothold machine has already resolved — servers it talked to, domain controllers, internal services.

---

### 0.3 — NetBIOS / WINS Cache

**Packets sent:** `0` | **Type:** None — OS memory read | **Detectable:** Never

```bash
# Windows — NetBIOS name cache (names resolved via broadcast or WINS)
nbtstat -c                 # Cached NetBIOS names → IP mappings
nbtstat -n                 # Local machine's own registered names

# PowerShell
Get-WmiObject Win32_NetworkAdapterConfiguration | 
  Select-Object Description, MACAddress, IPAddress, DNSHostName
```

---

### 0.4 — Hosts File & Network Config (Local Intel)

**Packets sent:** `0` | **Type:** None | **Detectable:** Never

```bash
# Linux — static host mappings (sometimes internal IPs hard-coded here)
cat /etc/hosts
cat /etc/resolv.conf       # Internal DNS server IPs → pivot for future queries
cat /etc/networks

# Routing table — reveals internal subnets reachable from this host
ip route show
route -n
netstat -rn

# Windows
type C:\Windows\System32\drivers\etc\hosts
ipconfig /all              # DNS suffix, WINS server, domain name
route print
Get-NetRoute               # PowerShell
```

**What you collect:**
- Internal DNS server IP (query it directly later)
- Domain/workgroup name
- Subnets the foothold can reach — defines your pivot scope

---

---

## db:1 — Passive Sniffing (Listen Only, Zero Transmission)

> Put the NIC into promiscuous mode and capture broadcast/multicast traffic that other hosts are already generating. ARP, NetBIOS, mDNS, and LLMNR broadcasts reveal hosts, MACs, and names without you sending a single byte.

**Packets sent:** `0` | **Type:** Receive-only — NIC listens passively | **Detectable:** Never (passive sniffing is electronically invisible — no outbound traffic)

### 1.1 — Capture ARP Broadcasts (MAC + IP Discovery)

```bash
# Linux — tcpdump, filter ARP only
sudo tcpdump -i eth0 -n arp -e 2>/dev/null
# -n  = no name resolution (don't generate DNS queries)
# -e  = print MAC addresses (link-layer header)

# Capture to file for offline analysis
sudo tcpdump -i eth0 -n arp -e -w arp_capture.pcap

# Parse captured ARP — extract unique IP → MAC pairs
tcpdump -r arp_capture.pcap -n arp -e 2>/dev/null | \
  grep "Request\|Reply" | \
  awk '{print $NF, $(NF-2)}' | sort -u

# Windows — using Wireshark capture filter
# Filter: arp
# Or PowerShell with raw socket (requires admin):
# netsh trace start capture=yes tracefile=C:\trace.etl
# netsh trace stop
```

---

### 1.2 — Capture NetBIOS Name Service Broadcasts (Port 137/UDP)

NetBIOS Name Service (NBNS) broadcasts announce hostnames to the subnet every few minutes.

```bash
# Linux — capture NBNS broadcasts (UDP 137)
sudo tcpdump -i eth0 -n 'udp port 137' -e

# Parse NetBIOS name from broadcast
sudo tcpdump -i eth0 -n 'udp port 137' -A 2>/dev/null | \
  grep -oP '[A-Z0-9\-]{1,15}(?=\s*<)'

# Tshark — more structured parsing
sudo tshark -i eth0 -f "udp port 137" -T fields \
  -e eth.src -e ip.src -e nbns.name 2>/dev/null
```

---

### 1.3 — Capture mDNS / LLMNR (Modern Windows/Linux Name Broadcasts)

mDNS (port 5353/UDP) and LLMNR (port 5355/UDP) — Windows Vista+ and Linux use these for local name resolution. Extremely revealing.

```bash
# Capture mDNS (Apple Bonjour + Linux Avahi + Windows)
sudo tcpdump -i eth0 -n 'udp port 5353' -e

# Capture LLMNR (Windows-specific link-local name resolution)
sudo tcpdump -i eth0 -n 'udp port 5355' -e

# Tshark — parse mDNS PTR records (hostname announcements)
sudo tshark -i eth0 -f "udp port 5353" -T fields \
  -e eth.src -e ip.src -e dns.qry.name -e dns.resp.name 2>/dev/null | \
  grep -v "^$" | sort -u

# Combine all three broadcast types in one capture
sudo tcpdump -i eth0 -n \
  'udp port 137 or udp port 138 or udp port 5353 or udp port 5355' \
  -e -w passive_names.pcap
```

**Wait time recommendation:** Capture for 10–30 minutes during business hours. Active hosts generate these broadcasts frequently. A full hour of passive capture can map 80–90% of a flat /24 network.

**What you collect per host (zero packets sent):**
- IP Address (from packet source)
- MAC Address (from Ethernet frame header)
- NetBIOS Name / mDNS Hostname (from broadcast payload)

---

### 1.4 — Passive OS Fingerprinting via TCP Traffic (p0f)

p0f identifies OS versions by analyzing the TCP/IP stack characteristics of packets — TTL, window size, IP options, TCP flags — without sending anything.

```bash
# Install and run p0f (Linux)
sudo p0f -i eth0 -o p0f_output.log

# p0f reads live traffic and builds a host table:
# .-[ 10.0.0.15/445 -> 10.0.0.1/12345 (syn) ]-
# | client   = 10.0.0.15
# | os       = Windows 7 or 8
# | dist     = 0
# | params   = none
# | raw_sig  = 4:128+0:0:65535:mss*44,0:mss,nop,nop,sackOK:df,id+:0

# Let it run in background during your engagement — passive, continuous OS mapping
sudo p0f -i eth0 -o /tmp/p0f.log -d   # -d = daemonize
```

**What p0f extracts:**
- OS family and version from TTL + TCP window size + options signature
- Distance (hops from your host — 0 = same subnet)
- No packets sent — ever

---

---

## db:2 — Single ARP Request per Host (MAC + Liveness)

> ARP requests are the most natural traffic on an Ethernet segment. Every host sends them constantly. A single targeted ARP for one IP is completely invisible in a busy network.

**Packets sent:** `1 ARP request` per host | **Type:** ARP — standard L2 broadcast, safe, non-malicious | **Detectable:** Near impossible — indistinguishable from normal traffic

### 2.1 — arping (Single ARP Request)

```bash
# Linux — send exactly 1 ARP request
sudo arping -c 1 10.0.0.15
# Output: ARPING 10.0.0.15 from 10.0.0.50 eth0
# 60 bytes from 00:50:56:ab:cd:ef (10.0.0.15): index=0

# Just get the MAC, no extra output
sudo arping -c 1 -r 10.0.0.15 2>/dev/null   # -r = only print MAC

# Loop across discovered hosts quietly (1 second apart)
for ip in $(cat alive_hosts.txt); do
  mac=$(sudo arping -c 1 -r $ip 2>/dev/null)
  [ -n "$mac" ] && echo "$ip,$mac"
  sleep 1
done

# Windows — arp -a after pinging (ARP is populated automatically)
ping -n 1 10.0.0.15 >nul
arp -a | findstr "10.0.0.15"
```

**What you collect:** MAC address confirmed for that IP. Cross-reference ARP cache. OUI = vendor = OS hint.

---

---

## db:3 — NetBIOS Name Service Query (Name + MAC + OS Hint)

> A single NBNS status request to port 137/UDP is a completely legitimate protocol operation. It returns the host's NetBIOS name table, workgroup/domain, and MAC address in one packet exchange.

**Packets sent:** `1 UDP request + 1 UDP response` per host | **Type:** UDP/137 — standard NetBIOS, safe, non-malicious | **Detectable:** Low — NBNS traffic is normal on Windows networks; unusual only on Linux-only networks

### 3.1 — nmblookup (Linux)

```bash
# Single host — query NetBIOS node status
nmblookup -A 10.0.0.15
# Returns:
# Looking up status of 10.0.0.15
# WORKSTATION01  <00> -         B <ACTIVE>     ← computer name
# WORKSTATION01  <20> -         B <ACTIVE>     ← file server service
# CORP           <00> - <GROUP> B <ACTIVE>     ← workgroup/domain
# MAC Address = 00-50-56-AB-CD-EF              ← MAC address

# Parse: extract name + MAC cleanly
nmblookup -A 10.0.0.15 2>/dev/null | awk '
  /<00>/ && !/<GROUP>/ { name=$1 }
  /MAC Address/ { mac=$NF }
  END { print name, mac }
'

# Quiet loop — one host per second
for ip in $(cat alive_hosts.txt); do
  result=$(nmblookup -A $ip 2>/dev/null)
  name=$(echo "$result" | awk '/<00>/ && !/<GROUP>/ {print $1; exit}')
  mac=$(echo "$result" | awk '/MAC Address/ {print $NF}')
  echo "$ip | $name | $mac"
  sleep 1
done
```

---

### 3.2 — nbtstat (Windows — from Foothold)

```bash
# Windows — node status query (same as nmblookup -A)
nbtstat -A 10.0.0.15
# Returns NetBIOS name table — computer name, domain, services registered

# Parse just the name
nbtstat -A 10.0.0.15 | findstr "<00>"

# Loop in PowerShell — quietly
$hosts = Get-Content "alive_hosts.txt"
foreach ($ip in $hosts) {
  $result = nbtstat -A $ip 2>$null
  $name = ($result | Select-String "<00>" | Select-Object -First 1).ToString().Trim().Split()[0]
  Write-Host "$ip`t$name"
  Start-Sleep -Seconds 1
}
```

---

### 3.3 — nmap Single-Host NetBIOS Script (Quiet)

```bash
# Linux — targeted nmap, NetBIOS script only, -T1 timing, no port scan
sudo nmap -sU -p 137 --script nbstat.nse -Pn -T1 10.0.0.15

# Output includes:
# Host script results:
# | nbstat:
# |   NetBIOS name: WORKSTATION01
# |   NetBIOS user: <unknown>
# |   NetBIOS MAC: 00:50:56:ab:cd:ef (VMware)
# |_  Names: WORKSTATION01<00>, CORP<00>, CORP<1e>
```

---

---

## db:4 — Targeted Single-Host OS Fingerprint (Paranoid Timing)

> You now query one specific host for OS version using Nmap's OS detection. Paranoid or Sneaky timing ensures the probe sequence is spread across seconds, not milliseconds.

**Packets sent:** `~50–200 TCP/UDP probes` per host | **Type:** TCP SYN/ACK/FIN/UDP — crafted but standard protocol behavior | **Detectable:** Low at T0/T1 — well below most IDS thresholds for a single host

### 4.1 — Nmap OS Detection (Single Host, Quiet)

```bash
# Linux — OS fingerprint only, no port scan required
# Must have ≥1 open and ≥1 closed port for reliable fingerprint
sudo nmap -O --osscan-limit --osscan-guess \
  -Pn -T1 --max-retries 1 \
  -p 22,80,135,139,443,445 \
  10.0.0.15 -oN os_10.0.0.15.txt

# Combined: OS + hostname + MAC — one pass
sudo nmap -O -sV --version-intensity 0 \
  --script nbstat,smb-os-discovery \
  -p 135,139,445 -Pn -T1 \
  10.0.0.15

# Flags:
# -O               = OS detection
# --osscan-limit   = Only attempt if conditions are confident
# --osscan-guess   = Guess aggressively if no exact match
# --max-retries 1  = Only retry once (reduces packet count significantly)
# -T1              = Sneaky timing (15s between probes)

# Windows (nmap for Windows with Npcap)
nmap -O --osscan-limit -Pn -T1 -p 135,139,445 10.0.0.15
```

---

### 4.2 — SMB OS Discovery Script (Most Reliable for Windows Hosts)

The `smb-os-discovery` script performs a full SMB negotiation and extracts the OS string, NetBIOS name, DNS name, and domain — all from one SMB session.

**Packets sent:** `~15–30` (SMB handshake) | **Type:** TCP/445 — SMB protocol (normal, safe) | **Detectable:** Low — looks like a normal SMB client connecting

```bash
# Linux
sudo nmap -p 445 --script smb-os-discovery -Pn -T2 10.0.0.15

# Output:
# Host script results:
# | smb-os-discovery:
# |   OS: Windows 10 Pro 19041                  ← exact OS version + build
# |   OS CPE: cpe:/o:microsoft:windows_10
# |   Computer name: WORKSTATION01              ← NetBIOS / computer name
# |   NetBIOS computer name: WORKSTATION01\x00
# |   Domain name: corp.local                  ← DNS domain
# |   Forest name: corp.local
# |   FQDN: WORKSTATION01.corp.local           ← full DNS name
# |_  System time: 2024-01-15T09:32:11+05:30

# Windows — equivalent via PowerShell (no nmap needed)
$smb = New-Object System.Net.Sockets.TcpClient
$smb.Connect("10.0.0.15", 445)
# Then read SMB negotiate response — or just use:
Invoke-Command -ComputerName 10.0.0.15 -ScriptBlock { $env:COMPUTERNAME; [System.Environment]::OSVersion }
# (Requires WinRM access / valid credentials)
```

---

### 4.3 — DNS Reverse Lookup (PTR Record) — Name from IP

**Packets sent:** `1 UDP query to internal DNS server` | **Type:** UDP/53 DNS PTR query — completely normal | **Detectable:** Never — indistinguishable from normal traffic

```bash
# Linux — reverse lookup (query internal DNS server found earlier)
dig -x 10.0.0.15 @10.0.0.1       # Query domain controller / internal DNS
dig +short -x 10.0.0.15 @10.0.0.1

# Batch — reverse lookup all hosts
for ip in $(cat alive_hosts.txt); do
  name=$(dig +short -x $ip @10.0.0.1 2>/dev/null | sed 's/\.$//')
  echo "$ip,$name"
  sleep 0.5
done

# Windows
nslookup 10.0.0.15 10.0.0.1      # Explicit DNS server
[System.Net.Dns]::GetHostEntry("10.0.0.15").HostName    # PowerShell
Resolve-DnsName -Name 10.0.0.15 -Server 10.0.0.1        # PowerShell
```

---

---

## db:5 — Subnet-Wide Fingerprint Sweep

> You've confirmed the internal DNS server, gathered passive data, and queried a few hosts manually. Now you sweep the full subnet using SMB and NetBIOS scripts at a measured pace. SOC may notice an internal host making many SMB connections.

**Packets sent:** `~5,000–20,000` across a /24 | **Type:** TCP/445 SMB + UDP/137 NBNS + OS probes | **Detectable:** Medium — unusual for a single host to query 254 others on port 445

### 5.1 — Nmap Subnet SMB + OS Sweep

```bash
# Linux — sweep entire /24, target only SMB/NetBIOS ports, T2 timing
sudo nmap -p 135,139,445 \
  --script smb-os-discovery,nbstat \
  -Pn -T2 --randomize-hosts \
  10.0.0.0/24 \
  -oA internal_sweep

# Parse results cleanly
grep -A 10 "smb-os-discovery" internal_sweep.nmap | \
  grep -E "OS:|Computer name:|FQDN:|NetBIOS"

# Windows (from foothold)
nmap -p 135,139,445 --script smb-os-discovery,nbstat \
  -Pn -T2 10.0.0.0/24 -oA internal_sweep
```

---

### 5.2 — CrackMapExec — One Command, Everything

CrackMapExec performs SMB fingerprinting against every host and returns OS version, hostname, domain, signing status — and it does it fast with controlled threading.

**Packets sent:** `~30–50 per host` (SMB negotiation) | **Type:** TCP/445 SMB — normal protocol | **Detectable:** Medium-High — one source connecting to all hosts on 445

```bash
# Linux — sweep /24, null session (no credentials needed for fingerprint)
crackmapexec smb 10.0.0.0/24 --no-bruteforce 2>/dev/null

# Output per host:
# SMB  10.0.0.15  445  WORKSTATION01  [*] Windows 10 Pro 19041 (name:WORKSTATION01) (domain:CORP) (signing:False) (SMBv1:False)
# Fields: IP | Port | NetBIOS Name | OS Version + Build | Domain | SMB Signing | SMBv1

# Throttle to be quieter (1 thread, 500ms delay between hosts)
crackmapexec smb 10.0.0.0/24 --threads 1 2>/dev/null

# Save to CSV
crackmapexec smb 10.0.0.0/24 2>/dev/null | \
  awk '{print $3","$5","$6","$7}' > host_inventory.csv
```

---

### 5.3 — DNS Forward Lookup of All Internal Hostnames

If you've identified the internal DNS server (from `/etc/resolv.conf` or `ipconfig /all`), querying it directly for all A records is extremely quiet — just DNS traffic.

```bash
# Linux — zone transfer (AXFR) attempt from internal DNS — single request
dig axfr @10.0.0.1 corp.local
# If successful: dumps every hostname and IP in the domain in one response

# If AXFR is blocked, enumerate common internal hostnames
for name in dc01 dc02 fileserver web01 mail exchange sql vpn; do
  ip=$(dig +short $name.corp.local @10.0.0.1)
  [ -n "$ip" ] && echo "$name.corp.local,$ip"
done

# Windows
nslookup
  server 10.0.0.1
  ls -d corp.local     # DNS zone transfer equivalent in nslookup

# PowerShell — AXFR attempt
Resolve-DnsName -Name corp.local -Type AXFR -Server 10.0.0.1
```

---

---

## Consolidated Collection Table

Once all db levels are run, your data per host should look like:

| Field | Source | db Level | Packets |
|-------|--------|----------|---------|
| **IP Address** | ARP cache / passive ARP | db:0 / db:1 | 0 |
| **MAC Address** | ARP cache / arping / nmblookup | db:0 / db:2 / db:3 | 0–1 |
| **Vendor (OUI)** | MAC prefix lookup (offline) | db:0 | 0 |
| **NetBIOS Name** | NBNS passive / nmblookup / CME | db:1 / db:3 / db:5 | 0–2 |
| **DNS Name (FQDN)** | DNS cache / PTR lookup / AXFR | db:0 / db:3 / db:5 | 0–1 |
| **Domain / Workgroup** | NetBIOS / SMB-OS-Discovery | db:3 / db:4 | 1–30 |
| **OS Version + Build** | p0f passive / Nmap OS / CME | db:1 / db:4 / db:5 | 0–200 |

---

## One-Shot Output Script

```bash
#!/bin/bash
# internal_fingerprint.sh
# Run from Linux foothold. Requires: nmap, nmblookup, arping, dig, awk
# Usage: ./internal_fingerprint.sh <subnet> <dns_server>
# Example: ./internal_fingerprint.sh 10.0.0.0/24 10.0.0.1

SUBNET=$1
DNS_SERVER=$2
OUTPUT="host_inventory_$(date +%Y%m%d_%H%M%S).csv"

echo "IP,MAC,Vendor,NetBIOS_Name,DNS_Name,OS_Version" > $OUTPUT

# Step 1: Passive — read ARP cache
echo "[*] Reading ARP cache..."
ip neigh show nud reachable | awk '{print $1, $5}' | while read ip mac; do
  [[ $ip == *"."* ]] || continue
  vendor=$(grep -i "${mac:0:8}" /usr/share/nmap/nmap-mac-prefixes 2>/dev/null | \
           head -1 | awk '{$1=""; print $0}' | xargs)
  echo "$ip,$mac,$vendor,,,pending" >> $OUTPUT
done

# Step 2: Targeted — per-host NetBIOS + DNS + OS (T1 timing, 1s delay)
echo "[*] Querying discovered hosts (quiet mode)..."
cut -d',' -f1 $OUTPUT | tail -n +2 | while read ip; do
  nbname=$(nmblookup -A $ip 2>/dev/null | \
           awk '/<00>/ && !/<GROUP>/ {print $1; exit}')
  dnsname=$(dig +short -x $ip @$DNS_SERVER 2>/dev/null | sed 's/\.$//')
  osver=$(sudo nmap -p 445 --script smb-os-discovery -Pn -T1 $ip 2>/dev/null | \
          grep "OS:" | awk -F': ' '{print $2}' | head -1)
  
  # Update the CSV row
  sed -i "s/^$ip,.*/$ip,$(grep "^$ip," $OUTPUT | cut -d',' -f2-3),$nbname,$dnsname,$osver/" $OUTPUT
  sleep 1
done

echo "[+] Done. Results saved to $OUTPUT"
cat $OUTPUT | column -t -s','
```

---

*Section version: 1.0 — Internal Fingerprinting Module | For authorized VAPT engagements only.*
