


### Pre-Requisites

| Sl. No. | Tool Name    | Download Link                                         |
| ------- | ------------ | ----------------------------------------------------- | 
| 1       | Nmap         | [Download](https://nmap.org/download.html#windows)    |
| 2       | CrackMapExec | [Download](https://crackmapexec.org/#download)        |
| 3       | NBTScan      | [Download](http://www.unixwiz.net/tools/nbtscan.html) |
| 4       | Metasploit   | [Download](https://windows.metasploit.com/metasploitframework-latest.msi) |
| 5       | PowerView    | [Download](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) | 
| 6       | Python 3     | [Download](https://www.python.org/downloads/windows/) | 




Ping Sweep - cmd
```
# Native Windows ping sweep across the /24 or CIDR range
for /L %i in (1,1,254) do @ping -n 1 -w 100 192.168.1.%i | find "Reply"
```

Ping Sweep - Powershell
```
# PowerShell version — faster, captures output
1..254 | ForEach-Object {
    $ip = "192.168.1.$_"
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1) {
        Write-Host "[+] ALIVE: $ip"
    }
}
```


arp -a                         # Lists IP-to-MAC mappings (reveals hosts even if ICMP is blocked)
route print                    # Understand the routing table — find subnets reachable via VPN
ipconfig /all                  # Your own IP, gateway, DNS, domain
nbtstat -n                     # NetBIOS name table



Step 1: Identifying Live & Reachable Hosts


Step 2: Identifying Hostname & OS

# OS detection
nmap -O -iL live_hosts.txt -oA nmap_os

nmap -sS -sV -O --osscan-guess --max-retries 2 --host-timeout 60s \
--script=banner,nbstat,smb-os-discovery,dns-brute,fingerprint-strings \
-oA profiling <live_hosts>



# Nmap top ports TCP scan
nmap -sS -sV -sC -T4 --top-ports 1000 -iL targets.txt -oX nmap_scan.xml -oN nmap_scan.txt 

# Nmap full port TCP scan
nmap -sS -sV -sC -T4 -p- -iL targets.txt -oX nmap_scan.xml -oN nmap_scan.txt 



# UDP scan (critical — finds SNMP, TFTP, DNS, NTP)
nmap -sU --top-ports 200 -iL live_hosts.txt -oA nmap_udp


nmap -sV --script vulners [--script-args mincvss=<arg_val>] <target>


# List all visible Windows hosts on the network
echo %USERDOMAIN%
nltest /domain_trusts
nltest /dclist:<domain>
net view
net view /domain
net user /domain


# NBTScan (Windows binary available)
nbtscan.exe 192.168.1.0/24

# Native SMB share listing
net view \\<target_ip> /all

nslookup -type=any <domain>
nslookup -type=MX <domain>
nslookup -type=NS <domain>
Resolve-DnsName -Name <domain> -Type ANY
# Zone transfer attempt (often misconfigured internally)
nslookup
  server <dns_server_ip>
  ls -d <domain>






# Using built-in RSAT / AD module (if available on the box)
Import-Module ActiveDirectory
Get-ADUser -Filter * -Properties * | Select Name,SamAccountName,Enabled,LastLogonDate
Get-ADComputer -Filter * -Properties * | Select Name,IPv4Address,OperatingSystem
Get-ADGroup -Filter * | Select Name,GroupCategory
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# Enumerate domain trusts
Get-ADTrust -Filter *

# Password policy (critical for spraying)
Get-ADDefaultDomainPasswordPolicy




CrackMapExec (Windows binary — CME)
```
crackmapexec smb 192.168.1.0/24                        # Enumerate SMB hosts
crackmapexec smb <target> -u '' -p '' --shares         # Null session share listing
crackmapexec smb <target> -u guest -p '' --shares      # Guest share listing
crackmapexec smb <target> -u <user> -p <pass> --users  # List users
crackmapexec smb <target> -u <user> -p <pass> --groups
crackmapexec smb <target> -u <user> -p <pass> --pass-pol  # Password policy

# Smbclient equivalent on Windows — map and browse shares
net use Z: \\<target>\<sharename> /user:<domain>\<user> <pass>
dir Z:\
```




