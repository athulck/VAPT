
# Network VAPT

This is how the attack chain goes for us:

`Networks` >>> `Hosts` >>>>> `Open Ports` >>>>> `Services` >>>>> `Service Versions` >>>>>>>>>>>>> `Vulnerabilities` > `Exploits`

We are looking for mainly 2 things:
1. Does the system run any vulnerable versions of a service, which we can exploit?
2. Does the system run any misconfigured service, which we can exploit?

The first part covers all the vulnerabilities which could apper in the codebases of the service itself, and the second part covers the vulnerabilities which could appear in the config files. The first part is well-documented, published and tracked. The second part is most often not.


##### Challenges

1. Network VAPT is a numbers game. 1 network can have 100 hosts, each can have 10-30 services running, varying versions, multiple vulnerabilities and a lot of exploit PoCs but barely a handful of working exploits. Tracking, documenting, assessing and managing all these is the problem.

2. **The Defenders**: The firewalls, EDRs, IDS, IPS, network monitoring, SIEM tools, SOCs, NOCs and what not. Attacking enterprise networks are not fun. We literally have to be a network ninja and a ghost at the same time.

3. The Changing Network: It is totally a real prossibility that the network services may go down and new services may come up as you do your testing. Deal with it! 




We don't know if there is any firewalls, IDS or IPS sitting on the other side waiting for our nmap scans to show up. So it's important that we start sneaky and then progressively get louder and noisy as we gather information.

So, the quiter tools first and then the big automated tools (like Nessus, OpenVAS, Nikto, Nuclei).








#### dB: 0

If you have a list of IPs, you can ping them and check if they are all up and accessible. 

```bash
ping <IP>
```

**Note**: This is not a deterministic check, as hosts could be alive and blocking ICMP ping requests.

```powershell
Test-Connection -ComputerName <IP> -Count 2 -Quiet -ErrorAction Stop
```


#### dB: 1

This would bring up the open ports.
```bash
sudo nmap -sS -T2 -iL <IP_list> -oA Initial_TCP_Scan -v
```
There is a reason why we are not running the `-sV`, `-sC` or the `-O` scans. It is because these produce a lot of traffic, and may alert the defenders.


Use [nmaptocsv](https://github.com/maaaaz/nmaptocsv) to convert nmap outputs into CSV for reporting purposes.


Do a UDP Scan as well. 

**WARN**: UDP Scans can be really really slow. So, it's important to pick your targets well.

```bash
sudo nmap -sU --top-ports 20 -iL <IP_list> -oA Initial_TCP_Scan -v
```





For each Host, collect these informations:

 - [ ] IP Address
 - [ ] MAC Address
 - [ ] Vendor Name (OUI Lookup)
 - [ ] NetBIOS/DNS Name
 - [ ] OS Version




#### Appendix: Nmap Options and Flags

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
