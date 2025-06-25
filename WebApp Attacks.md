


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
