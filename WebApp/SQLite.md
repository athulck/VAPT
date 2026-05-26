# SQLite Databases

Suppose you have found an SQLite database on the server named `database.db`.

## Exfilteration

#### Method 1: Using Base64 encoding

Encode the file using base 64 and copy it.
```bash
base64 database.db
```

Decode the file:
```bash
base64 -d "<CONTENT>" > database.db
```

## Analysis

Open the database:
```bash
sqlite3 database.db
```

List tables:
```bash
.tables
```

Show Schema:
```bash
.schema
.schema <table_name>
```

Dump all data:
```bash
.dump
```

Query data:
```sql
SELECT * FROM <table>;
```
