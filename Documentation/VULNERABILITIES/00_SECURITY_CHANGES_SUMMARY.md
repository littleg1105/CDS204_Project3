# Security Changes Summary

## Recent Modifications for Vulnerability Testing

### 1. SQL Injection Fix and Testing (June 14, 2025)

#### Issue
- SQL query was referencing non-existent `stock` column
- UNION-based SQL injections were failing due to LIKE clause structure

#### Changes Made
- **views.py**: Removed `stock` from SQL query (line 368)
- **product_detail.html**: Removed stock display (line 12)

#### Working SQL Injection Payloads
- Basic: `' OR '1'='1`
- SQLMap confirmed working with proper session cookie

### 2. Cross-Origin Access for Kali VM Testing

#### Network Setup
- Host OS: 10.211.55.2
- Kali VM: 10.211.55.4

#### Configuration Changes

**Modified Files:**
1. **.env**
   - Added VM IPs to ALLOWED_HOSTS
   ```
   ALLOWED_HOSTS=...,10.211.55.2,10.211.55.4
   ```

2. **settings.py** (lines 459-475)
   - Disabled CSRF cookie security:
     ```python
     CSRF_COOKIE_SECURE = False  # Was True
     CSRF_COOKIE_SAMESITE = None  # Was 'Strict'
     ```
   - Added trusted origins:
     ```python
     CSRF_TRUSTED_ORIGINS = [
         'http://10.211.55.2:8000',
         'http://10.211.55.4:8000'
     ]
     ```

### 3. Existing Vulnerabilities Maintained

#### Authentication Weaknesses
- Weak MD5 password hashing
- User enumeration through different error messages
- No rate limiting on login attempts
- No CAPTCHA protection (disabled)

#### Session Management
- `SESSION_COOKIE_SECURE = False`
- `SESSION_COOKIE_HTTPONLY = False`
- Session fixation vulnerabilities

#### SQL Injection
- Raw SQL queries with string concatenation in catalog search
- Vulnerable endpoint: `/?q=`
- Information disclosure through error messages

#### XSS Vulnerabilities
- Product reviews displayed without escaping
- `{% autoescape off %}` in templates
- No input sanitization

#### CSRF Vulnerabilities
- `@csrf_exempt` decorators on sensitive endpoints
- `/transfer-credits/` and `/update-email/` endpoints

#### IDOR Vulnerabilities
- Direct object references in order viewing
- No authorization checks on `/order/<order_id>/`

## Testing Instructions

### From Host Machine
```bash
python manage.py runserver
# Access at http://127.0.0.1:8000
```

### From Kali VM
```bash
# On host machine
python manage.py runserver 0.0.0.0:8000

# From Kali
# Access at http://10.211.55.2:8000
```

### SQLMap Testing
```bash
# Get session cookie first by logging in
sqlmap -u "http://10.211.55.2:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8 \
       -T eshop_customuser \
       --dump
```

## Security Impact

These changes introduce/maintain the following vulnerabilities:
1. **A03:2021 – Injection** (SQL Injection)
2. **A07:2021 – Identification and Authentication Failures**
3. **A01:2021 – Broken Access Control** (IDOR)
4. **A03:2021 – Injection** (XSS)
5. **A05:2021 – Security Misconfiguration** (CSRF disabled)

## Important Notes

⚠️ **WARNING**: This configuration is intentionally vulnerable for educational penetration testing purposes only.

🔒 **For Production**: All these vulnerabilities must be fixed:
- Enable CSRF protection
- Use secure session cookies
- Implement parameterized queries
- Add proper authentication and authorization
- Enable rate limiting
- Sanitize all user inputs