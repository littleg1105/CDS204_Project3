# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Context: Vulnerable E-Shop for Penetration Testing
This is the VULNERABLE branch of the e-shop application, intentionally modified to contain security vulnerabilities for educational penetration testing purposes.

## Build/Run Commands
- Activate venv: `source venv/bin/activate` (macOS/Linux) or `venv\Scripts\activate` (Windows)
- Install requirements: `pip install -r requirements.txt`
- Run migrations: `python manage.py migrate`
- Run server (INSECURE MODE): `python manage.py runserver` (no HTTPS for easier testing)
- Run all tests: `python manage.py test --settings=eshop.tests.test_settings`
- Run security tests: `cd scripts/security_tests && python run_all_tests.py`
- Reset database: `cd scripts/db && ./reset_db.sh` or `python reset_database.py`

## Vulnerability Implementation Guidelines
**IMPORTANT**: This branch intentionally contains security vulnerabilities for educational purposes.

### Implemented Vulnerabilities:
1. **SQL Injection**
   - Location: `views.py` - catalog search functionality
   - Raw SQL queries with direct string concatenation
   - Vulnerable endpoints: `/catalog/?search=`

2. **Cross-Site Scripting (XSS)**
   - Location: Forms and templates
   - Removed bleach sanitization
   - Disabled Django auto-escaping in specific templates
   - Vulnerable inputs: Product reviews, user profile fields

3. **Authentication Weaknesses**
   - User enumeration via different error messages
   - No rate limiting on login attempts
   - Weak password hashing (MD5)
   - No CAPTCHA protection

4. **Broken Access Control**
   - Direct object references without authorization checks
   - Predictable sequential IDs instead of UUIDs

5. **Session Management Issues**
   - Insecure cookie settings (no HttpOnly, Secure flags)
   - Session fixation vulnerabilities

## Code Style Guidelines (Vulnerable Version)
- **Security Anti-Patterns**: Use raw SQL, disable input validation where vulnerabilities are needed
- **Error Handling**: Expose detailed error messages for information disclosure
- **Debug Mode**: Keep DEBUG=True to expose system information
- **Weak Cryptography**: Use MD5 for passwords, weak/no encryption for sensitive data

## Testing Vulnerabilities
- Use Burp Suite or OWASP ZAP for testing
- SQLMap for SQL injection testing
- Manual payloads for XSS testing
- Scripts in `scripts/security_tests/` for automated testing

## Documentation Requirements
- Document each vulnerability with:
  - Location in code
  - Exploitation steps
  - Impact assessment
  - Remediation (for the report)