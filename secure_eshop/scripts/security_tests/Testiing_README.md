# Security Testing Scripts

This directory contains security testing scripts for the secure_eshop application. These scripts are designed to test various security aspects of the application including authentication, injection vulnerabilities, XSS, CSRF, and encryption.

## Directory Structure

```
security_tests/
├── authentication/    # Authentication security tests
├── injection/         # SQL injection tests
├── xss/               # Cross-Site Scripting tests
├── csrf/              # Cross-Site Request Forgery tests
├── encryption/        # Encryption and data protection tests
└── README.md          # This file
```

## Test Descriptions

### Authentication Tests

1. **Brute Force Attack Test** (`authentication/brute_force_test.py`)
   - Tests the application's resistance to brute force password attacks
   - Checks if rate limiting is implemented
   - Checks if account lockout is implemented after multiple failed attempts

2. **User Enumeration Test** (`authentication/user_enumeration_test.py`)
   - Tests if the application leaks information about valid usernames
   - Checks if there are differences in responses for valid vs. invalid usernames
   - Analyzes timing differences that could enable user enumeration

3. **Timing Attack Test** (`authentication/timing_attack_test.py`)
   - Tests for timing side-channel vulnerabilities in authentication
   - Measures response time differences for various usernames and passwords
   - Checks if constant-time comparison is used for credentials

4. **OTP Brute Force Test** (`authentication/otp_brute_force_test.py`)
   - Tests the two-factor authentication implementation
   - Checks if OTP tokens can be brute-forced
   - Checks if rate limiting is applied to OTP verification

### Injection Tests

1. **SQL Injection Test** (`injection/sql_injection_test.py`)
   - Tests for SQL injection vulnerabilities in forms and URL parameters
   - Checks if the application is using parameterized queries
   - Tests login bypass through SQL injection

### Cross-Site Scripting (XSS) Tests

1. **XSS Test** (`xss/xss_test.py`)
   - Tests for Reflected XSS vulnerabilities
   - Tests for Stored XSS vulnerabilities
   - Tests for DOM-based XSS vulnerabilities
   - Analyzes Content Security Policy effectiveness

### Cross-Site Request Forgery (CSRF) Tests

1. **CSRF Test** (`csrf/csrf_test.py`)
   - Tests if forms have proper CSRF protection
   - Checks if CSRF tokens are validated correctly
   - Analyzes cookie security settings (SameSite, Secure, HttpOnly)
   - Generates proof-of-concept CSRF attack pages

### Encryption Tests

1. **Encryption Test** (`encryption/encryption_test.py`)
   - Analyzes database for proper encryption of sensitive data
   - Checks for hardcoded encryption keys
   - Analyzes encryption implementation for security issues
   - Reviews Django security settings

## Usage

Each script can be run independently with appropriate parameters. Most scripts require a target URL and optionally a username and password.

### Example Usage

```bash
# Brute force attack test
python authentication/brute_force_test.py https://localhost:8000/login/ admin

# User enumeration test
python authentication/user_enumeration_test.py https://localhost:8000/login/ admin

# SQL injection test
python injection/sql_injection_test.py https://localhost:8000/ admin password

# XSS test
python xss/xss_test.py https://localhost:8000/ admin password

# CSRF test
python csrf/csrf_test.py https://localhost:8000/ admin password

# Encryption test
python encryption/encryption_test.py /path/to/db.sqlite3 /path/to/app
```

## Dependencies

These scripts require the following Python packages:

- requests
- beautifulsoup4
- tabulate
- selenium (for XSS DOM testing)
- cryptography (for encryption tests)
- matplotlib (for data visualization)
- numpy (for data analysis)
- scipy (for statistical analysis)

You can install all dependencies with:

```bash
pip install -r scripts/security_tests/testing_requirements.txt
```

Or install them individually:

```bash
pip install requests beautifulsoup4 tabulate selenium cryptography matplotlib numpy scipy
```

## Security Note

These scripts are intended for security testing of your own applications or applications you have permission to test. Never use these tools against systems without explicit permission.

## Disclaimer

These scripts are provided as is without any warranty. The authors are not responsible for any misuse or damage caused by these scripts.