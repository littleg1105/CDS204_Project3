# Security Documentation

This document provides a comprehensive overview of the security features implemented in the Secure E-Shop application, including protections against common web vulnerabilities and security best practices.

## Security Architecture

The Secure E-Shop application demonstrates a security-first approach with multiple layers of protection:

- **Authentication Security**: Protection against brute force attacks, timing attacks, and user enumeration
- **Data Protection**: Thorough input sanitization and validation for all user inputs
- **Transport Security**: Properly configured HTTPS with HSTS implementation
- **Protection Against Common Attacks**: Comprehensive measures against XSS, CSRF, and SQL Injection
- **Rate Limiting**: Well-implemented rate limiting for sensitive operations
- **Password Security**: Secure password storage using Argon2 hashing

## Authentication Security

### Login Protection

The application implements multiple security measures in the login system:

1. **Protection Against Timing Attacks**:
   - Constant-time string comparison using `hmac.compare_digest()`
   - Fixed response time (minimum 300ms) regardless of authentication result
   - Random delay (0-100ms) to add variability to response timing

```python
# From LoginForm in forms.py
def constant_time_compare(val1, val2):
    return hmac.compare_digest(
        str(val1).encode('utf-8'),
        str(val2).encode('utf-8')
    )

# Authentication with timing attack protection
user = authenticate(self.request, username=username, password=password)

# Fixed time delay + random noise
random_delay = secrets.randbelow(100) / 1000
if execution_time < 0.3:
    time.sleep(0.3 - execution_time + random_delay)
```

2. **User Enumeration Prevention**:
   - Generic error messages that don't reveal if username exists
   - Identical timing for existing/non-existing users
   - Same behavior for all authentication failures

3. **Brute Force Protection**:
   - Integration with django-axes for tracking failed login attempts
   - Lockout after 5 failed attempts for 1 hour
   - Lockout based on combined username/IP address/user-agent
   - Rate limiting (10 attempts per minute per IP)

### Password Storage

1. **Hashing Algorithm**: 
   - Uses Argon2 (winner of the Password Hashing Competition)
   - Multiple fallback hashers for backward compatibility

```python
# From settings.py
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
]
```

2. **Password Validation**:
   - Minimum length requirement
   - Common password check
   - User attribute similarity check
   - Non-numeric requirement

### Session Management

1. **Session Security**:
   - Session key cycling after successful login (protection against session fixation)
   - Secure session cookies (HTTPS only, HTTPOnly flag)
   - SameSite cookie policy to prevent CSRF

```python
# After successful authentication
request.session.cycle_key()
```

2. **Session Data Handling**:
   - Secure storage of session data in the database
   - Proper cleanup after order completion
   - Temporary storage of sensitive data (e.g., shipping address)

```python
# Store data in session
request.session['shipping_address_id'] = address.id

# Clean up after use
if 'shipping_address_id' in request.session:
    del request.session['shipping_address_id']
```

## Two-Factor Authentication (2FA)

The admin interface is protected with Time-based One-Time Password (TOTP) two-factor authentication:

1. **OTP Implementation**:
   - Custom management command to set up OTP for users
   - QR code generation for easy setup with authenticator apps
   - Backup codes for account recovery

2. **OTP Administration**:
   - Custom OTP device management for admins
   - Ability to reset OTP devices when needed

## Protection Against Common Web Vulnerabilities

### Cross-Site Scripting (XSS) Protection

Multiple layers of XSS protection:

1. **Input Sanitization**:
   - All user inputs sanitized with bleach
   - Type validation for numeric fields
   - HTML entities escaped

```python
# From catalog_view in views.py
search_query = request.GET.get('q', '')
clean_query = bleach.clean(search_query)
```

2. **Output Escaping**:
   - Django template automatic escaping
   - Double sanitization in context processors
   - Safe data attributes for JavaScript access

3. **Content Security Policy**:
   - Strict CSP header configuration
   - Resource restrictions (self-origin for most resources)
   - Limited external sources (only CDN)

```python
# From settings.py
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "https://cdn.jsdelivr.net")
CSP_STYLE_SRC = ("'self'", "https://cdn.jsdelivr.net")
CSP_FONT_SRC = ("'self'", "https://cdn.jsdelivr.net")
CSP_IMG_SRC = ("'self'", "data:")
CSP_CONNECT_SRC = ("'self'",)
```

### Cross-Site Request Forgery (CSRF) Protection

Comprehensive CSRF protection implemented:

1. **CSRF Tokens**:
   - Django's built-in CSRF middleware
   - CSRF token in all forms
   - CSRF token in AJAX requests

```html
<!-- In form templates -->
<form method="post">
    {% csrf_token %}
    <!-- form fields -->
</form>
```

```javascript
// From cart.js
const csrfToken = this.getAttribute('data-csrf-token');

fetch('/add-to-cart/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrfToken
    },
    body: JSON.stringify({ product_id: productId })
})
```

2. **Cookie Settings**:
   - CSRF cookies with SameSite policy
   - Secure flag for HTTPS-only
   - Limited trusted origins

```python
# From settings.py
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'Lax'
```

### SQL Injection Protection

Secure database interaction:

1. **Django ORM**:
   - Exclusive use of Django ORM for database queries
   - Parameterized queries for all database operations
   - No raw SQL queries

```python
# Safe query using the ORM
products = Product.objects.filter(
    Q(name__icontains=clean_query) | 
    Q(description__icontains=clean_query)
)
```

2. **Input Sanitization**:
   - All inputs sanitized before use in queries
   - Type validation for IDs and numeric values

### Rate Limiting

Multiple layers of rate limiting:

1. **Login Rate Limiting**:
   - 10 attempts per minute per IP
   - django-axes for additional brute force protection

2. **Cart Operations**:
   - 20 requests per minute per user for add/update/remove

3. **Payment Processing**:
   - 5 submissions per minute per user

4. **Implementation**:
   - Throttling based on IP or user ID
   - Cache-based tracking of request counts
   - Graceful failure with 429 responses

```python
@ratelimit(key='ip', rate='10/m', method=['POST'], block=True)
def login_view(request):
    # Protected view implementation
```

## Transport Layer Security

HTTPS implementation:

1. **SSL Configuration**:
   - SSL redirect enabled
   - HTTPS-only cookies
   - HSTS headers

2. **Security Headers**:
   - Strict-Transport-Security
   - X-Content-Type-Options: nosniff
   - X-XSS-Protection enabled

```python
# From settings.py
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

## Form Validation and Input Sanitization

The application implements thorough form validation and sanitization:

1. **ShippingAddress Form**:
   - Regular expression validation for postal codes, phone numbers
   - Email validation with format checking and domain verification
   - Automatic HTML sanitization with bleach

2. **Login Form**:
   - Sanitized error messages
   - Protection against timing attacks

Example of email validation with domain verification:

```python
# From forms.py (ShippingAddressForm)
def clean_email(self):
    email = self.cleaned_data.get('email')
    
    if email:
        # Basic format validation with regex
        email_pattern = r'^[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]{0,63}[a-zA-Z0-9])?@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
        if not re.match(email_pattern, email):
            raise ValidationError('Η διεύθυνση email δεν είναι έγκυρη. Ελέγξτε τη μορφή της.')
```

## Logging and Error Handling

Security event logging:

1. **Logger Configuration**:
   - Separate security logger
   - File and console handlers
   - Detailed formatting

2. **Events Logged**:
   - Failed login attempts
   - Rate limit violations
   - Payment processing
   - Error conditions

```python
# From settings.py
LOGGING = {
    # ...
    'loggers': {
        'security': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
    }
}
```

## Known Limitations and Security Risks

Despite the comprehensive security measures, the following limitations are acknowledged:

1. **Development Environment Limitations**:
   - Self-signed certificate in development (not suitable for production)
   - SQLite database (not ideal for production)

2. **Additional Security Measures Needed**:
   - Comprehensive rate limiting for all API endpoints
   - Additional validation for shipping addresses
   - Real payment gateway integration (current implementation is simulated)
   - More comprehensive logging and monitoring
   - CAPTCHA implementation

## Security Testing

The application includes dedicated security tests:

1. **Rate Limiting Tests**:
   - Verify rate limits for login, cart operations, payment
   - Confirm proper 429 responses

2. **CSRF Tests**:
   - Ensure CSRF protection on all forms
   - Verify AJAX CSRF handling

3. **XSS Tests**:
   - Test input sanitization
   - Confirm output escaping

4. **Authentication Tests**:
   - Timing attack protection
   - Brute force mitigation
   - Session security

## Security Recommendations

For production deployment, the following additional security measures are recommended:

1. **Web Application Firewall (WAF)**:
   - Implement a WAF for additional protection against common attacks

2. **Enhanced Authentication**:
   - Extend two-factor authentication to all users
   - Implement OAuth integration for third-party login
   - Add password complexity visualization

3. **Additional Security Headers**:
   - Add Referrer-Policy header
   - Implement Feature-Policy/Permissions-Policy headers
   - Consider Subresource Integrity for CDN resources

4. **Infrastructure Security**:
   - Regular security updates for all system components
   - Database encryption at rest
   - DDoS protection
