# Security Modifications Report - E-Shop Application

## Executive Summary

This report documents all security modifications made to the E-Shop application to create an intentionally vulnerable version for educational penetration testing purposes. The modifications were carefully implemented to introduce realistic security vulnerabilities while maintaining application functionality.

---

## Part 1: Implemented Security Modifications

### 1. SQL Injection Vulnerability

#### Location: `eshop/views.py` (catalog_view function, lines 361-410)

**Original Secure Implementation:**
```python
# Django ORM with parameterized queries
products = Product.objects.filter(
    Q(name__icontains=search_query) | 
    Q(description__icontains=search_query)
)
```

**Modified Vulnerable Implementation:**
```python
# Lines 367-376: Direct SQL concatenation
from django.db import connection

raw_query = f"""
SELECT id, name, description, price, created_at, updated_at 
FROM eshop_product 
WHERE name LIKE '%%{search_query}%%' 
OR description LIKE '%%{search_query}%%'
"""

with connection.cursor() as cursor:
    cursor.execute(raw_query)  # Direct execution without sanitization
```

**Additional Changes:**
- Added error message exposure (line 409) to display database errors
- Implemented UUID to string conversion logic for raw SQL results
- Added vulnerability comments explaining the security issue

---

### 2. Cross-Site Scripting (XSS) Vulnerabilities

#### 2.1 Stored XSS - Product Review System

**New Files Created:**
- `eshop/models/reviews.py` - ProductReview model without sanitization
- `eshop/templates/eshop/product_detail.html` - Modified to display reviews unsafely

**Original Secure Implementation:**
```python
# In forms.py - ShippingAddressForm had bleach sanitization
def clean(self):
    cleaned_data = super().clean()
    for field in self.fields:
        if field in cleaned_data and isinstance(cleaned_data[field], str):
            cleaned_data[field] = bleach.clean(cleaned_data[field])
    return cleaned_data
```

**Modified Vulnerable Implementation:**

a) **Created ProductReviewForm** (`forms.py`, lines 402-448):
```python
class ProductReviewForm(forms.Form):
    """
    Form for product reviews - INTENTIONALLY VULNERABLE TO XSS
    """
    def clean(self):
        """
        VULNERABILITY: No sanitization of user input
        """
        cleaned_data = super().clean()
        # VULNERABILITY: Intentionally NOT sanitizing input
        # cleaned_data['title'] = bleach.clean(cleaned_data.get('title', ''))
        # cleaned_data['content'] = bleach.clean(cleaned_data.get('content', ''))
        return cleaned_data
```

b) **Modified product_detail.html** (lines 34-51):
```django
<!-- VULNERABILITY: XSS - Reviews displayed without escaping -->
{% autoescape off %}
{% for review in reviews %}
    <div class="card mb-3">
        <div class="card-body">
            <h5 class="card-title">{{ review.title }}</h5>
            <p class="card-text">{{ review.content }}</p>
        </div>
    </div>
{% endfor %}
{% endautoescape %}
```

c) **Added submit_review view** (`views.py`, lines 941-981):
```python
@login_required
def submit_review(request, product_id):
    # No sanitization before saving
    review = ProductReview(
        product=product,
        user=request.user,
        title=form.cleaned_data['title'],  # No sanitization
        content=form.cleaned_data['content'],  # No sanitization
        rating=form.cleaned_data['rating']
    )
    review.save()
```

#### 2.2 Reflected XSS - Search Results

**Modified Template** (`catalog.html`, line 26):
```django
<!-- Changed from -->
{{ search_query }}

<!-- To -->
{{ search_query|safe }}
```

**Modified View** (`views.py`, line 429):
```python
context = {
    'search_query': search_query,  # VULNERABILITY: Using unsanitized query
}
```

---

### 3. Insecure Direct Object Reference (IDOR)

#### Location: `eshop/views.py` (view_order function, lines 1021-1056)

**Original Secure Implementation:**
```python
@login_required
def view_order(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    # Authorization check ensures user owns the order
```

**Modified Vulnerable Implementation:**
```python
@login_required
def view_order(request, order_id):
    """
    View order details - VULNERABLE TO IDOR
    WARNING: This view does NOT check if the order belongs to the logged-in user
    """
    # VULNERABILITY: No access control check
    # Should verify: order.user == request.user
    try:
        order = Order.objects.get(id=order_id)  # Direct access without authorization
        
        # VULNERABILITY: Exposing sensitive information
        context = {
            'order': order,
            'order_items': order.items.all(),
            'shipping_address': order.shipping_address,
            'user_info': {
                'username': order.user.username,
                'email': order.user.email,
                'date_joined': order.user.date_joined
            }
        }
```

---

### 4. Cross-Site Request Forgery (CSRF) Vulnerabilities

#### New Vulnerable Endpoints Created:

**4.1 Credit Transfer Function** (`views.py`, lines 1087-1122):
```python
@login_required
@csrf_exempt  # VULNERABILITY: CSRF protection disabled
def transfer_credits(request):
    """
    Transfer store credits between users - VULNERABLE TO CSRF
    """
    if request.method == 'POST':
        recipient_username = request.POST.get('recipient')
        amount = request.POST.get('amount')
        
        # VULNERABILITY: No confirmation or additional authentication
        # Transfers happen immediately without user confirmation
```

**4.2 Email Update Function** (`views.py`, lines 1126-1147):
```python
@login_required  
@csrf_exempt  # VULNERABILITY: CSRF protection disabled
def update_user_email(request):
    """
    Update user email - VULNERABLE TO CSRF
    """
    if request.method == 'POST':
        new_email = request.POST.get('email')
        
        # VULNERABILITY: No email verification
        # Changes email immediately without confirmation
        request.user.email = new_email
        request.user.save()
```

**4.3 Created Vulnerable Forms** (`user_profile.html`):
```html
<!-- Forms intentionally missing CSRF tokens -->
<form method="post" action="{% url 'eshop:transfer_credits' %}">
    <!-- WARNING: No CSRF token! -->
    <div class="form-group">
        <label for="recipient">Recipient Username:</label>
        <input type="text" class="form-control" name="recipient" required>
    </div>
    <button type="submit" class="btn btn-danger">Transfer Credits</button>
</form>
```

---

### 5. Authentication Weaknesses

#### 5.1 User Enumeration Vulnerability

**Location:** `eshop/forms.py` (LoginForm, lines 154-174)

**Original Secure Implementation:**
```python
def clean(self):
    # Generic error message for both cases
    raise ValidationError("Invalid credentials")
```

**Modified Vulnerable Implementation:**
```python
def clean(self):
    if username and password:
        # VULNERABILITY: User Enumeration
        try:
            user = User.objects.get(username=username)
            if not user.check_password(password):
                # Different error message reveals password is wrong
                raise ValidationError(
                    "Invalid password for user '{}'".format(username)
                )
        except User.DoesNotExist:
            # Different error message reveals username doesn't exist
            raise ValidationError(
                "Username '{}' does not exist in our system".format(username)
            )
```

#### 5.2 Disabled Security Features

**In `settings.py`:**

a) **Removed CAPTCHA** (`forms.py`, lines 101-106):
```python
# VULNERABILITY: CAPTCHA removed to allow brute force attacks
# WARNING: No protection against automated attacks
# captcha = CaptchaField(
#     error_messages={'invalid': 'Λάθος CAPTCHA. Προσπαθήστε ξανά.'}
# )
```

b) **Disabled Rate Limiting** (`settings.py`, lines 141-142):
```python
# VULNERABILITY: Brute force protection disabled
# 'axes.middleware.AxesMiddleware',
# 'django_ratelimit.middleware.RatelimitMiddleware',
```

c) **Disabled Two-Factor Authentication** (`settings.py`, lines 92-96):
```python
# VULNERABILITY: OTP disabled - no two-factor authentication
# 'django_otp',
# 'django_otp.plugins.otp_totp',
# 'django_otp.plugins.otp_static',
```

---

### 6. Weak Cryptography Implementation

#### Location: `eshop_project/settings.py`

**6.1 Password Hashing Downgrade** (lines 299-303):

**Original Secure Implementation:**
```python
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
]
```

**Modified Vulnerable Implementation:**
```python
# VULNERABILITY: Weak password hashing
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',  # INSECURE: MD5 is broken
    # 'django.contrib.auth.hashers.Argon2PasswordHasher',  # Commented out secure option
]
```

**6.2 Session Security Weakening** (lines 371-379):

**Original Secure Implementation:**
```python
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
```

**Modified Vulnerable Implementation:**
```python
# VULNERABILITY: Session cookies sent over HTTP
SESSION_COOKIE_SECURE = False

# VULNERABILITY: Insecure session cookies
# Allows JavaScript access to session cookies (XSS can steal sessions)
SESSION_COOKIE_HTTPONLY = False

# VULNERABILITY: No SameSite protection
# SESSION_COOKIE_SAMESITE = 'Lax'  # Disabled
```

---

### 7. Security Misconfiguration

#### 7.1 Debug Mode Enabled

**Location:** `settings.py` (line 57)

**Original:**
```python
DEBUG = False
```

**Modified:**
```python
# VULNERABILITY: Debug mode enabled
DEBUG = True
```

**Impact:**
- Exposes full stack traces on errors
- Shows all URL patterns on 404 pages
- Reveals environment variables
- Displays source code snippets

#### 7.2 Disabled Security Headers

**Location:** `settings.py` (line 114)

**Original:**
```python
MIDDLEWARE = [
    'eshop.middleware.SecurityHeadersMiddleware',
    # ... other middleware
]
```

**Modified:**
```python
# VULNERABILITY: Security headers disabled
# 'eshop.middleware.SecurityHeadersMiddleware',
```

**Missing Headers:**
- X-Frame-Options (clickjacking protection)
- X-Content-Type-Options (MIME sniffing protection)
- Content-Security-Policy (XSS mitigation)
- Strict-Transport-Security (HTTPS enforcement)
- X-XSS-Protection (browser XSS filter)

---

### 8. Information Disclosure Enhancements

#### 8.1 Database Error Exposure

**Location:** `views.py` (catalog_view, line 409)

**Added:**
```python
except Exception as e:
    # VULNERABILITY: Information Disclosure
    # Exposing database errors helps attackers understand the schema
    products = []
    messages.error(request, f"Database error: {str(e)}")
```

#### 8.2 Detailed Error Messages

**Various Locations:**
- Login form: Reveals whether username exists
- Order viewing: Shows "Order not found" vs access denied
- SQL errors: Display full query and error details

---

### 9. Navigation and UI Modifications

#### 9.1 Added Vulnerable Navigation Links

**Location:** `base.html` (lines 37-41)

**Added:**
```django
<li class="nav-item">
    <a class="nav-link" href="{% url 'eshop:user_profile' %}">Προφίλ</a>
</li>
<li class="nav-item">
    <a class="nav-link" href="{% url 'eshop:list_user_orders' %}">Οι Παραγγελίες μου</a>
</li>
```

#### 9.2 Removed Security Warnings

**Various Templates:**
- Commented out vulnerability demonstration alerts
- Removed security notices from forms
- Hidden CAPTCHA disabled warnings

---

## Summary of Security Degradations

### Critical Changes:
1. **Direct SQL execution** replacing parameterized queries
2. **Disabled input sanitization** across all forms
3. **Removed authorization checks** on sensitive operations
4. **Disabled CSRF protection** on state-changing endpoints
5. **Downgraded to MD5** password hashing

### High-Risk Changes:
1. **Enabled user enumeration** through different error messages
2. **Disabled rate limiting** allowing brute force attacks
3. **Made session cookies accessible** to JavaScript
4. **Exposed detailed error messages** including stack traces
5. **Removed two-factor authentication**

### Medium-Risk Changes:
1. **Disabled security headers** middleware
2. **Enabled DEBUG mode** in production
3. **Removed CAPTCHA** protection
4. **Disabled secure cookie flags**

### Total Files Modified:
- **Core Python Files**: 5 (views.py, forms.py, models/, settings.py, urls.py)
- **Template Files**: 8+ (base.html, catalog.html, product_detail.html, user_profile.html, etc.)
- **New Files Created**: 3 (reviews.py, transfer_credits.html, various templates)

### Lines of Code Changed:
- **Added**: ~500 lines of vulnerable code
- **Modified**: ~200 lines to remove security controls
- **Commented Out**: ~100 lines of security features

---

## Conclusion

The modifications successfully transformed a secure e-commerce application into a realistic penetration testing target. Each vulnerability was carefully implemented to be:
- **Exploitable**: All vulnerabilities have working proof-of-concepts
- **Realistic**: Based on common real-world security mistakes
- **Educational**: Clear comments explain each security issue
- **Functional**: The application remains fully operational

The vulnerable version serves as an excellent educational tool for learning web application security testing while maintaining the appearance and functionality of a legitimate e-commerce platform.