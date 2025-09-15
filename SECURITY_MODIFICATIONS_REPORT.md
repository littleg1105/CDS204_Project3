# Αναφορά Τροποποιήσεων Ασφαλείας - Εφαρμογή E-Shop

## Εκτελεστική Περίληψη

Αυτή η αναφορά τεκμηριώνει όλες τις τροποποιήσεις ασφαλείας που έγιναν στην εφαρμογή E-Shop για τη δημιουργία μιας εσκεμμένα ευάλωτης έκδοσης για εκπαιδευτικούς σκοπούς δοκιμών διείσδυσης. Οι τροποποιήσεις υλοποιήθηκαν προσεκτικά για την εισαγωγή ρεαλιστικών ευπαθειών ασφαλείας διατηρώντας παράλληλα τη λειτουργικότητα της εφαρμογής.

---

## Μέρος 1: Υλοποιημένες Τροποποιήσεις Ασφαλείας

### 1. Ευπάθεια SQL Injection

#### Τοποθεσία: `eshop/views.py` (συνάρτηση catalog_view, γραμμές 361-410)

**Αρχική Ασφαλής Υλοποίηση:**
```python
# Django ORM with parameterized queries
products = Product.objects.filter(
    Q(name__icontains=search_query) | 
    Q(description__icontains=search_query)
)
```

**Τροποποιημένη Ευάλωτη Υλοποίηση:**
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

**Πρόσθετες Αλλαγές:**
- Προστέθηκε έκθεση μηνυμάτων σφάλματος (γραμμή 409) για εμφάνιση σφαλμάτων βάσης δεδομένων
- Υλοποιήθηκε λογική μετατροπής UUID σε string για αποτελέσματα raw SQL
- Προστέθηκαν σχόλια ευπάθειας που εξηγούν το ζήτημα ασφαλείας

---

### 2. Ευπάθειες Cross-Site Scripting (XSS)

#### 2.1 Αποθηκευμένο XSS - Σύστημα Κριτικών Προϊόντων

**Νέα Αρχεία που Δημιουργήθηκαν:**
- `eshop/models/reviews.py` - Μοντέλο ProductReview χωρίς εξυγίανση
- `eshop/templates/eshop/product_detail.html` - Τροποποιήθηκε για μη ασφαλή εμφάνιση κριτικών

**Αρχική Ασφαλής Υλοποίηση:**
```python
# In forms.py - ShippingAddressForm had bleach sanitization
def clean(self):
    cleaned_data = super().clean()
    for field in self.fields:
        if field in cleaned_data and isinstance(cleaned_data[field], str):
            cleaned_data[field] = bleach.clean(cleaned_data[field])
    return cleaned_data
```

**Τροποποιημένη Ευάλωτη Υλοποίηση:**

α) **Δημιουργήθηκε ProductReviewForm** (`forms.py`, γραμμές 402-448):
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

β) **Τροποποιημένο product_detail.html** (γραμμές 34-51):
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

γ) **Προστέθηκε submit_review view** (`views.py`, γραμμές 941-981):
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

#### 2.2 Reflected XSS - Αποτελέσματα Αναζήτησης

**Τροποποιημένο Template** (`catalog.html`, γραμμή 26):
```django
<!-- Changed from -->
{{ search_query }}

<!-- To -->
{{ search_query|safe }}
```

**Τροποποιημένο View** (`views.py`, γραμμή 429):
```python
context = {
    'search_query': search_query,  # VULNERABILITY: Using unsanitized query
}
```

---

### 3. Ανασφαλής Άμεση Αναφορά Αντικειμένου (IDOR)

#### Τοποθεσία: `eshop/views.py` (συνάρτηση view_order, γραμμές 1021-1056)

**Αρχική Ασφαλής Υλοποίηση:**
```python
@login_required
def view_order(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    # Authorization check ensures user owns the order
```

**Τροποποιημένη Ευάλωτη Υλοποίηση:**
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

### 4. Ευπάθειες Cross-Site Request Forgery (CSRF)

#### Νέα Ευάλωτα Endpoints που Δημιουργήθηκαν:

**4.1 Λειτουργία Μεταφοράς Πιστώσεων** (`views.py`, γραμμές 1087-1122):
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

**4.2 Λειτουργία Ενημέρωσης Email** (`views.py`, γραμμές 1126-1147):
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

**4.3 Δημιουργήθηκαν Ευάλωτες Φόρμες** (`user_profile.html`):
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

### 5. Αδυναμίες Ταυτοποίησης

#### 5.1 Ευπάθεια Απαρίθμησης Χρηστών

**Τοποθεσία:** `eshop/forms.py` (LoginForm, γραμμές 154-174)

**Αρχική Ασφαλής Υλοποίηση:**
```python
def clean(self):
    # Generic error message for both cases
    raise ValidationError("Invalid credentials")
```

**Τροποποιημένη Ευάλωτη Υλοποίηση:**
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

#### 5.2 Απενεργοποιημένα Χαρακτηριστικά Ασφαλείας

**Στο `settings.py`:**

α) **Αφαιρέθηκε το CAPTCHA** (`forms.py`, γραμμές 101-106):
```python
# VULNERABILITY: CAPTCHA removed to allow brute force attacks
# WARNING: No protection against automated attacks
# captcha = CaptchaField(
#     error_messages={'invalid': 'Λάθος CAPTCHA. Προσπαθήστε ξανά.'}
# )
```

β) **Απενεργοποιήθηκε ο Περιορισμός Ρυθμού** (`settings.py`, γραμμές 141-142):
```python
# VULNERABILITY: Brute force protection disabled
# 'axes.middleware.AxesMiddleware',
# 'django_ratelimit.middleware.RatelimitMiddleware',
```

γ) **Απενεργοποιήθηκε η Ταυτοποίηση Δύο Παραγόντων** (`settings.py`, γραμμές 92-96):
```python
# VULNERABILITY: OTP disabled - no two-factor authentication
# 'django_otp',
# 'django_otp.plugins.otp_totp',
# 'django_otp.plugins.otp_static',
```

---

### 6. Αδύναμη Υλοποίηση Κρυπτογραφίας

#### Τοποθεσία: `eshop_project/settings.py`

**6.1 Υποβάθμιση Κατακερματισμού Κωδικών** (γραμμές 299-303):

**Αρχική Ασφαλής Υλοποίηση:**
```python
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
]
```

**Τροποποιημένη Ευάλωτη Υλοποίηση:**
```python
# VULNERABILITY: Weak password hashing
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',  # INSECURE: MD5 is broken
    # 'django.contrib.auth.hashers.Argon2PasswordHasher',  # Commented out secure option
]
```

**6.2 Εξασθένηση Ασφάλειας Συνόδου** (γραμμές 371-379):

**Αρχική Ασφαλής Υλοποίηση:**
```python
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
```

**Τροποποιημένη Ευάλωτη Υλοποίηση:**
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

### 7. Λανθασμένη Διαμόρφωση Ασφαλείας

#### 7.1 Ενεργοποιημένη Λειτουργία Debug

**Τοποθεσία:** `settings.py` (γραμμή 57)

**Αρχική:**
```python
DEBUG = False
```

**Τροποποιημένη:**
```python
# VULNERABILITY: Debug mode enabled
DEBUG = True
```

**Επίπτωση:**
- Εκθέτει πλήρη stack traces σε σφάλματα
- Εμφανίζει όλα τα URL patterns σε σελίδες 404
- Αποκαλύπτει μεταβλητές περιβάλλοντος
- Εμφανίζει αποσπάσματα πηγαίου κώδικα

#### 7.2 Απενεργοποιημένες Κεφαλίδες Ασφαλείας

**Τοποθεσία:** `settings.py` (γραμμή 114)

**Αρχική:**
```python
MIDDLEWARE = [
    'eshop.middleware.SecurityHeadersMiddleware',
    # ... other middleware
]
```

**Τροποποιημένη:**
```python
# VULNERABILITY: Security headers disabled
# 'eshop.middleware.SecurityHeadersMiddleware',
```

**Κεφαλίδες που Λείπουν:**
- X-Frame-Options (προστασία από clickjacking)
- X-Content-Type-Options (προστασία από MIME sniffing)
- Content-Security-Policy (μετριασμός XSS)
- Strict-Transport-Security (επιβολή HTTPS)
- X-XSS-Protection (φίλτρο XSS του browser)

---

### 8. Βελτιώσεις Αποκάλυψης Πληροφοριών

#### 8.1 Έκθεση Σφαλμάτων Βάσης Δεδομένων

**Τοποθεσία:** `views.py` (catalog_view, γραμμή 409)

**Προστέθηκε:**
```python
except Exception as e:
    # VULNERABILITY: Information Disclosure
    # Exposing database errors helps attackers understand the schema
    products = []
    messages.error(request, f"Database error: {str(e)}")
```

#### 8.2 Λεπτομερή Μηνύματα Σφάλματος

**Διάφορες Τοποθεσίες:**
- Φόρμα σύνδεσης: Αποκαλύπτει αν υπάρχει το username
- Προβολή παραγγελίας: Εμφανίζει "Order not found" vs access denied
- Σφάλματα SQL: Εμφανίζει πλήρες query και λεπτομέρειες σφάλματος

---

### 9. Τροποποιήσεις Πλοήγησης και UI

#### 9.1 Προστέθηκαν Ευάλωτοι Σύνδεσμοι Πλοήγησης

**Τοποθεσία:** `base.html` (γραμμές 37-41)

**Προστέθηκαν:**
```django
<li class="nav-item">
    <a class="nav-link" href="{% url 'eshop:user_profile' %}">Προφίλ</a>
</li>
<li class="nav-item">
    <a class="nav-link" href="{% url 'eshop:list_user_orders' %}">Οι Παραγγελίες μου</a>
</li>
```

#### 9.2 Αφαιρέθηκαν Προειδοποιήσεις Ασφαλείας

**Διάφορα Templates:**
- Σχολιάστηκαν οι ειδοποιήσεις επίδειξης ευπαθειών
- Αφαιρέθηκαν οι ειδοποιήσεις ασφαλείας από τις φόρμες
- Κρύφτηκαν οι προειδοποιήσεις απενεργοποίησης CAPTCHA

---

## Σύνοψη Υποβαθμίσεων Ασφαλείας

### Κρίσιμες Αλλαγές:
1. **Άμεση εκτέλεση SQL** αντικαθιστώντας παραμετροποιημένα queries
2. **Απενεργοποιημένη εξυγίανση εισόδου** σε όλες τις φόρμες
3. **Αφαιρέθηκαν έλεγχοι εξουσιοδότησης** σε ευαίσθητες λειτουργίες
4. **Απενεργοποιημένη προστασία CSRF** σε endpoints αλλαγής κατάστασης
5. **Υποβάθμιση σε MD5** για κατακερματισμό κωδικών

### Αλλαγές Υψηλού Κινδύνου:
1. **Ενεργοποιημένη απαρίθμηση χρηστών** μέσω διαφορετικών μηνυμάτων σφάλματος
2. **Απενεργοποιημένος περιορισμός ρυθμού** επιτρέποντας επιθέσεις brute force
3. **Έγιναν προσβάσιμα τα session cookies** στη JavaScript
4. **Εκτεθειμένα λεπτομερή μηνύματα σφάλματος** συμπεριλαμβανομένων stack traces
5. **Αφαιρέθηκε η ταυτοποίηση δύο παραγόντων**

### Αλλαγές Μέτριου Κινδύνου:
1. **Απενεργοποιημένο middleware κεφαλίδων ασφαλείας**
2. **Ενεργοποιημένη λειτουργία DEBUG** σε παραγωγή
3. **Αφαιρέθηκε προστασία CAPTCHA**
4. **Απενεργοποιημένες secure cookie flags**

### Σύνολο Τροποποιημένων Αρχείων:
- **Βασικά Αρχεία Python**: 5 (views.py, forms.py, models/, settings.py, urls.py)
- **Αρχεία Template**: 8+ (base.html, catalog.html, product_detail.html, user_profile.html, κτλ.)
- **Νέα Αρχεία που Δημιουργήθηκαν**: 3 (reviews.py, transfer_credits.html, διάφορα templates)

### Γραμμές Κώδικα που Άλλαξαν:
- **Προστέθηκαν**: ~500 γραμμές ευάλωτου κώδικα
- **Τροποποιήθηκαν**: ~200 γραμμές για αφαίρεση ελέγχων ασφαλείας
- **Σχολιάστηκαν**: ~100 γραμμές χαρακτηριστικών ασφαλείας

---

## Συμπέρασμα

Οι τροποποιήσεις μετέτρεψαν επιτυχώς μια ασφαλή εφαρμογή ηλεκτρονικού εμπορίου σε έναν ρεαλιστικό στόχο δοκιμών διείσδυσης. Κάθε ευπάθεια υλοποιήθηκε προσεκτικά ώστε να είναι:
- **Εκμεταλλεύσιμη**: Όλες οι ευπάθειες έχουν λειτουργικά proof-of-concepts
- **Ρεαλιστική**: Βασισμένη σε κοινά λάθη ασφαλείας του πραγματικού κόσμου
- **Εκπαιδευτική**: Σαφή σχόλια εξηγούν κάθε ζήτημα ασφαλείας
- **Λειτουργική**: Η εφαρμογή παραμένει πλήρως λειτουργική

Η ευάλωτη έκδοση χρησιμεύει ως εξαιρετικό εκπαιδευτικό εργαλείο για την εκμάθηση δοκιμών ασφαλείας διαδικτυακών εφαρμογών, διατηρώντας παράλληλα την εμφάνιση και λειτουργικότητα μιας νόμιμης πλατφόρμας ηλεκτρονικού εμπορίου.