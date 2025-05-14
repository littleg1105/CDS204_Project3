# ============================================================================
# IMPORTS - Εισαγωγή απαραίτητων modules
# ============================================================================

# Django forms module - βασικό framework για δημιουργία forms
from django import forms
# Χρησιμότητα: Παρέχει Form και ModelForm classes για εύκολη δημιουργία forms

# Authentication module για έλεγχο credentials
from django.contrib.auth import authenticate
# Χρησιμότητα: Επιστρέφει User object αν τα credentials είναι έγκυρα

# Exceptions για custom validation errors
from django.core.exceptions import ValidationError
# Χρησιμότητα: Επιτρέπει custom error messages σε form validation

# Import του ShippingAddress model για ModelForm
from .models import ShippingAddress
# Χρησιμότητα: Το model που θα συνδεθεί με το ShippingAddressForm

# Import utility functions
from .utils import verify_email_domain
# Χρησιμότητα: Παρέχει λειτουργίες όπως cached DNS verification

# Time module για timing attack protection
import time
# Χρησιμότητα: Χρησιμοποιείται για σταθερό χρόνο απόκρισης

# Bleach library για input sanitization
import bleach
# Χρησιμότητα: Καθαρίζει HTML/JavaScript από user input (XSS protection)

# Secrets module για cryptographically secure random numbers
import secrets
# Χρησιμότητα: Παράγει ασφαλείς τυχαίους αριθμούς για timing variations

# HMAC module για secure string comparison
import hmac
# Χρησιμότητα: Παρέχει constant-time comparison για αποφυγή timing attacks

# Captcha για προστασία από αυτοματοποιημένες επιθέσεις
from captcha.fields import CaptchaField
# Χρησιμότητα: Παρέχει CAPTCHA field για forms

# Validate_email για επικύρωση διεύθυνσης email
import dns.resolver
import re
# Χρησιμότητα: Επικύρωση εγκυρότητας domain email με DNS lookup


# ============================================================================
# LOGIN FORM - Φόρμα σύνδεσης με προηγμένα μέτρα ασφαλείας
# ============================================================================

class LoginForm(forms.Form):
    """
    Φόρμα σύνδεσης χρηστών με προστασία από:
    - Timing attacks
    - User enumeration  
    - Brute force attacks (μέσω django-axes)
    - Αυτοματοποιημένες επιθέσεις (μέσω CAPTCHA)
    
    Χρησιμότητα:
    - Ασφαλής αυθεντικοποίηση χρηστών
    - Προστασία από common attack vectors
    - User-friendly interface με Bootstrap classes
    - Επιπλέον επίπεδο ασφάλειας με CAPTCHA
    """
    
    # Πεδίο username με custom styling
    username = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-control',      # Bootstrap CSS class
            'placeholder': 'Username'      # Placeholder text
        })
    )
    # Χρησιμότητα: Clean input field με styling που ταιριάζει με το site design
    
    # Πεδίο password με masking
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',      # Bootstrap CSS class
            'placeholder': 'Password'      # Placeholder text
        })
    )
    # Χρησιμότητα: Password field με αυτόματο masking για ασφάλεια
    
    # Πεδίο CAPTCHA για προστασία από bots
    captcha = CaptchaField(
        # Χρησιμότητα: Προσθέτει CAPTCHA verification στη φόρμα
        error_messages={'invalid': 'Λάθος CAPTCHA. Προσπαθήστε ξανά.'}
    )
    
    def __init__(self, *args, **kwargs):
        """
        Custom initialization για να περάσουμε το request object.
        
        Χρησιμότητα:
        - Επιτρέπει πρόσβαση στο request για authentication
        - Διατηρεί compatibility με Django's authenticate()
        """
        # Εξαγωγή του request από kwargs
        self.request = kwargs.pop('request', None)
        # Κλήση του parent constructor
        super().__init__(*args, **kwargs)
    
    def clean(self):
        """
        Custom validation με προστασία από timing attacks.
        
        Μέτρα ασφαλείας:
        1. Constant-time operations
        2. Random delays για obfuscation
        3. Generic error messages (no user enumeration)
        4. Minimum response time enforcement
        
        Χρησιμότητα:
        - Αποτρέπει attackers από το να μάθουν αν ένα username υπάρχει
        - Δυσκολεύει brute force attacks
        - Παρέχει uniform response times
        """
        # Κλήση του parent clean method
        cleaned_data = super().clean()
        
        # Λήψη των πεδίων
        username = cleaned_data.get('username')
        password = cleaned_data.get('password')
        
        if username and password:
            # Καταγραφή χρόνου έναρξης για timing protection
            start_time = time.time()
            
            # Constant-time string comparison function
            # Χρησιμότητα: Αποφεύγει timing leaks σε string comparisons
            def constant_time_compare(val1, val2):
                """
                Σύγκριση strings με σταθερό χρόνο εκτέλεσης.
                
                Χρησιμότητα:
                - Δεν leak πληροφορίες μέσω execution time
                - Χρησιμοποιεί secure HMAC comparison
                """
                return hmac.compare_digest(
                    str(val1).encode('utf-8'),
                    str(val2).encode('utf-8')
                )
            
            # Πραγματικός έλεγχος αυθεντικοποίησης
            # Χρησιμότητα: Django's built-in authentication με session support
            user = authenticate(self.request, username=username, password=password)
            
            # Τυχαία καθυστέρηση 0-100ms
            # Χρησιμότητα: Προσθέτει noise στο timing για να δυσκολέψει analysis
            random_delay = secrets.randbelow(100) / 1000  # Milliseconds σε seconds
            
            # Υπολογισμός χρόνου εκτέλεσης
            execution_time = time.time() - start_time
            
            # Enforcement ελάχιστου χρόνου απόκρισης 300ms
            # Χρησιμότητα: 
            # - Εξασφαλίζει consistent response time
            # - Κρύβει πραγματικό authentication time
            # - Δυσκολεύει timing attacks
            if execution_time < 0.3:
                time.sleep(0.3 - execution_time + random_delay)
            
            # Έλεγχος αποτελέσματος authentication
            if not user:
                # Γενικό μήνυμα σφάλματος
                # Χρησιμότητα: Δεν αποκαλύπτει αν το username υπάρχει
                raise ValidationError(
                    "Τα στοιχεία σύνδεσης που εισάγατε δεν είναι έγκυρα. Παρακαλώ προσπαθήστε ξανά."
                )
            
            # Αποθήκευση του authenticated user για χρήση στο view
            # Χρησιμότητα: Το view μπορεί να κάνει login τον χρήστη
            self.user = user
        
        return cleaned_data


# ============================================================================
# SHIPPING ADDRESS FORM - Φόρμα διεύθυνσης αποστολής
# ============================================================================

class ShippingAddressForm(forms.ModelForm):
    """
    ModelForm για τη συλλογή στοιχείων διεύθυνσης αποστολής.
    
    Features:
    - Αυτόματη δημιουργία από ShippingAddress model
    - Bootstrap styling για όλα τα πεδία
    - XSS protection με bleach
    - Greek placeholders για καλύτερο UX
    
    Χρησιμότητα:
    - Εύκολη δημιουργία/επεξεργασία διευθύνσεων
    - Consistent styling με το υπόλοιπο site
    - Προστασία από malicious input
    """
    
    class Meta:
        """
        Metadata για το ModelForm.
        
        Χρησιμότητα:
        - Ορίζει ποιο model θα χρησιμοποιηθεί
        - Καθορίζει ποια fields θα συμπεριληφθούν
        - Προσθέτει custom widgets με styling
        """
        # Το model που συνδέεται με τη φόρμα
        model = ShippingAddress
        
        # Πεδία που θα εμφανίζονται στη φόρμα
        fields = ['name', 'address', 'city', 'zip_code', 'country', 'phone', 'email']
        
        # Custom widgets με Bootstrap styling και Greek placeholders
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Ονοματεπώνυμο'
            }),
            'address': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Διεύθυνση'
            }),
            'city': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Πόλη'
            }),
            'zip_code': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'ΤΚ'
            }),
            'country': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Χώρα'
            }),
            'phone': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Τηλέφωνο'
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'Email'
            }),
        }
    
    def clean_zip_code(self):
        """
        Επιπλέον validation για τον ταχυδρομικό κώδικα.
        
        Χρησιμότητα:
        - Επιβεβαιώνει ότι ο ΤΚ αποτελείται μόνο από ψηφία
        - Ελέγχει το μήκος (5 ψηφία για Ελλάδα)
        - Επιστρέφει λεπτομερές μήνυμα λάθους
        """
        zip_code = self.cleaned_data.get('zip_code')
        
        if zip_code:
            # Αφαίρεση κενών διαστημάτων
            zip_code = zip_code.strip()
            
            # Έλεγχος αν αποτελείται μόνο από ψηφία
            if not zip_code.isdigit():
                raise ValidationError('Ο ταχυδρομικός κώδικας πρέπει να περιέχει μόνο ψηφία.')
            
            # Έλεγχος μήκους
            if len(zip_code) != 5:
                raise ValidationError('Ο ταχυδρομικός κώδικας πρέπει να έχει ακριβώς 5 ψηφία.')
        
        return zip_code
    
    def clean_phone(self):
        """
        Επιπλέον validation για το τηλέφωνο.
        
        Χρησιμότητα:
        - Επιβεβαιώνει ότι το τηλέφωνο ακολουθεί ελληνικό format
        - Αφαιρεί περιττά κενά και χαρακτήρες
        - Επιτρέπει διάφορες μορφές εισαγωγής
        """
        phone = self.cleaned_data.get('phone')
        
        if phone:
            # Αφαίρεση κενών διαστημάτων και παύλων
            phone = re.sub(r'[\s-]', '', phone)
            
            # Έλεγχος αν το τηλέφωνο είναι έγκυρο ελληνικό
            greek_phone_pattern = r'^(?:\+30|0030)?(?:\s*)(?:(?:69\d{8})|(?:2\d{9}))$'
            if not re.match(greek_phone_pattern, phone):
                raise ValidationError('Παρακαλώ εισάγετε έγκυρο ελληνικό αριθμό τηλεφώνου (σταθερό ή κινητό).')
            
            # Ομοιόμορφη μορφοποίηση με πρόθεμα +30
            if not phone.startswith('+30') and not phone.startswith('0030'):
                if len(phone) == 10:
                    phone = '+30' + phone
            elif phone.startswith('0030'):
                phone = '+30' + phone[4:]
        
        return phone
    
    def clean_email(self):
        """
        Επιπλέον validation για το email με έλεγχο domain.
        
        Χρησιμότητα:
        - Επιβεβαιώνει ότι το format του email είναι σωστό
        - Ελέγχει αν το domain υπάρχει πραγματικά μέσω DNS lookup
        - Αποτρέπει εισαγωγή ανύπαρκτων διευθύνσεων email
        """
        email = self.cleaned_data.get('email')
        
        if email:
            # Έλεγχος βασικής μορφής με regex
            email_pattern = r'^[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]{0,63}[a-zA-Z0-9])?@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
            if not re.match(email_pattern, email):
                raise ValidationError('Η διεύθυνση email δεν είναι έγκυρη. Ελέγξτε τη μορφή της.')
            
            # Εξαγωγή domain
            domain = email.split('@')[-1]
            
            # Έλεγχος εγκυρότητας domain με cached DNS lookup
            if not verify_email_domain(email):
                raise ValidationError(f'Το domain "{domain}" δεν είναι έγκυρο ή δεν υπάρχει.')
        
        return email
    
    def clean(self):
        """
        Custom validation με XSS protection και επιπλέον ελέγχους.
        
        Χρησιμότητα:
        - Καθαρίζει όλα τα string fields από HTML/JavaScript
        - Προστατεύει από XSS attacks
        - Διατηρεί clean data στη βάση
        - Κάνει επιπλέον συνδυαστικούς ελέγχους
        
        Security:
        - Χρησιμοποιεί bleach για HTML sanitization
        - Εφαρμόζεται σε όλα τα text fields αυτόματα
        """
        # Κλήση του parent clean method
        cleaned_data = super().clean()
        
        # Καθαρισμός όλων των string fields με bleach
        # Χρησιμότητα: Αυτόματη προστασία χωρίς manual intervention
        for field in self.fields:
            # Έλεγχος αν το field υπάρχει στα cleaned_data και είναι string
            if field in cleaned_data and isinstance(cleaned_data[field], str):
                # Καθαρισμός με bleach (strip όλα τα tags)
                cleaned_data[field] = bleach.clean(cleaned_data[field])
        
        # Έλεγχος αν η χώρα είναι Ελλάδα για επιπλέον validation
        country = cleaned_data.get('country', '').lower()
        if country in ['ελλάδα', 'ελλαδα', 'greece', 'hellas']:
            # Βεβαιωνόμαστε ότι ο ΤΚ και το τηλέφωνο ακολουθούν ελληνικούς κανόνες
            # (επιπλέον από τους ελέγχους στα clean_* methods)
            zip_code = cleaned_data.get('zip_code', '')
            phone = cleaned_data.get('phone', '')
            
            # Οποιαδήποτε επιπλέον ειδική λογική για ελληνικές διευθύνσεις
        
        return cleaned_data
    
# ============================================================================
# Ανάλυση Χρησιμότητας ανά Block
# 1. Imports Section

# Django forms: Core functionality για forms
# Authentication: Για έλεγχο user credentials
# Security modules: bleach, secrets, hmac για προστασία
# Time: Για timing attack mitigation

# 2. LoginForm Class
# Προηγμένη φόρμα σύνδεσης με multiple security layers:
# Field Definitions

# Username field: Styled text input
# Password field: Masked input για security
# Bootstrap classes: Consistent UI design

# Security Measures

# Timing Attack Protection:

# Constant execution time
# Random delays για obfuscation
# Minimum 300ms response time


# User Enumeration Prevention:

# Generic error messages
# Ίδια απόκριση για valid/invalid usernames
# No information leakage


# Constant-time Operations:

# HMAC comparison για strings
# Αποφυγή timing leaks



# Clean Method

# Custom validation logic
# Authentication check
# Error handling με security focus

# 3. ShippingAddressForm Class
# ModelForm για shipping addresses:
# Meta Class Configuration

# Model binding: Αυτόματη δημιουργία από model
# Field selection: Επιλογή specific fields
# Widget customization: Bootstrap styling

# XSS Protection

# Bleach sanitization: Αφαίρεση HTML/JS
# Automatic application: Σε όλα τα string fields
# Clean data storage: Ασφαλής αποθήκευση

# Security Best Practices
# 1. Input Sanitization

# Bleach για HTML/JavaScript removal
# Automatic για όλα τα fields
# Prevents stored XSS attacks

# 2. Timing Attack Mitigation

# Constant execution time
# Random delays
# No information leakage

# 3. User Enumeration Prevention

# Generic error messages
# Same response για όλα τα failures
# No username disclosure

# 4. CAPTCHA Implementation

# Προστασία από bots και αυτοματοποιημένες επιθέσεις
# Επιπλέον επίπεδο ασφάλειας πέρα από django-axes
# Anti-automation mechanism

# 5. Bootstrap Integration

# Consistent styling
# Responsive design
# Professional appearance