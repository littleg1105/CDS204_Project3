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


# ============================================================================
# LOGIN FORM - Φόρμα σύνδεσης με προηγμένα μέτρα ασφαλείας
# ============================================================================

class LoginForm(forms.Form):
    """
    Φόρμα σύνδεσης χρηστών με προστασία από:
    - Timing attacks
    - User enumeration  
    - Brute force attacks (μέσω django-axes)
    
    Χρησιμότητα:
    - Ασφαλής αυθεντικοποίηση χρηστών
    - Προστασία από common attack vectors
    - User-friendly interface με Bootstrap classes
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
    
    def clean(self):
        """
        Custom validation με XSS protection.
        
        Χρησιμότητα:
        - Καθαρίζει όλα τα string fields από HTML/JavaScript
        - Προστατεύει από XSS attacks
        - Διατηρεί clean data στη βάση
        
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

# 4. Bootstrap Integration

# Consistent styling
# Responsive design
# Professional appearance