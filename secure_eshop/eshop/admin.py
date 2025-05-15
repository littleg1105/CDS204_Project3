# ============================================================================
# DJANGO ADMIN CONFIGURATION
# Αρχείο διαμόρφωσης για το Django Admin Interface with OTP support
# ============================================================================

# Εισαγωγή του Django admin module
from django.contrib import admin
from django.http import HttpResponse
from django.core.cache import cache
from django.utils import timezone
import time
import logging
# Χρησιμότητα: Παρέχει πρόσβαση στο Django admin framework
# που επιτρέπει διαχείριση μοντέλων μέσω web interface

# Import OTP Admin
from django_otp.admin import OTPAdminSite
from django_otp.forms import OTPAuthenticationForm
from django.dispatch import receiver
# Χρησιμότητα: Παρέχει two-factor authentication για το admin interface

# Εισαγωγή όλων των μοντέλων που θέλουμε να διαχειριστούμε μέσω admin
from .models import Product, Cart, CartItem, ShippingAddress, Order, OrderItem
# Χρησιμότητα: Επιτρέπει την καταχώρηση αυτών των μοντέλων στο admin interface

# Configure logger
logger = logging.getLogger('security')

# We'll use the admin login method instead of signals to track OTP verification failures

# Custom OTP Authentication Form with enhanced security
class OTPLockoutTracker:
    """
    Helper class to track and enforce OTP lockout.
    """
    MAX_ATTEMPTS = 3  # Lock after 3 failed attempts
    LOCKOUT_TIME = 3600  # 1 hour in seconds
    
    @classmethod
    def check_lockout(cls, username):
        """Check if user is locked out"""
        if not username:
            return False
        
        cache_key = f"otp_lockout:{username}"
        return cache.get(cache_key, False)
    
    @classmethod
    def get_attempts(cls, username):
        """Get current number of failed attempts"""
        if not username:
            return 0
            
        attempts_key = f"otp_attempts:{username}"
        return cache.get(attempts_key, 0)
    
    @classmethod
    def log_failed_attempt(cls, username):
        """Log failed attempt and lock account if threshold reached"""
        if not username:
            return 0
        
        attempts_key = f"otp_attempts:{username}" 
        attempts = cache.get(attempts_key, 0) + 1
        cache.set(attempts_key, attempts, cls.LOCKOUT_TIME)
        
        # Log the attempt
        logger.warning(f"OTP verification failed for user {username}. Attempt {attempts}")
        
        if attempts >= cls.MAX_ATTEMPTS:
            # Lock the account
            cache_key = f"otp_lockout:{username}"
            cache.set(cache_key, True, cls.LOCKOUT_TIME)
            logger.warning(f"User {username} locked out due to too many failed OTP attempts")
            return 0  # No attempts remaining
        
        return cls.MAX_ATTEMPTS - attempts
    
    @classmethod
    def clear_attempts(cls, username):
        """Clear failed attempts on successful login"""
        if not username:
            return
        
        attempts_key = f"otp_attempts:{username}"
        cache.delete(attempts_key)
        
        # Also clear any lockout
        cache_key = f"otp_lockout:{username}"
        cache.delete(cache_key)

# Set up the OTP admin site
class SecureOTPAdmin(OTPAdminSite):
    site_title = 'Secure eShop Admin with OTP'
    site_header = 'Secure eShop Administration with OTP'
    index_title = 'eShop Admin Panel'
    
    def get_otp_auth_form(self):
        """Get the OTP authentication form with lockout support"""
        from .forms import SecureOTPAuthenticationForm
        return SecureOTPAuthenticationForm
    
    def login(self, request, extra_context=None):
        """Override login to implement OTP lockout"""
        username = request.POST.get('username')
        
        # Create a context dictionary if none was passed
        if extra_context is None:
            extra_context = {}
            
        # Check if user is locked out
        if username and OTPLockoutTracker.check_lockout(username):
            from django.shortcuts import render
            from django.contrib.auth.forms import AuthenticationForm
            
            # Return the login page without processing the form
            context = self.each_context(request)
            context['form'] = AuthenticationForm(request)
            context['title'] = 'Log in'
            context['app_path'] = request.path
            
            # Add lockout message directly in the context
            context['lockout_message'] = "Account locked due to too many failed verification attempts. Please try again later or contact an administrator."
            
            # Add extra context from the argument
            context.update(extra_context)
            
            # Important: We return here to block further login processing
            return render(request, 'admin/login.html', context)
        
        # If not locked out, check for attempts and add warning to context if needed
        if username:
            attempts = OTPLockoutTracker.get_attempts(username)
            if attempts > 0:
                extra_context['lockout_message'] = f"Warning: {attempts} failed verification attempt(s). Your account will be locked after {OTPLockoutTracker.MAX_ATTEMPTS} failed attempts."
                
        # If not locked out, proceed with standard OTP login
        response = super().login(request, extra_context)
        
        # Check if login succeeded
        if request.method == 'POST' and not request.user.is_authenticated:
            # Login didn't succeed - check if it was a valid username but wrong OTP
            from django.contrib.auth import get_user_model
            User = get_user_model()
            
            if username:
                try:
                    user = User.objects.get(username=username)
                    
                    # Check if the password was correct but OTP failed
                    from django.contrib.auth import authenticate
                    password = request.POST.get('password')
                    user_auth = authenticate(request, username=username, password=password)
                    
                    if user_auth is not None:
                        # Password was correct, but OTP failed - track as OTP failure
                        remaining = OTPLockoutTracker.log_failed_attempt(username)
                        if remaining == 0:
                            # Account is now locked - force a reload to show the lockout message
                            from django.shortcuts import redirect
                            return redirect(request.path)
                except User.DoesNotExist:
                    # Username doesn't exist - not an OTP failure
                    pass
        
        # If user logged in successfully, clear attempts counter
        if request.user.is_authenticated:
            OTPLockoutTracker.clear_attempts(username)
        
        return response
        
    def has_permission(self, request):
        """
        Override to enforce OTP lockout at the admin level
        """
        if not request.user.is_authenticated:
            return False
            
        # Important: Check if the authenticated user is locked out
        if OTPLockoutTracker.check_lockout(request.user.username):
            # Force logout the user if they're locked out
            from django.contrib.auth import logout
            logout(request)
            
            # Note: We'll let middleware handle the error response
            return False
            
        # Proceed with regular permission check
        return super().has_permission(request)

# Replace the default admin site
admin.site.__class__ = SecureOTPAdmin


# ============================================================================
# CUSTOM ADMIN CLASS - ProductAdmin
# Προσαρμογή του admin interface για το Product model
# ============================================================================

class ProductAdmin(admin.ModelAdmin):
    """
    Προσαρμοσμένη κλάση για τη διαχείριση του Product model στο admin.
    
    Χρησιμότητα:
    - Βελτιωμένη εμφάνιση και λειτουργικότητα στο admin interface
    - Ευκολότερη διαχείριση προϊόντων από τους administrators
    - Γρήγορη αναζήτηση και φιλτράρισμα
    """
    
    # Πεδία που εμφανίζονται στη λίστα προϊόντων
    list_display = ('name', 'price', 'created_at')
    # Χρησιμότητα:
    # - Επιτρέπει γρήγορη εποπτεία βασικών πληροφοριών
    # - Ταξινόμηση με κλικ στις κεφαλίδες
    # - Καθορίζει τις στήλες του πίνακα στο list view
    
    # Πεδία στα οποία μπορεί να γίνει αναζήτηση
    search_fields = ('name', 'description')
    # Χρησιμότητα:
    # - Προσθέτει search box στο admin interface
    # - Επιτρέπει full-text search σε αυτά τα πεδία
    # - Χρησιμοποιεί ILIKE query για case-insensitive αναζήτηση
    
    # Πεδία για φιλτράρισμα στο sidebar
    list_filter = ('created_at',)
    # Χρησιμότητα:
    # - Προσθέτει filter sidebar στη δεξιά πλευρά
    # - Επιτρέπει φιλτράρισμα με ημερομηνία δημιουργίας
    # - Django αυτόματα δημιουργεί χρήσιμες επιλογές (Today, Past 7 days, κλπ)


# ============================================================================
# MODEL REGISTRATION - Καταχώρηση μοντέλων στο Admin
# ============================================================================

# Καταχώρηση Product model με την custom ProductAdmin class
admin.site.register(Product, ProductAdmin)
# Χρησιμότητα:
# - Συνδέει το Product model με την ProductAdmin διαμόρφωση
# - Εφαρμόζει όλες τις προσαρμογές που ορίσαμε στην ProductAdmin
# - Το Product θα εμφανίζεται στο admin με βελτιωμένη λειτουργικότητα

# Βασική καταχώρηση για Cart model
admin.site.register(Cart)
# Χρησιμότητα:
# - Προσθέτει το Cart στο admin interface
# - Χρησιμοποιεί τις default ρυθμίσεις του Django admin
# - Επιτρέπει CRUD operations για Cart objects

# Βασική καταχώρηση για CartItem model
admin.site.register(CartItem)
# Χρησιμότητα:
# - Διαχείριση των αντικειμένων στα καλάθια
# - Δυνατότητα προβολής ποιο προϊόν είναι σε ποιο καλάθι
# - Έλεγχος ποσοτήτων και σχέσεων

# Βασική καταχώρηση για ShippingAddress model
admin.site.register(ShippingAddress)
# Χρησιμότητα:
# - Διαχείριση διευθύνσεων αποστολής
# - Προβολή/επεξεργασία στοιχείων παραληπτών
# - Σύνδεση διευθύνσεων με χρήστες

# Βασική καταχώρηση για Order model
admin.site.register(Order)
# Χρησιμότητα:
# - Διαχείριση παραγγελιών
# - Αλλαγή status παραγγελιών
# - Προβολή ιστορικού παραγγελιών

# Βασική καταχώρηση για OrderItem model
admin.site.register(OrderItem)
# Χρησιμότητα:
# - Διαχείριση προϊόντων μέσα σε παραγγελίες
# - Προβολή λεπτομερειών κάθε παραγγελίας
# - Παρακολούθηση ποσοτήτων και τιμών


# ============================================================================
# ΣΧΟΛΙΑ ΠΕΡΙΓΡΑΦΗΣ
# ============================================================================

# This code is registering the models defined in the `models.py` file with the Django admin interface.
# It allows the admin to manage these models through the Django admin panel.
# The `ProductAdmin` class customizes the admin interface for the `Product` model, allowing for search and filtering.

# Ανάλυση Χρησιμότητας ανά Block
# 1. Imports

# django.contrib.admin: Το core module του Django admin framework
# Model imports: Εισάγει όλα τα μοντέλα που θα διαχειριστούν μέσω admin

# 2. ProductAdmin Class
# Προσαρμοσμένη διαμόρφωση για το Product model:
# list_display

# Στήλες πίνακα: Εμφανίζει name, price, created_at σε στήλες
# Ταξινόμηση: Click στις κεφαλίδες για sorting
# Quick view: Βλέπεις τις σημαντικές πληροφορίες με μια ματιά

# search_fields

# Search box: Προσθέτει πεδίο αναζήτησης
# Multiple fields: Ψάχνει ταυτόχρονα σε name και description
# Case-insensitive: Δεν κάνει διάκριση πεζών-κεφαλαίων

# list_filter

# Sidebar filters: Δημιουργεί πλευρική μπάρα με φίλτρα
# Date filtering: Αυτόματες επιλογές (Today, This week, This month)
# Quick filtering: Γρήγορο φιλτράρισμα με ένα κλικ

# 3. Model Registration
# Product με ProductAdmin

# Custom interface: Εφαρμόζει όλες τις προσαρμογές
# Enhanced functionality: Βελτιωμένη εμπειρία διαχείρισης
# Organized display: Καλύτερη οργάνωση δεδομένων

# Υπόλοιπα Models (Default Registration)

# Basic CRUD: Create, Read, Update, Delete operations
# Auto-generated forms: Αυτόματη δημιουργία φορμών
# Relationship handling: Διαχείριση ForeignKey και ManyToMany σχέσεων