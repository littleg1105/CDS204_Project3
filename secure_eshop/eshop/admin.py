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
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.admin import TOTPDeviceAdmin
from django_otp.plugins.otp_static.admin import StaticDeviceAdmin
from django.contrib.auth import get_user_model
# Χρησιμότητα: Παρέχει two-factor authentication για το admin interface

# Εισαγωγή όλων των μοντέλων που θέλουμε να διαχειριστούμε μέσω admin
from .models import Product, Cart, CartItem, ShippingAddress, Order, OrderItem, CustomUser
# Χρησιμότητα: Επιτρέπει την καταχώρηση αυτών των μοντέλων στο admin interface

# Configure logger
logger = logging.getLogger('security')

# =============================================================================
# ΜΗΧΑΝΙΣΜΟΣ ΑΣΦΑΛΕΙΑΣ OTP - ΠΡΟΣΤΑΣΙΑ ΑΠΟ BRUTE FORCE
# =============================================================================
# Η κλάση OTPLockoutTracker υλοποιεί έναν μηχανισμό προστασίας κατά επιθέσεων 
# brute force στους κωδικούς OTP. Αυτό αποτρέπει επιθέσεις εξαντλητικής δοκιμής
# όλων των πιθανών κωδικών OTP (στην περίπτωση TOTP, υπάρχουν μόνο 1.000.000
# πιθανοί κωδικοί).

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

# =============================================================================
# ΠΡΟΣΑΡΜΟΣΜΕΝΟ ADMIN SITE ΜΕ TWO-FACTOR AUTHENTICATION
# =============================================================================
# Η κλάση SecureOTPAdmin επεκτείνει το OTPAdminSite του Django 
# προσθέτοντας επιπλέον μέτρα ασφαλείας όπως:
# 1. Αναγνώριση και επιβολή κλειδώματος λογαριασμών
# 2. Καταγραφή αποτυχημένων προσπαθειών αυθεντικοποίησης
# 3. Προειδοποιητικά μηνύματα για επικείμενο κλείδωμα
# 4. Αυτόματο ξεκλείδωμα μετά από επιτυχημένη σύνδεση

# Set up the OTP admin site
class SecureOTPAdmin(OTPAdminSite):
    site_title = 'Secure eShop Admin with OTP'
    site_header = 'Secure eShop Administration with OTP'
    index_title = 'eShop Admin Panel'
    
    def get_otp_auth_form(self):
        """Get the OTP authentication form with lockout support"""
        from .forms import SecureOTPAuthenticationForm
        return SecureOTPAuthenticationForm
    
    def _is_user_locked_out(self, username):
        """Check if user is locked out."""
        return username and OTPLockoutTracker.check_lockout(username)
    
    def _render_lockout_page(self, request, extra_context=None):
        """Render the lockout page."""
        from django.shortcuts import render
        from django.contrib.auth.forms import AuthenticationForm
        
        context = self.each_context(request)
        context['form'] = AuthenticationForm(request)
        context['title'] = 'Log in'
        context['app_path'] = request.path
        context['lockout_message'] = "Account locked due to too many failed verification attempts. Please try again later or contact an administrator."
        
        if extra_context:
            context.update(extra_context)
            
        return render(request, 'admin/login.html', context)
    
    def _add_attempt_warning(self, username, extra_context):
        """Add warning about failed attempts to context."""
        if not username:
            return
            
        attempts = OTPLockoutTracker.get_attempts(username)
        if attempts > 0:
            extra_context['lockout_message'] = f"Warning: {attempts} failed verification attempt(s). Your account will be locked after {OTPLockoutTracker.MAX_ATTEMPTS} failed attempts."
    
    def _handle_failed_otp_verification(self, request, username):
        """Handle failed OTP verification after successful password check."""
        from django.contrib.auth import get_user_model, authenticate
        from django.shortcuts import redirect
        
        if not username:
            return None
            
        User = get_user_model()
        password = request.POST.get('password')
        
        try:
            user = User.objects.get(username=username)
            user_auth = authenticate(request, username=username, password=password)
            
            if user_auth is not None:
                # Password was correct, but OTP failed
                remaining = OTPLockoutTracker.log_failed_attempt(username)
                if remaining == 0:
                    return redirect(request.path)
        except User.DoesNotExist:
            pass
            
        return None
    
    def login(self, request, extra_context=None):
        """Override login to implement OTP lockout"""
        username = request.POST.get('username')
        extra_context = extra_context or {}
        
        # Handle locked out users
        if self._is_user_locked_out(username):
            return self._render_lockout_page(request, extra_context)
        
        # Add warning for failed attempts
        self._add_attempt_warning(username, extra_context)
        
        # Proceed with standard OTP login
        response = super().login(request, extra_context)
        
        # Handle post-login processing
        if request.method == 'POST':
            if not request.user.is_authenticated:
                # Login failed - check if it was OTP failure
                redirect_response = self._handle_failed_otp_verification(request, username)
                if redirect_response:
                    return redirect_response
            else:
                # Login succeeded - clear attempts
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

# =============================================================================
# ΑΝΤΙΚΑΤΑΣΤΑΣΗ ΤΟΥ DEFAULT ADMIN SITE ΜΕ ΤΟ SECURE OTP ADMIN
# =============================================================================
# Αυτή η γραμμή αντικαθιστά την προεπιλεγμένη κλάση του admin site
# με τη δική μας υλοποίηση που περιλαμβάνει two-factor authentication
# και προστασία από επιθέσεις brute force.
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

# =============================================================================
# ΠΡΟΣΑΡΜΟΣΜΕΝΟΙ ΔΙΑΧΕΙΡΙΣΤΕΣ ΣΥΣΚΕΥΩΝ OTP
# =============================================================================
# Οι παρακάτω κλάσεις CustomTOTPDeviceAdmin και CustomStaticDeviceAdmin 
# επεκτείνουν τις αντίστοιχες προεπιλεγμένες κλάσεις διαχείρισης συσκευών OTP,
# προσθέτοντας υποστήριξη για UUID primary keys που χρησιμοποιούνται στο 
# custom user model της εφαρμογής. Αυτό επιτρέπει τη σωστή διαχείριση των 
# συσκευών OTP των χρηστών από το περιβάλλον διαχείρισης.

# Custom TOTP Device Admin
class CustomTOTPDeviceAdmin(TOTPDeviceAdmin):
    """
    Enhanced TOTP Device admin that works with UUID-based user models
    """
    list_display = ['user', 'name', 'confirmed']
    raw_id_fields = ['user']
    
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == 'user':
            kwargs['queryset'] = get_user_model().objects.all()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

# Custom Static Device Admin for backup codes
class CustomStaticDeviceAdmin(StaticDeviceAdmin):
    """
    Enhanced Static Device admin that works with UUID-based user models
    """
    list_display = ['user', 'name', 'confirmed']
    raw_id_fields = ['user']
    
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == 'user':
            kwargs['queryset'] = get_user_model().objects.all()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

# Register OTP models with custom admin - use unregister first to avoid AlreadyRegistered error
from django.contrib.admin.sites import site as admin_site

# Unregister the default OTP admin classes
try:
    admin_site.unregister(TOTPDevice)
    admin_site.unregister(StaticDevice)
except Exception:
    pass  # These models might not be registered yet
    
# Register with our custom admin classes
admin.site.register(TOTPDevice, CustomTOTPDeviceAdmin)
admin.site.register(StaticDevice, CustomStaticDeviceAdmin)

# =============================================================================
# ΠΡΟΣΑΡΜΟΣΜΕΝΟΣ ΔΙΑΧΕΙΡΙΣΤΗΣ ΧΡΗΣΤΩΝ - CustomUserAdmin
# =============================================================================
# Η κλάση CustomUserAdmin επεκτείνει τον προεπιλεγμένο UserAdmin του Django
# για να υποστηρίζει το CustomUser model που χρησιμοποιεί UUID ως primary key.
# Η κλάση αυτή ορίζει ποια πεδία θα εμφανίζονται στη λίστα χρηστών και ποια 
# πεδία θα είναι διαθέσιμα στις φόρμες προσθήκης/επεξεργασίας χρηστών.

from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _

class CustomUserAdmin(UserAdmin):
    """
    Custom admin for User model with UUID as primary key
    """
    model = CustomUser
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff')
    
    # Field sets for user add/change forms
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email', 'profile_picture')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    
    # Field sets for user add form
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2'),
        }),
    )
    
    # Register the custom user admin
admin.site.register(CustomUser, CustomUserAdmin)

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