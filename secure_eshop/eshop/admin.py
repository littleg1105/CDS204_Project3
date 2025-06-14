# ============================================================================
# DJANGO ADMIN CONFIGURATION
# Αρχείο διαμόρφωσης για το Django Admin Interface - VULNERABLE VERSION
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

# VULNERABILITY: OTP removed - no two-factor authentication
# from django_otp.admin import OTPAdminSite
# from django_otp.forms import OTPAuthenticationForm

# Εισαγωγή όλων των μοντέλων που θέλουμε να διαχειριστούμε μέσω admin
from .models import Product, Cart, CartItem, ShippingAddress, Order, OrderItem, CustomUser, ProductReview
# Χρησιμότητα: Επιτρέπει την καταχώρηση αυτών των μοντέλων στο admin interface

# Configure logger
logger = logging.getLogger('security')

# VULNERABILITY: OTP lockout removed - allows brute force attacks
# Custom OTP Authentication Form removed

# VULNERABILITY: Using default admin without OTP
# admin.site.__class__ = SecureOTPAdmin


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
    # Χρησιμότητα: Εμφανίζει αυτά τα πεδία ως στήλες στη λίστα των προϊόντων
    
    # Πεδία για αναζήτηση
    search_fields = ('name', 'description')
    # Χρησιμότητα: Επιτρέπει αναζήτηση στα προϊόντα με βάση το όνομα ή την περιγραφή
    
    # Φίλτρα στο πλάι
    list_filter = ('created_at',)
    # Χρησιμότητα: Δημιουργεί filters στη δεξιά πλευρά για εύκολο φιλτράρισμα
    
    # Ταξινόμηση
    ordering = ('-created_at',)
    # Χρησιμότητα: Ταξινομεί τα προϊόντα με τα νεότερα πρώτα


# ============================================================================
# CUSTOM ADMIN CLASS - OrderAdmin
# Προσαρμογή του admin interface για το Order model
# ============================================================================

class OrderAdmin(admin.ModelAdmin):
    """
    Προσαρμοσμένη κλάση για τη διαχείριση του Order model στο admin.
    
    Χρησιμότητα:
    - Καλύτερη εποπτεία των παραγγελιών
    - Γρήγορη πρόσβαση στις πληροφορίες παραγγελιών
    - Φιλτράρισμα και αναζήτηση παραγγελιών
    """
    
    # Πεδία που εμφανίζονται στη λίστα παραγγελιών
    list_display = ('id', 'user', 'status', 'total_price', 'created_at')
    # Χρησιμότητα: Εμφανίζει τις βασικές πληροφορίες κάθε παραγγελίας
    
    # Φίλτρα
    list_filter = ('status', 'created_at')
    # Χρησιμότητα: Επιτρέπει φιλτράρισμα με βάση το status και την ημερομηνία
    
    # Αναζήτηση
    search_fields = ('user__username', 'user__email')
    # Χρησιμότητα: Αναζήτηση παραγγελιών με βάση το username ή email του χρήστη
    
    # Ημερομηνία hierarchy
    date_hierarchy = 'created_at'
    # Χρησιμότητα: Προσθέτει πλοήγηση με βάση την ημερομηνία στο πάνω μέρος


# ============================================================================
# REGISTER MODELS - Καταχώρηση μοντέλων στο admin
# ============================================================================

# Καταχώρηση του Product model με custom admin class
admin.site.register(Product, ProductAdmin)
# Χρησιμότητα: Επιτρέπει τη διαχείριση προϊόντων μέσω του admin interface

# Καταχώρηση του Order model με custom admin class
admin.site.register(Order, OrderAdmin)
# Χρησιμότητα: Επιτρέπει τη διαχείριση παραγγελιών μέσω του admin interface

# Καταχώρηση υπόλοιπων μοντέλων με default admin interface
admin.site.register(Cart)
admin.site.register(CartItem)
admin.site.register(ShippingAddress)
admin.site.register(OrderItem)

# VULNERABILITY: No OTP device registration
# admin.site.register(TOTPDevice, TOTPDeviceAdmin)
# admin.site.register(StaticDevice, StaticDeviceAdmin)

# ============================================================================
# CUSTOM ADMIN CLASS - ProductReviewAdmin
# Προσαρμογή του admin interface για το ProductReview model
# ============================================================================

class ProductReviewAdmin(admin.ModelAdmin):
    """
    Προσαρμοσμένη κλάση για τη διαχείριση του ProductReview model στο admin.
    
    VULNERABILITY: No content sanitization - allows XSS attacks
    """
    
    # Πεδία που εμφανίζονται στη λίστα κριτικών
    list_display = ('product', 'user', 'rating', 'title', 'created_at')
    # Χρησιμότητα: Εμφανίζει τα βασικά στοιχεία κάθε κριτικής
    
    # Φίλτρα
    list_filter = ('rating', 'created_at')
    # Χρησιμότητα: Επιτρέπει φιλτράρισμα με βάση το rating και την ημερομηνία
    
    # Αναζήτηση
    search_fields = ('title', 'content', 'user__username', 'product__name')
    # Χρησιμότητα: Αναζήτηση σε τίτλο, περιεχόμενο, χρήστη και προϊόν
    
    # Ημερομηνία hierarchy
    date_hierarchy = 'created_at'
    # Χρησιμότητα: Προσθέτει πλοήγηση με βάση την ημερομηνία
    
    # Readonly fields
    readonly_fields = ('created_at', 'updated_at')
    # Χρησιμότητα: Αποτρέπει την τροποποίηση των timestamps

# Καταχώρηση του ProductReview model με custom admin class
admin.site.register(ProductReview, ProductReviewAdmin)

# ============================================================================
# CUSTOM USER ADMIN - Διαχείριση χρηστών στο admin
# ============================================================================

from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _

class CustomUserAdmin(UserAdmin):
    """
    Προσαρμοσμένη κλάση για τη διαχείριση του CustomUser model στο admin.
    """
    
    # Πεδία που εμφανίζονται στη λίστα χρηστών
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'date_joined')
    
    # VULNERABILITY: Simplified fieldsets - no OTP-related fields
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email', 'profile_picture')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2'),
        }),
    )

# Καταχώρηση του CustomUser model
try:
    admin.site.unregister(CustomUser)
except admin.sites.NotRegistered:
    pass

admin.site.register(CustomUser, CustomUserAdmin)


# ============================================================================
# ADMIN SITE CUSTOMIZATION - Προσαρμογή του admin interface
# ============================================================================

# Τίτλος του admin site
admin.site.site_header = "E-Shop Admin (VULNERABLE)"
# Χρησιμότητα: Εμφανίζεται στο header του admin interface

# Τίτλος του admin index
admin.site.site_title = "E-Shop Admin"
# Χρησιμότητα: Εμφανίζεται στο browser tab

# Τίτλος της αρχικής σελίδας
admin.site.index_title = "Διαχείριση E-Shop"
# Χρησιμότητα: Εμφανίζεται στην αρχική σελίδα του admin