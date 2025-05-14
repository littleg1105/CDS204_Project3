# ============================================================================
# DJANGO ADMIN CONFIGURATION
# Αρχείο διαμόρφωσης για το Django Admin Interface with OTP support
# ============================================================================

# Εισαγωγή του Django admin module
from django.contrib import admin
# Χρησιμότητα: Παρέχει πρόσβαση στο Django admin framework
# που επιτρέπει διαχείριση μοντέλων μέσω web interface

# Import OTP Admin
from django_otp.admin import OTPAdminSite
# Χρησιμότητα: Παρέχει two-factor authentication για το admin interface

# Εισαγωγή όλων των μοντέλων που θέλουμε να διαχειριστούμε μέσω admin
from .models import Product, Cart, CartItem, ShippingAddress, Order, OrderItem
# Χρησιμότητα: Επιτρέπει την καταχώρηση αυτών των μοντέλων στο admin interface

# Set up the OTP admin site
class OTPAdmin(OTPAdminSite):
    site_title = 'Secure eShop Admin with OTP'
    site_header = 'Secure eShop Administration with OTP'
    index_title = 'eShop Admin Panel'

# Replace the default admin site
admin.site.__class__ = OTPAdmin


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