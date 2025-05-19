# ============================================================================
# IMPORTS - Εισαγωγή απαραίτητων modules
# ============================================================================

# Django URL configuration
from django.urls import path
# Χρησιμότητα: Η βασική function για ορισμό URL patterns στο Django

# Import των views από το current app
from . import views
# Χρησιμότητα: Εισάγει όλα τα views που ορίζονται στο views.py του ίδιου app


# ============================================================================
# URL PATTERNS - Ορισμός των διαδρομών του application
# ============================================================================

# Namespace for the app - Required for tests
app_name = 'eshop'

urlpatterns = [
    # -------------------------------------------------------------------------
    # AUTHENTICATION URLs - Διαδρομές για σύνδεση/αποσύνδεση χρηστών
    # -------------------------------------------------------------------------
    
    # Login URL
    path('login/', views.login_view, name='login'),
    # Χρησιμότητα:
    # - URL: /login/
    # - View: login_view από το views.py
    # - Name: 'login' για reverse URL lookup
    # - Χρήση: {% url 'login' %} στα templates
    # - Σκοπός: Σελίδα σύνδεσης χρηστών με authentication form
    
    # Logout URL
    path('logout/', views.logout_view, name='logout'),
    # Χρησιμότητα:
    # - URL: /logout/
    # - View: logout_view από το views.py
    # - Name: 'logout' για reverse URL lookup
    # - Χρήση: {% url 'logout' %} στα templates
    # - Σκοπός: Endpoint για αποσύνδεση και τερματισμό session
    
    # -------------------------------------------------------------------------
    # MAIN APPLICATION URLs - Κύριες διαδρομές της εφαρμογής
    # -------------------------------------------------------------------------
    
    # Home/Catalog URL (root URL)
    path('', views.catalog_view, name='catalog'),
    # Χρησιμότητα:
    # - URL: / (root του application)
    # - View: catalog_view από το views.py
    # - Name: 'catalog' για reverse URL lookup
    # - Χρήση: {% url 'catalog' %} στα templates
    # - Σκοπός: Κεντρική σελίδα με κατάλογο προϊόντων και αναζήτηση
    
    # -------------------------------------------------------------------------
    # CART MANAGEMENT URLs - Διαδρομές για διαχείριση καλαθιού (AJAX)
    # -------------------------------------------------------------------------
    
    # Add to cart URL
    path('add-to-cart/', views.add_to_cart, name='add_to_cart'),
    # Χρησιμότητα:
    # - URL: /add-to-cart/
    # - View: add_to_cart από το views.py
    # - Name: 'add_to_cart' για reverse URL lookup
    # - Method: POST only (AJAX endpoint)
    # - Σκοπός: Προσθήκη προϊόντων στο καλάθι χωρίς page reload
    
    # Remove from cart URL
    path('remove-from-cart/', views.remove_from_cart, name='remove_from_cart'),  # Νέο URL
    # Χρησιμότητα:
    # - URL: /remove-from-cart/
    # - View: remove_from_cart από το views.py
    # - Name: 'remove_from_cart' για reverse URL lookup
    # - Method: POST only (AJAX endpoint)
    # - Σκοπός: Αφαίρεση προϊόντων από το καλάθι
    # - Σημείωση: Νέο URL που προστέθηκε πρόσφατα
    
    # Update cart item URL
    path('update-cart-item/', views.update_cart_item, name='update_cart_item'),
    # Χρησιμότητα:
    # - URL: /update-cart-item/
    # - View: update_cart_item από το views.py
    # - Name: 'update_cart_item' για reverse URL lookup
    # - Method: POST only (AJAX endpoint)
    # - Σκοπός: Ενημέρωση ποσότητας προϊόντων στο καλάθι
    
    # -------------------------------------------------------------------------
    # CHECKOUT URLs - Διαδρομές για τη διαδικασία checkout
    # -------------------------------------------------------------------------
    
    # Payment/Checkout URL
    path('payment/', views.payment_view, name='payment'),  # Ενημερωμένο με το σωστό view
    # Χρησιμότητα:
    # - URL: /payment/
    # - View: payment_view από το views.py
    # - Name: 'payment' για reverse URL lookup
    # - Methods: GET και POST
    # - Σκοπός: Διαδικασία checkout (shipping address + order confirmation)
    # - Σημείωση: Ενημερώθηκε για να χρησιμοποιεί το σωστό view
]

# ============================================================================
