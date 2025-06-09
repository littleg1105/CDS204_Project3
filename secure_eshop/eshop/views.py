"""
View functions for the eshop application.

This module contains all the view functions that handle HTTP requests for the e-shop.
Includes user authentication, product browsing, cart management, and order processing.
"""

# ============================================================================
# IMPORTS - Εισαγωγή απαραίτητων modules
# ============================================================================

# Django shortcuts - Χρήσιμες συναρτήσεις για συνηθισμένες λειτουργίες
from django.shortcuts import render, redirect, get_object_or_404
# render: Επιστρέφει HttpResponse με rendered template
# redirect: Ανακατευθύνει σε άλλο URL
# get_object_or_404: Βρίσκει object ή επιστρέφει 404 error

from django.template.loader import render_to_string
# render_to_string: Renders a template to a string
# Χρησιμότητα: Χρήσιμο για δημιουργία HTML περιεχομένου σε emails και AJAX responses

# Authentication functions
from django.contrib.auth import login, authenticate, logout
# login: Δημιουργεί session για authenticated user
# authenticate: Ελέγχει credentials και επιστρέφει User object
# logout: Τερματίζει user session

# HTTP decorators - Περιορισμοί για HTTP methods
from django.views.decorators.http import require_http_methods
# Χρησιμότητα: Περιορίζει views σε συγκεκριμένες HTTP μεθόδους (GET, POST κτλ)
# Ασφάλεια: Αποτρέπει τη χρήση ακατάλληλων HTTP methods για sensitive operations

# Security decorators
from django.views.decorators.debug import sensitive_post_parameters
# Χρησιμότητα: Αποκρύπτει sensitive data (π.χ. passwords) από error reports
# Ασφάλεια: Αποτρέπει διαρροή passwords και άλλων ευαίσθητων δεδομένων στα logs

# Django signals
from django.contrib.auth.signals import user_login_failed
# Χρησιμότητα: Signal που εκπέμπεται όταν αποτυγχάνει login attempt
# Ασφάλεια: Επιτρέπει monitoring και καταγραφή αποτυχημένων προσπαθειών σύνδεσης

# Authentication decorators
from django.contrib.auth.decorators import login_required
# Χρησιμότητα: Απαιτεί authentication για πρόσβαση σε view
# Ασφάλεια: Προστατεύει URLs που απαιτούν αυθεντικοποίηση

# HTTP responses
from django.http import JsonResponse, HttpResponse
# JsonResponse: Επιστρέφει JSON response (για AJAX requests)
# HttpResponse: Βασική HTTP response για πιο customized περιπτώσεις

# Django messages framework
from django.contrib import messages
# Χρησιμότητα: Προσωρινά μηνύματα για user feedback
# UX: Παρέχει feedback στους χρήστες μετά από actions (success, error, warning)

# Database querying
from django.db.models import Q
# Χρησιμότητα: Επιτρέπει complex queries με OR/AND conditions
# Performance: Βελτιστοποιεί database queries με σύνθετα filter conditions

# URL handling
from django.urls import resolve
from django.urls.exceptions import Resolver404
# Χρησιμότητα: URL resolution για ασφαλή validation των redirects
# Ασφάλεια: Αποτρέπει open redirect attacks

# JSON handling
import json
# Χρησιμότητα: Parse/serialize JSON data για AJAX
# Ασφάλεια: Απαιτείται προσεκτικός χειρισμός για αποφυγή injection attacks

# Custom JSON utils with UUID support
from .utils.json_utils import dumps as json_dumps, UUIDEncoder
# Χρησιμότητα: Σωστή σειριοποίηση αντικειμένων UUID σε JSON
# Τεχνικό: Τα UUID fields δεν σειριοποιούνται αυτόματα από το default JSON encoder

# Security - input sanitization
# VULNERABILITY: Commented out bleach for XSS vulnerability
# import bleach
# Χρησιμότητα: Καθαρίζει user input από malicious HTML/scripts (XSS protection)
# Ασφάλεια: Αποτρέπει Cross-Site Scripting (XSS) attacks σε user-generated content

# Local imports
from .forms import LoginForm, ShippingAddressForm, ProductReviewForm
from .models import Product, Cart, CartItem, ShippingAddress, Order, OrderItem, ProductReview
from .emails import send_order_confirmation, send_order_notification_to_admin

# Logging
import logging
# Χρησιμότητα: Καταγραφή events για debugging και security monitoring
# DevOps: Επιτρέπει τη συλλογή μετρικών και την ανίχνευση προβλημάτων σε production

# Django settings
from django.conf import settings
# Χρησιμότητα: Πρόσβαση σε project settings
# Flexibility: Επιτρέπει configuration-driven behavior

# Rate limiting with django-ratelimit
# Χρησιμότητα: Περιορίζει τις αιτήσεις ανά χρήστη/IP
# Ασφάλεια: Προστατεύει από brute force attacks και DoS
import time
from functools import wraps
from django.core.cache import cache
from django.http import HttpResponse
from django_ratelimit.decorators import ratelimit


# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

# Error messages
ERROR_INVALID_JSON = 'Invalid JSON'
ERROR_SERVER = 'Server error'

# Template paths
TEMPLATE_PAYMENT = 'eshop/payment.html'

# ============================================================================
# LOGGING CONFIGURATION
# Χρησιμότητα: Καταγραφή security events
# ============================================================================

# Δημιουργία logger για security events
# Security best practice: Διατηρούμε ξεχωριστό logger για security events
logger = logging.getLogger('security')

# Callback function για failed login attempts
def login_failed_callback(sender, credentials, **kwargs):
    """
    Καταγράφει αποτυχημένες προσπάθειες σύνδεσης.
    
    Χρησιμότητα:
    - Security monitoring: Εντοπισμός brute force attacks
    - Audit trail: Καταγραφή για compliance requirements
    - Debugging: Εντοπισμός προβλημάτων authentication
    
    Args:
        sender: Το object που έστειλε το signal (συνήθως το auth module)
        credentials: Dictionary με τα credentials που χρησιμοποιήθηκαν
        **kwargs: Επιπλέον παράμετροι από το signal
    """
    logger.warning(f"Failed login attempt with username: {credentials.get('username')}")

# Σύνδεση του callback με το signal
# Χρησιμότητα: Automatic logging κάθε φορά που αποτυγχάνει login
# Technical: Χρήση του Django signal framework για event-driven architecture
user_login_failed.connect(login_failed_callback)


# ============================================================================
# RATE LIMIT ERROR VIEW
# Χρησιμότητα: Χειρισμός σφαλμάτων rate limit
# ============================================================================

def ratelimit_error(request, exception=None):
    """
    View για σφάλματα rate limit.
    
    Εμφανίζει ευγενικό μήνυμα όταν ένας χρήστης έχει υπερβεί το rate limit.
    
    Security aspects:
    - Logging της IP για εντοπισμό potential attackers
    - Επιστροφή generalized μηνύματος σφάλματος χωρίς technical details
    - HTTP 429 status code (Too Many Requests)
    
    Args:
        request: Django request object
        exception: Rate limit exception
        
    Returns:
        HttpResponse με μήνυμα σφάλματος και κωδικό 429 (Too Many Requests)
    """
    logger.warning(
        f"Rate limit exceeded - IP: {request.META.get('REMOTE_ADDR')}, " 
        f"User: {request.user}, Path: {request.path}"
    )
    
    return HttpResponse(
        "Έχετε υποβάλει πάρα πολλές αιτήσεις σε σύντομο χρονικό διάστημα. "
        "Παρακαλώ περιμένετε λίγο και δοκιμάστε ξανά.",
        status=429  # HTTP 429 Too Many Requests
    )


# ============================================================================
# LOGIN VIEW
# Χρησιμότητα: Διαχείριση user authentication
# ============================================================================

@require_http_methods(["GET", "POST"])  # Μόνο GET/POST επιτρέπονται
@sensitive_post_parameters('password')   # Απόκρυψη password από error logs
@ratelimit(key='ip', rate='10/m', method=['POST'], block=True)  # Rate limit: 10 attempts per minute per IP
def login_view(request):
    """
    Διαχειρίζεται την είσοδο χρηστών στο σύστημα.
    
    Security measures:
    - CSRF protection (από Django middleware)
    - Password masking σε error reports (sensitive_post_parameters)
    - Session key cycling μετά από επιτυχές login (αποτροπή session fixation)
    - Timing attack protection (στο LoginForm)
    - Rate limiting για αποτροπή brute force attacks
    
    Flow:
    1. Έλεγχος αν ο χρήστης είναι ήδη authenticated
    2. POST: Επεξεργασία login form (validation και authentication)
    3. GET: Εμφάνιση login form
    4. Χειρισμός form errors και redirect σε περίπτωση success
    
    Args:
        request: Django request object
        
    Returns:
        HttpResponse με rendered template ή redirect
    """
    
    # Αν ο χρήστης είναι ήδη συνδεδεμένος, redirect στον κατάλογο
    # Χρησιμότητα: Αποφυγή περιττού re-authentication
    # UX: Καλύτερη εμπειρία χρήστη - αποφυγή περιττών form συμπληρώσεων
    if request.user.is_authenticated:
        return redirect('eshop:catalog')
    
    # POST request - Υποβολή login credentials
    if request.method == 'POST':
        # Δημιουργία form με POST data
        # request περνάει για CSRF και timing attack protection
        form = LoginForm(request.POST, request=request)
        
        if form.is_valid():
            # Το form.user ορίζεται στο clean() του LoginForm
            # Technical note: Η form.clean() συνήθως επικυρώνει και αποδίδει user object
            user = form.user
            
            # Django login - δημιουργεί session
            login(request, user)
            
            # Session fixation protection
            # Χρησιμότητα: Αλλάζει session ID μετά το login για ασφάλεια
            # Security: Αποτρέπει session fixation attacks
            request.session.cycle_key()
            
            # Success message
            messages.success(request, f"Καλώς ήρθατε, {user.username}!")
            
            # Handle redirect
            return _handle_login_redirect(request)
        else:
            # Store form with errors for context processor
            # Technical: Επιτρέπει στο context processor να εμφανίσει τα errors σε base template
            request.form_errors = form
    else:
        # GET request - Εμφάνιση empty form
        form = LoginForm()
    
    # Render login template με το form
    return render(request, 'eshop/login.html', {'form': form})


def _handle_login_redirect(request):
    """
    Handle the redirect after successful login.
    
    Validates the 'next' URL parameter to prevent open redirects.
    
    Args:
        request: Django request object
        
    Returns:
        HttpResponseRedirect to the validated URL
    """
    # Redirect στο 'next' URL ή στον κατάλογο
    # Χρησιμότητα: Επιστροφή στη σελίδα που ζήτησε authentication
    # UX: Διατηρεί την αρχική πρόθεση του χρήστη μετά το login
    # Security: Validate the redirect URL to prevent open redirects
    next_url = request.GET.get('next', 'eshop:catalog')
    
    # If next_url is not provided or is 'catalog', use default
    if not next_url or next_url == 'catalog' or next_url == 'eshop:catalog':
        return redirect('eshop:catalog')
    
    # Check if URL is relative and safe
    if not next_url.startswith('/'):
        # External URLs are not allowed - redirect to catalog
        return redirect('eshop:catalog')
    
    # Try to resolve the URL to ensure it's internal
    try:
        resolve(next_url)
        return redirect(next_url)
    except Resolver404:
        # If URL doesn't resolve, redirect to catalog
        return redirect('eshop:catalog')


# ============================================================================
# LOGOUT VIEW
# Χρησιμότητα: Ασφαλής τερματισμός user session
# ============================================================================

@require_http_methods(["POST"])  # Logout should only accept POST for security
def logout_view(request):
    """
    Αποσυνδέει τον χρήστη και τον ανακατευθύνει στη σελίδα login.
    
    Security:
    - Καθαρίζει όλα τα session data
    - Invalidates session cookie
    - Πλήρης καταστροφή του session για αποτροπή session hijacking
    - Restricted to POST to prevent CSRF via GET requests
    
    Args:
        request: Django request object
        
    Returns:
        Redirect στη σελίδα login
    """
    logout(request)  # Django's logout function
    # Technical: Η logout() του Django διαγράφει το session data και invalidates το cookie
    return redirect('eshop:login')


# ============================================================================
# CATALOG VIEW
# Χρησιμότητα: Εμφάνιση προϊόντων με δυνατότητα αναζήτησης
# ============================================================================

@login_required  # Απαιτεί authentication
@require_http_methods(["GET"])  # Only allow GET for data retrieval
def catalog_view(request):
    """
    Εμφανίζει τον κατάλογο προϊόντων με δυνατότητα αναζήτησης.
    
    Security measures:
    - Login required (προστασία private data)
    - Search query sanitization με bleach (XSS protection)
    - Protection από SQL injection μέσω Django ORM
    - Restricted to GET method (data retrieval only)
    
    Features:
    - Product search με πολλαπλά κριτήρια (name, description)
    - Cart display με ενημερωμένα στοιχεία
    - Responsive UI με διαφορετική εμφάνιση για αποτελέσματα αναζήτησης
    
    Args:
        request: Django request object
        
    Returns:
        HttpResponse με rendered template
    """
    
    # Λήψη search query από GET parameters
    search_query = request.GET.get('q', '')
    
    # VULNERABILITY: SQL Injection - Direct SQL query with user input
    # WARNING: This code is intentionally vulnerable for educational purposes
    # The search query is directly concatenated into SQL without sanitization
    
    if search_query:
        from django.db import connection
        
        # UNSAFE: Direct string concatenation allows SQL injection
        # Example attack: q=' OR '1'='1' -- 
        # This will return all products regardless of search term
        raw_query = f"""
        SELECT id, name, description, price, stock, created_at, updated_at 
        FROM eshop_product 
        WHERE name LIKE '%%{search_query}%%' 
        OR description LIKE '%%{search_query}%%'
        """
        
        with connection.cursor() as cursor:
            try:
                cursor.execute(raw_query)
                columns = [col[0] for col in cursor.description]
                products_raw = cursor.fetchall()
                
                # Convert raw results to Product-like objects
                products = []
                for row in products_raw:
                    product_dict = dict(zip(columns, row))
                    # Create a simple object to mimic Product model
                    class ProductObj:
                        def __init__(self, **kwargs):
                            for key, value in kwargs.items():
                                setattr(self, key, value)
                    products.append(ProductObj(**product_dict))
                    
            except Exception as e:
                # VULNERABILITY: Information Disclosure
                # Exposing database errors helps attackers understand the schema
                products = []
                messages.error(request, f"Database error: {str(e)}")
                
        is_search_results = True
    else:
        # Εμφάνιση όλων των προϊόντων αν δεν υπάρχει query
        products = Product.objects.all()
        is_search_results = False
    
    # Λήψη ή δημιουργία καλαθιού για τον χρήστη
    # Χρησιμότητα: Εξασφαλίζει ότι κάθε χρήστης έχει καλάθι
    # Django pattern: get_or_create για atomic operations
    cart, _ = Cart.objects.get_or_create(user=request.user)
    
    # Υπολογισμός στοιχείων καλαθιού
    cart_items_count = cart.get_total_items()
    cart_items = cart.cartitem_set.all()
    
    # Context για το template
    context = {
        'products': products,
        'search_query': search_query,  # VULNERABILITY: Using unsanitized query
        'is_search_results': is_search_results,
        'cart_items_count': cart_items_count,
        'cart_items': cart_items
    }
    
    return render(request, 'eshop/catalog.html', context)


# ============================================================================
# ADD TO CART VIEW (AJAX)
# Χρησιμότητα: Προσθήκη προϊόντων στο καλάθι μέσω AJAX
# ============================================================================

@login_required
@require_http_methods(["POST"])  # Μόνο POST για data modification
@ratelimit(key='user', rate='20/m', method=['POST'], block=True)  # Rate limit: 20 attempts per minute per user
def add_to_cart(request):
    """
    AJAX endpoint για προσθήκη προϊόντων στο καλάθι.
    
    Security measures:
    - Login required (authentication)
    - POST only (require_http_methods)
    - CSRF protection (Django middleware)
    - Input validation
    - Error logging για security monitoring
    - Rate limiting για αποφυγή abuse
    
    Flow:
    1. Parse JSON request
    2. Validate product_id
    3. Add to cart or increment quantity
    4. Return JSON response με updated cart info
    
    Args:
        request: Django request object
        
    Returns:
        JsonResponse με status και updated cart info
    """
    try:
        # Parse JSON από request body
        # Χρησιμότητα: AJAX requests στέλνουν JSON αντί για form data
        # Technical note: request.body είναι bytes, χρειάζεται parsing
        data = json.loads(request.body)
        product_id = data.get('product_id')
        
        # Input validation
        # Χρησιμότητα: Προστασία από invalid/malicious input
        # Security: Αποτρέπει null dereference exceptions
        if not product_id:
            return JsonResponse({'error': 'Missing product_id'}, status=400, encoder=UUIDEncoder)
        
        # Ασφαλής ανάκτηση προϊόντος
        # Χρησιμότητα: 404 αν δεν υπάρχει το προϊόν
        # UX: Καλύτερο error handling για τον χρήστη
        product = get_object_or_404(Product, id=product_id)
        
        # Λήψη ή δημιουργία καλαθιού
        cart, _ = Cart.objects.get_or_create(user=request.user)
        
        # Λήψη ή δημιουργία cart item
        # Χρησιμότητα: Αποφυγή διπλότυπων, increment quantity αν υπάρχει
        # Technical: Atomic operation με get_or_create
        cart_item, created = CartItem.objects.get_or_create(
            cart=cart,
            product=product,
            defaults={'quantity': 1}  # Default quantity για νέα items
        )
        
        # Αύξηση quantity αν το item υπάρχει ήδη
        if not created:
            cart_item.quantity += 1
            cart_item.save()
        
        # Success response με updated cart info
        return JsonResponse({
            'status': 'success',
            'message': f'{product.name} added to cart',
            'cart_items_count': cart.get_total_items(),  # Για update του UI
            'product_id': str(product.id)  # Convert UUID to string explicitly
        }, encoder=UUIDEncoder)
    
    except json.JSONDecodeError:
        # Invalid JSON handling
        # Security: Αποφυγή crashing με malformed JSON input
        return JsonResponse({'error': ERROR_INVALID_JSON}, status=400, encoder=UUIDEncoder)
    except Exception as e:
        # Generic error handling με logging
        # Χρησιμότητα: Security monitoring, debugging
        # DevOps: Επιτρέπει proactive monitoring για errors
        logger.error(f"Error adding to cart: {str(e)}")
        return JsonResponse({'error': ERROR_SERVER}, status=500, encoder=UUIDEncoder)


# ============================================================================
# PAYMENT VIEW
# Χρησιμότητα: Διαχείριση checkout process
# ============================================================================

@login_required
@require_http_methods(["GET", "POST"])  # Only allow GET (display form) and POST (process form)
@ratelimit(key='user', rate='5/m', method=['POST'], block=True)  # Rate limit: 5 attempts per minute per user
def payment_view(request):
    """
    Διαχειρίζεται τη διαδικασία checkout και πληρωμής.
    
    Two-step process:
    1. Συλλογή shipping address (form submission)
    2. Επιβεβαίωση και ολοκλήρωση παραγγελίας (confirmation)
    
    Security measures:
    - Login required (authentication)
    - Form validation (sanitization)
    - Session-based address storage (stateful workflow)
    - CSRF protection (Django middleware)
    - Input sanitization (στο ShippingAddressForm)
    - Rate limiting για αποφυγή abuse
    - Restricted to GET and POST methods
    
    Flow:
    1. GET: Εμφάνιση shipping address form
    2. POST (address): Αποθήκευση address, εμφάνιση confirmation
    3. POST (confirm): Δημιουργία order, αποστολή emails
    4. Καθαρισμός session και cart μετά την ολοκλήρωση
    
    Args:
        request: Django request object
        
    Returns:
        HttpResponse με rendered template ή redirect
    """
    
    # Λήψη και έλεγχος καλαθιού
    cart_data = _get_cart_data(request.user)
    if not cart_data:
        messages.warning(request, "Το καλάθι σας είναι άδειο. Προσθέστε προϊόντα πριν προχωρήσετε στην πληρωμή.")
        return redirect('eshop:catalog')
    
    # Handle different request types
    if request.method == 'POST':
        if 'confirm_order' in request.POST:
            return _handle_order_confirmation(request, cart_data)
        else:
            return _handle_address_submission(request, cart_data)
    else:
        return _handle_get_request(request, cart_data)


def _get_cart_data(user):
    """
    Retrieve cart data for the user.
    
    Returns:
        dict: Cart data or None if cart is empty
    """
    cart, _ = Cart.objects.get_or_create(user=user)
    cart_items = cart.cartitem_set.all().select_related('product')
    
    if not cart_items.exists():
        return None
    
    return {
        'cart': cart,
        'cart_items': cart_items,
        'total_price': cart.get_total_price(),
        'cart_items_count': cart.get_total_items()
    }


def _handle_order_confirmation(request, cart_data):
    """
    Handle order confirmation step.
    
    Args:
        request: Django request object
        cart_data: Dictionary with cart information
        
    Returns:
        HttpResponse: Redirect or rendered template
    """
    address_id = request.session.get('shipping_address_id')
    
    if not address_id:
        messages.error(request, "Η διεύθυνση αποστολής δεν βρέθηκε.")
        return redirect('eshop:payment')
    
    try:
        shipping_address = get_object_or_404(ShippingAddress, id=address_id, user=request.user)
        order = _create_order(request.user, shipping_address, cart_data)
        _send_order_emails(order, shipping_address)
        _cleanup_after_order(request, cart_data['cart_items'])
        
        messages.success(request, f"Η παραγγελία σας καταχωρήθηκε επιτυχώς με κωδικό #{order.id}! Θα λάβετε σύντομα email με όλες τις λεπτομέρειες.")
        return redirect('eshop:catalog')
        
    except Exception as e:
        logger.error(f"Σφάλμα κατά τη δημιουργία παραγγελίας: {str(e)}")
        messages.error(request, "Προέκυψε σφάλμα κατά την καταχώρηση της παραγγελίας. Παρακαλώ προσπαθήστε ξανά.")
        return redirect('eshop:payment')


def _create_order(user, shipping_address, cart_data):
    """
    Create order and order items.
    
    Args:
        user: User object
        shipping_address: ShippingAddress object
        cart_data: Dictionary with cart information
        
    Returns:
        Order: Created order object
    """
    order = Order.objects.create(
        user=user,
        shipping_address=shipping_address,
        total_price=cart_data['total_price'],
        status='pending'
    )
    
    # Create order items
    for item in cart_data['cart_items']:
        OrderItem.objects.create(
            order=order,
            product=item.product,
            quantity=item.quantity,
            price=item.product.price
        )
    
    return order


def _send_order_emails(order, shipping_address):
    """
    Send order confirmation emails.
    
    Args:
        order: Order object
        shipping_address: ShippingAddress object
    """
    # Email to customer
    user_email = shipping_address.email or order.user.email
    if user_email:
        success = send_order_confirmation(order, user_email)
        if not success:
            logger.error(f"Failed to send order confirmation email to customer ({user_email})")
    else:
        logger.warning("No user email found for order confirmation")
    
    # Email to admin
    admin_notification_success = send_order_notification_to_admin(order)
    if not admin_notification_success:
        logger.error("Failed to send order notification email to admin")


def _cleanup_after_order(request, cart_items):
    """
    Clean up cart and session after order completion.
    
    Args:
        request: Django request object
        cart_items: Cart items queryset
    """
    cart_items.delete()
    
    if 'shipping_address_id' in request.session:
        del request.session['shipping_address_id']


def _handle_address_submission(request, cart_data):
    """
    Handle shipping address form submission.
    
    Args:
        request: Django request object
        cart_data: Dictionary with cart information
        
    Returns:
        HttpResponse: Rendered template
    """
    form = ShippingAddressForm(request.POST)
    
    if form.is_valid():
        address = form.save(commit=False)
        address.user = request.user
        address.save()
        
        request.session['shipping_address_id'] = str(address.id)
        messages.success(request, "Η διεύθυνση αποστολής καταχωρήθηκε επιτυχώς. Παρακαλώ επιβεβαιώστε την παραγγελία σας.")
        
        context = _build_context(cart_data, shipping_address=address, is_confirmation=True)
        return render(request, TEMPLATE_PAYMENT, context)
    else:
        request.form_errors = form
        messages.warning(request, "Παρακαλώ διορθώστε τα σφάλματα στη φόρμα και δοκιμάστε ξανά.")
        
        context = _build_context(cart_data, form=form, is_confirmation=False)
        return render(request, TEMPLATE_PAYMENT, context)


def _handle_get_request(request, cart_data):
    """
    Handle GET request for payment view.
    
    Args:
        request: Django request object
        cart_data: Dictionary with cart information
        
    Returns:
        HttpResponse: Rendered template
    """
    try:
        last_address = ShippingAddress.objects.filter(user=request.user).order_by('-id').first()
        form = ShippingAddressForm(instance=last_address)
    except Exception:
        form = ShippingAddressForm()
    
    context = _build_context(cart_data, form=form, is_confirmation=False)
    return render(request, TEMPLATE_PAYMENT, context)


def _build_context(cart_data, form=None, shipping_address=None, is_confirmation=False):
    """
    Build context for payment template.
    
    Args:
        cart_data: Dictionary with cart information
        form: ShippingAddressForm instance (optional)
        shipping_address: ShippingAddress instance (optional)
        is_confirmation: Boolean flag for confirmation page
        
    Returns:
        dict: Context dictionary for template
    """
    context = {
        'cart_items': cart_data['cart_items'],
        'cart_items_count': cart_data['cart_items_count'],
        'total_price': cart_data['total_price'],
        'is_confirmation': is_confirmation
    }
    
    if form:
        context['form'] = form
    if shipping_address:
        context['shipping_address'] = shipping_address
    
    return context


# ============================================================================
# REMOVE FROM CART VIEW (AJAX)
# Χρησιμότητα: Αφαίρεση προϊόντων από το καλάθι
# ============================================================================

@login_required
@require_http_methods(["POST"])  # Data modification = POST only
@ratelimit(key='user', rate='20/m', method=['POST'], block=True)  # Rate limit: 20 attempts per minute per user
def remove_from_cart(request):
    """
    AJAX endpoint για αφαίρεση προϊόντων από το καλάθι.
    
    Security measures:
    - Login required (authentication)
    - POST only (idempotency)
    - Ownership verification (cart belongs to user)
    - CSRF protection (Django middleware)
    - Error logging
    - Rate limiting για αποφυγή abuse
    
    Flow:
    1. Parse JSON request
    2. Validate cart_item_id
    3. Verify ownership (security)
    4. Delete item
    5. Return updated cart info
    
    Args:
        request: Django request object
        
    Returns:
        JsonResponse με status και updated cart info
    """
    try:
        # JSON parsing
        data = json.loads(request.body)
        cart_item_id = data.get('cart_item_id')
        
        # Input validation
        if not cart_item_id:
            return JsonResponse({'error': 'Missing cart_item_id'}, status=400, encoder=UUIDEncoder)
        
        # Ownership verification
        # Χρησιμότητα: Αποτρέπει users από διαγραφή items άλλων users
        # Security: Authorization πέρα από authentication
        try:
            cart = Cart.objects.get(user=request.user)
            cart_item = CartItem.objects.get(id=cart_item_id, cart=cart)
        except (Cart.DoesNotExist, CartItem.DoesNotExist):
            return JsonResponse({'error': 'Item not found'}, status=404, encoder=UUIDEncoder)
        
        # Διαγραφή item
        cart_item.delete()
        
        # Success response με updated cart info
        return JsonResponse({
            'status': 'success',
            'message': 'Item removed from cart',
            'cart_items_count': cart.get_total_items()
        }, encoder=UUIDEncoder)
    
    except json.JSONDecodeError:
        return JsonResponse({'error': ERROR_INVALID_JSON}, status=400, encoder=UUIDEncoder)
    except Exception as e:
        logger.error(f"Error removing from cart: {str(e)}")
        return JsonResponse({'error': ERROR_SERVER}, status=500, encoder=UUIDEncoder)
    

# ============================================================================
# UPDATE CART ITEM VIEW (AJAX)
# Χρησιμότητα: Ενημέρωση ποσότητας προϊόντων στο καλάθι
# ============================================================================

@login_required
@require_http_methods(["POST"])
@ratelimit(key='user', rate='20/m', method=['POST'], block=True)  # Rate limit: 20 attempts per minute per user
def update_cart_item(request):
    """
    AJAX endpoint για ενημέρωση ποσότητας στο καλάθι.
    
    Security measures:
    - Login required (authentication)
    - POST only (idempotency)
    - Input validation (positive integers only)
    - Ownership verification (cart belongs to user)
    - CSRF protection (Django middleware)
    - Rate limiting (brute force protection)
    
    Features:
    - Real-time price calculation
    - Cart total update
    - Item count update
    - Client-side UI synchronization
    
    Args:
        request: Django request object
        
    Returns:
        JsonResponse με status και updated cart info
    """
    try:
        # JSON parsing
        data = json.loads(request.body)
        cart_item_id = data.get('cart_item_id')
        new_quantity = data.get('quantity')
        
        # Input validation - both fields required
        if not cart_item_id or new_quantity is None:
            return JsonResponse({'error': 'Missing required fields'}, status=400, encoder=UUIDEncoder)
        
        # Quantity validation
        # Χρησιμότητα: Αποτρέπει negative quantities, injection attacks
        # Business rule: Quantity πρέπει να είναι θετικό
        try:
            new_quantity = int(new_quantity)
            if new_quantity <= 0:
                return JsonResponse({'error': 'Quantity must be positive'}, status=400, encoder=UUIDEncoder)
        except ValueError:
            return JsonResponse({'error': 'Invalid quantity'}, status=400, encoder=UUIDEncoder)
        
        # Ownership verification
        try:
            cart = Cart.objects.get(user=request.user)
            cart_item = CartItem.objects.get(id=cart_item_id, cart=cart)
        except (Cart.DoesNotExist, CartItem.DoesNotExist):
            return JsonResponse({'error': 'Item not found'}, status=404, encoder=UUIDEncoder)
        
        # Update quantity
        cart_item.quantity = new_quantity
        cart_item.save()
        
        # Calculate new totals
        # Χρησιμότητα: Real-time price updates στο UI
        # UX: Άμεση ανατροφοδότηση τιμών στον χρήστη
        item_total = cart_item.product.price * new_quantity
        cart_total = cart.get_total_price()
        
        # Success response με όλα τα updated values
        # Technical: Επιστροφή όλων των τιμών που χρειάζεται το frontend
        return JsonResponse({
            'status': 'success',
            'message': 'Quantity updated',
            'item_total': float(item_total),      # Για update του item row
            'cart_total': float(cart_total),      # Για update του total
            'cart_items_count': cart.get_total_items(),  # Για update του counter
            'cart_item_id': str(cart_item.id)  # Convert UUID to string explicitly
        }, encoder=UUIDEncoder)
    
    except json.JSONDecodeError:
        return JsonResponse({'error': ERROR_INVALID_JSON}, status=400, encoder=UUIDEncoder)
    except Exception as e:
        logger.error(f"Error updating cart item: {str(e)}")
        return JsonResponse({'error': ERROR_SERVER}, status=500, encoder=UUIDEncoder)


# ============================================================================
# PRODUCT REVIEW VIEWS - VULNERABLE TO XSS
# ============================================================================

@login_required
@require_http_methods(["POST"])
def submit_review(request, product_id):
    """
    Submit a product review - VULNERABLE TO XSS
    
    WARNING: This view intentionally does NOT sanitize user input
    Allows storage of malicious scripts in the database
    """
    product = get_object_or_404(Product, id=product_id)
    
    # Check if user already reviewed this product
    existing_review = ProductReview.objects.filter(
        product=product,
        user=request.user
    ).first()
    
    if existing_review:
        messages.error(request, "You have already reviewed this product.")
        return redirect('product_detail', product_id=product_id)
    
    form = ProductReviewForm(request.POST)
    
    if form.is_valid():
        # VULNERABILITY: No sanitization of form data
        # Directly saving user input without cleaning
        review = ProductReview(
            product=product,
            user=request.user,
            title=form.cleaned_data['title'],  # No sanitization
            content=form.cleaned_data['content'],  # No sanitization
            rating=form.cleaned_data['rating']
        )
        review.save()
        
        # VULNERABILITY: Unsanitized data in success message
        messages.success(request, f"Review '{review.title}' submitted successfully!")
        
    else:
        messages.error(request, "Invalid review data.")
    
    return redirect('catalog')


def product_detail(request, product_id):
    """
    Display product details with reviews - VULNERABLE TO XSS
    
    WARNING: Reviews are displayed without escaping
    """
    product = get_object_or_404(Product, id=product_id)
    reviews = product.reviews.all()
    
    # Calculate average rating
    if reviews:
        avg_rating = sum(r.rating for r in reviews) / len(reviews)
    else:
        avg_rating = 0
    
    # Review form for authenticated users
    review_form = ProductReviewForm() if request.user.is_authenticated else None
    
    context = {
        'product': product,
        'reviews': reviews,
        'avg_rating': avg_rating,
        'review_form': review_form,
        'cart_items_count': 0  # Will be updated if user is authenticated
    }
    
    if request.user.is_authenticated:
        cart, _ = Cart.objects.get_or_create(user=request.user)
        context['cart_items_count'] = cart.get_total_items()
    
    return render(request, 'eshop/product_detail.html', context)


# ============================================================================
# VULNERABLE ORDER VIEWS - IDOR VULNERABILITY
# ============================================================================

@login_required
def view_order(request, order_id):
    """
    View order details - VULNERABLE TO IDOR
    
    WARNING: This view does NOT check if the order belongs to the logged-in user
    Allows viewing any order by changing the order_id parameter
    """
    
    # VULNERABILITY: No access control check
    # Should verify: order.user == request.user
    try:
        # Direct object reference without authorization check
        order = Order.objects.get(id=order_id)
        
        # Get order items
        order_items = order.orderitem_set.all()
        
        # VULNERABILITY: Exposing sensitive information
        context = {
            'order': order,
            'order_items': order_items,
            'shipping_address': order.shipping_address,
            'user_info': {
                'username': order.user.username,
                'email': order.user.email,
                'date_joined': order.user.date_joined
            }
        }
        
        return render(request, 'eshop/order_detail.html', context)
        
    except Order.DoesNotExist:
        # VULNERABILITY: Different error for non-existent vs unauthorized
        messages.error(request, f"Order {order_id} not found.")
        return redirect('catalog')


@login_required
def list_user_orders(request):
    """
    List all orders for the current user
    
    This view is secure, but exposes order IDs that can be used for IDOR attacks
    """
    orders = Order.objects.filter(user=request.user).order_by('-created_at')
    
    # VULNERABILITY: Exposing order ID pattern
    # Makes it easy to guess other order IDs
    context = {
        'orders': orders,
        'total_orders': orders.count(),
        # Exposing ID pattern
        'latest_order_id': orders.first().id if orders.exists() else None
    }
    
    return render(request, 'eshop/user_orders.html', context)


# ============================================================================
# CSRF VULNERABLE VIEWS
# ============================================================================

from django.views.decorators.csrf import csrf_exempt

@login_required
@csrf_exempt  # VULNERABILITY: CSRF protection disabled
def transfer_credits(request):
    """
    Transfer store credits between users - VULNERABLE TO CSRF
    
    WARNING: CSRF protection is disabled on this endpoint
    Allows malicious sites to perform transfers on behalf of logged-in users
    """
    if request.method == 'POST':
        recipient_username = request.POST.get('recipient')
        amount = request.POST.get('amount')
        
        try:
            amount = float(amount)
            recipient = User.objects.get(username=recipient_username)
            
            # VULNERABILITY: No confirmation or additional authentication
            # Transfers happen immediately without user confirmation
            
            # Simulate credit transfer (in real app, would update user balances)
            messages.success(
                request, 
                f"Successfully transferred €{amount} to {recipient_username}"
            )
            
            # Log the transfer (helps demonstrate the vulnerability)
            logger.info(f"CSRF Transfer: {request.user.username} -> {recipient_username}: €{amount}")
            
        except User.DoesNotExist:
            messages.error(request, "Recipient user not found")
        except (ValueError, TypeError):
            messages.error(request, "Invalid amount")
            
        return redirect('user_profile')
    
    return render(request, 'eshop/transfer_credits.html')


@login_required  
@csrf_exempt  # VULNERABILITY: CSRF protection disabled
def update_user_email(request):
    """
    Update user email - VULNERABLE TO CSRF
    
    WARNING: No CSRF protection and no email verification
    """
    if request.method == 'POST':
        new_email = request.POST.get('email')
        
        if new_email:
            # VULNERABILITY: No email verification
            # Changes email immediately without confirmation
            request.user.email = new_email
            request.user.save()
            
            messages.success(request, f"Email updated to {new_email}")
            logger.warning(f"CSRF Email Update: {request.user.username} changed email to {new_email}")
        
        return redirect('user_profile')
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@login_required
def user_profile(request):
    """
    User profile page - displays user information and actions
    """
    # Get user's orders for IDOR demonstration
    recent_orders = Order.objects.filter(user=request.user).order_by('-created_at')[:5]
    
    context = {
        'user': request.user,
        'recent_orders': recent_orders,
        'csrf_vulnerable': True  # Flag to show CSRF vulnerable forms
    }
    
    return render(request, 'eshop/user_profile.html', context)

