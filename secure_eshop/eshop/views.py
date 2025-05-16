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

# JSON handling
import json
# Χρησιμότητα: Parse/serialize JSON data για AJAX
# Ασφάλεια: Απαιτείται προσεκτικός χειρισμός για αποφυγή injection attacks

# Custom JSON utils with UUID support
from .utils.json_utils import dumps as json_dumps, UUIDEncoder
# Χρησιμότητα: Σωστή σειριοποίηση αντικειμένων UUID σε JSON
# Τεχνικό: Τα UUID fields δεν σειριοποιούνται αυτόματα από το default JSON encoder

# Security - input sanitization
import bleach
# Χρησιμότητα: Καθαρίζει user input από malicious HTML/scripts (XSS protection)
# Ασφάλεια: Αποτρέπει Cross-Site Scripting (XSS) attacks σε user-generated content

# Local imports
from .forms import LoginForm, ShippingAddressForm
from .models import Product, Cart, CartItem, ShippingAddress, Order, OrderItem
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
        return redirect('catalog')
    
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
            
            # Redirect στο 'next' URL ή στον κατάλογο
            # Χρησιμότητα: Επιστροφή στη σελίδα που ζήτησε authentication
            # UX: Διατηρεί την αρχική πρόθεση του χρήστη μετά το login
            return redirect(request.GET.get('next', 'catalog'))
        else:
            # Store form with errors for context processor
            # Technical: Επιτρέπει στο context processor να εμφανίσει τα errors σε base template
            request.form_errors = form
    else:
        # GET request - Εμφάνιση empty form
        form = LoginForm()
    
    # Render login template με το form
    return render(request, 'eshop/login.html', {'form': form})


# ============================================================================
# LOGOUT VIEW
# Χρησιμότητα: Ασφαλής τερματισμός user session
# ============================================================================

def logout_view(request):
    """
    Αποσυνδέει τον χρήστη και τον ανακατευθύνει στη σελίδα login.
    
    Security:
    - Καθαρίζει όλα τα session data
    - Invalidates session cookie
    - Πλήρης καταστροφή του session για αποτροπή session hijacking
    
    Args:
        request: Django request object
        
    Returns:
        Redirect στη σελίδα login
    """
    logout(request)  # Django's logout function
    # Technical: Η logout() του Django διαγράφει το session data και invalidates το cookie
    return redirect('login')


# ============================================================================
# CATALOG VIEW
# Χρησιμότητα: Εμφάνιση προϊόντων με δυνατότητα αναζήτησης
# ============================================================================

@login_required  # Απαιτεί authentication
def catalog_view(request):
    """
    Εμφανίζει τον κατάλογο προϊόντων με δυνατότητα αναζήτησης.
    
    Security measures:
    - Login required (προστασία private data)
    - Search query sanitization με bleach (XSS protection)
    - Protection από SQL injection μέσω Django ORM
    
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
    
    # XSS Protection: Καθαρισμός του query με bleach
    # Χρησιμότητα: Αφαιρεί malicious HTML/JavaScript
    # Security: Αποτρέπει stored/reflected XSS attacks
    clean_query = bleach.clean(search_query)
    
    # Αναζήτηση προϊόντων
    if clean_query:
        # Complex query με Q objects
        # Χρησιμότητα: Αναζήτηση σε name ΚΑΙ description ταυτόχρονα
        # Performance: Βελτιστοποιεί το SQL query σε OR conditions
        products = Product.objects.filter(
            Q(name__icontains=clean_query) |      # Case-insensitive search στο name
            Q(description__icontains=clean_query)  # ή στο description
        )
        is_search_results = True
    else:
        # Εμφάνιση όλων των προϊόντων αν δεν υπάρχει query
        products = Product.objects.all()
        is_search_results = False
    
    # Λήψη ή δημιουργία καλαθιού για τον χρήστη
    # Χρησιμότητα: Εξασφαλίζει ότι κάθε χρήστης έχει καλάθι
    # Django pattern: get_or_create για atomic operations
    cart, created = Cart.objects.get_or_create(user=request.user)
    
    # Υπολογισμός στοιχείων καλαθιού
    cart_items_count = cart.get_total_items()
    cart_items = cart.cartitem_set.all()
    
    # Context για το template
    context = {
        'products': products,
        'search_query': clean_query,
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
        cart, created = Cart.objects.get_or_create(user=request.user)
        
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
        return JsonResponse({'error': 'Invalid JSON'}, status=400, encoder=UUIDEncoder)
    except Exception as e:
        # Generic error handling με logging
        # Χρησιμότητα: Security monitoring, debugging
        # DevOps: Επιτρέπει proactive monitoring για errors
        logger.error(f"Error adding to cart: {str(e)}")
        return JsonResponse({'error': 'Server error'}, status=500, encoder=UUIDEncoder)


# ============================================================================
# PAYMENT VIEW
# Χρησιμότητα: Διαχείριση checkout process
# ============================================================================

@login_required
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
    
    # Λήψη καλαθιού και προϊόντων
    cart, created = Cart.objects.get_or_create(user=request.user)
    # select_related για optimization - μειώνει database queries
    # Performance: Αποφυγή N+1 query problem
    cart_items = cart.cartitem_set.all().select_related('product')
    
    # Υπολογισμοί για το καλάθι
    total_price = cart.get_total_price()
    cart_items_count = cart.get_total_items()
    
    # Έλεγχος αν το καλάθι είναι άδειο
    # Χρησιμότητα: Αποτρέπει checkout με άδειο καλάθι
    # UX: Early validation για καλύτερη εμπειρία χρήστη
    if not cart_items.exists():
        messages.warning(request, "Το καλάθι σας είναι άδειο. Προσθέστε προϊόντα πριν προχωρήσετε στην πληρωμή.")
        return redirect('catalog')
    
    # POST request handling
    if request.method == 'POST':
        # Step 2: Επιβεβαίωση παραγγελίας
        if 'confirm_order' in request.POST:
            # Ανάκτηση address ID από session
            # Χρησιμότητα: Ασφαλής μεταφορά data μεταξύ requests
            # Security: Stateful process για έλεγχο ότι το address επιλέχθηκε νωρίτερα
            address_id = request.session.get('shipping_address_id')
            
            if not address_id:
                messages.error(request, "Η διεύθυνση αποστολής δεν βρέθηκε.")
                return redirect('payment')
            
            # Ασφαλής ανάκτηση address - έλεγχος ownership
            # Security: Αποτρέπει access σε addresses άλλων χρηστών
            # Technical note: The address_id is stored as a string in the session
            shipping_address = get_object_or_404(ShippingAddress, id=address_id, user=request.user)
            
            try:
                # Δημιουργία νέας παραγγελίας
                # Transaction: Ιδανικά θα έπρεπε να χρησιμοποιηθεί transaction.atomic() για atomicity
                order = Order.objects.create(
                    user=request.user,
                    shipping_address=shipping_address,
                    total_price=total_price,
                    status='pending'
                )
                
                # Μεταφορά items από cart σε order
                # Χρησιμότητα: Διατήρηση ιστορικού τιμών
                # Business logic: Αποτροπή αλλαγών τιμών μετά την παραγγελία
                for item in cart_items:
                    OrderItem.objects.create(
                        order=order,
                        product=item.product,
                        quantity=item.quantity,
                        price=item.product.price  # Αποθήκευση τρέχουσας τιμής
                    )
                
                # Email στον πελάτη
                # Priority: Address email > User email
                # Flexibility: Επιτρέπει διαφορετικό email για κάθε παραγγελία
                user_email = shipping_address.email or request.user.email
                if user_email:
                    success = send_order_confirmation(order, user_email)
                    if not success:
                        logger.error(f"Failed to send order confirmation email to customer ({user_email})")
                else:
                    logger.warning("No user email found for order confirmation")
                
                # Email στον admin
                # Notification: Ενημερώνει τους διαχειριστές για νέες παραγγελίες
                admin_notification_success = send_order_notification_to_admin(order)
                if not admin_notification_success:
                    logger.error("Failed to send order notification email to admin")
                
                # Καθαρισμός μετά την παραγγελία
                # 1. Άδειασμα καλαθιού
                # UX: Αποτρέπει διπλές παραγγελίες από το ίδιο καλάθι
                cart_items.delete()
                
                # 2. Καθαρισμός session data
                # Security: Αποτρέπει επαναχρησιμοποίηση του address_id
                if 'shipping_address_id' in request.session:
                    del request.session['shipping_address_id']
                
                # Success message και redirect
                messages.success(request, f"Η παραγγελία σας καταχωρήθηκε επιτυχώς με κωδικό #{order.id}! Θα λάβετε σύντομα email με όλες τις λεπτομέρειες.")
                return redirect('catalog')
                
            except Exception as e:
                # Error handling με logging
                # DevOps: Καταγραφή σφαλμάτων για troubleshooting
                logger.error(f"Σφάλμα κατά τη δημιουργία παραγγελίας: {str(e)}")
                messages.error(request, "Προέκυψε σφάλμα κατά την καταχώρηση της παραγγελίας. Παρακαλώ προσπαθήστε ξανά.")
                return redirect('payment')
        
        # Step 1: Υποβολή shipping address
        form = ShippingAddressForm(request.POST)
        
        if form.is_valid():
            # Αποθήκευση address με user association
            address = form.save(commit=False)  # Δεν αποθηκεύει ακόμα
            address.user = request.user        # Σύνδεση με χρήστη
            address.save()                     # Τώρα αποθήκευση
            
            # Αποθήκευση στο session για το επόμενο βήμα
            # Convert UUID to string to make it JSON serializable
            # Technical: UUIDs δεν είναι JSON serializable by default
            request.session['shipping_address_id'] = str(address.id)
            
            # Success message
            messages.success(request, "Η διεύθυνση αποστολής καταχωρήθηκε επιτυχώς. Παρακαλώ επιβεβαιώστε την παραγγελία σας.")
            
            # Προετοιμασία για confirmation page
            context = {
                'cart_items': cart_items,
                'cart_items_count': cart_items_count,
                'total_price': total_price,
                'shipping_address': address,
                'is_confirmation': True  # Flag για το template
            }
            return render(request, 'eshop/payment.html', context)
        else:
            # Store form with errors for context processor
            request.form_errors = form
            
            # Warning message about validation errors
            messages.warning(request, "Παρακαλώ διορθώστε τα σφάλματα στη φόρμα και δοκιμάστε ξανά.")
            
            # Form errors - επανεμφάνιση με errors
            context = {
                'form': form, 
                'cart_items': cart_items,
                'cart_items_count': cart_items_count,
                'total_price': total_price,
                'is_confirmation': False
            }
            return render(request, 'eshop/payment.html', context)
    else:
        # GET request - Εμφάνιση address form
        try:
            # Pre-fill με την τελευταία διεύθυνση του χρήστη
            # Χρησιμότητα: Βελτίωση user experience
            # UX: Μειώνει data entry για επαναλαμβανόμενους χρήστες
            last_address = ShippingAddress.objects.filter(user=request.user).order_by('-id').first()
            form = ShippingAddressForm(instance=last_address)
        except:
            # Empty form αν δεν υπάρχει προηγούμενη διεύθυνση
            form = ShippingAddressForm()
    
    # Context για initial form display
    context = {
        'form': form,
        'cart_items': cart_items,
        'cart_items_count': cart_items_count,
        'total_price': total_price,
        'is_confirmation': False
    }
    
    return render(request, 'eshop/payment.html', context)


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
        return JsonResponse({'error': 'Invalid JSON'}, status=400, encoder=UUIDEncoder)
    except Exception as e:
        logger.error(f"Error removing from cart: {str(e)}")
        return JsonResponse({'error': 'Server error'}, status=500, encoder=UUIDEncoder)
    

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
        return JsonResponse({'error': 'Invalid JSON'}, status=400, encoder=UUIDEncoder)
    except Exception as e:
        logger.error(f"Error updating cart item: {str(e)}")
        return JsonResponse({'error': 'Server error'}, status=500, encoder=UUIDEncoder)

