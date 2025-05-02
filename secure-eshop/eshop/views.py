from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.views.decorators.http import require_http_methods
from django.views.decorators.debug import sensitive_post_parameters
from django.contrib.auth.signals import user_login_failed
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib import messages
from django.db.models import Q
import json
import bleach
from .forms import LoginForm
from .models import Product, Cart, CartItem
import logging

# Ρύθμιση logging για καταγραφή αποτυχημένων προσπαθειών σύνδεσης
logger = logging.getLogger('security')

def login_failed_callback(sender, credentials, **kwargs):
    logger.warning(f"Failed login attempt with username: {credentials.get('username')}")

user_login_failed.connect(login_failed_callback)

@require_http_methods(["GET", "POST"])
@sensitive_post_parameters('password')
def login_view(request):
    # Το υπάρχον login_view παραμένει ως έχει
    # ... (ο υπόλοιπος κώδικας του login_view)
    if request.user.is_authenticated:
        return redirect('catalog')
    
    if request.method == 'POST':
        form = LoginForm(request.POST, request=request)
        if form.is_valid():
            user = form.user
            login(request, user)
            request.session.cycle_key()
            return redirect(request.GET.get('next', 'catalog'))
    else:
        form = LoginForm()
    
    return render(request, 'eshop/login.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
def catalog_view(request):
    # Λήψη του query για αναζήτηση
    search_query = request.GET.get('q', '')
    
    # Καθαρισμός του query με το bleach για προστασία από XSS
    clean_query = bleach.clean(search_query)
    
    # Αναζήτηση προϊόντων
    if clean_query:
        # Χρήση του Q object για πιο σύνθετα queries
        products = Product.objects.filter(
            Q(name__icontains=clean_query) | 
            Q(description__icontains=clean_query)
        )
        is_search_results = True
    else:
        # Αν δεν υπάρχει query, εμφάνισε όλα τα προϊόντα
        products = Product.objects.all()
        is_search_results = False
    
    # Παίρνουμε το καλάθι του χρήστη ή δημιουργούμε ένα νέο αν δεν υπάρχει
    cart, created = Cart.objects.get_or_create(user=request.user)
    
    # Μετράμε τα αντικείμενα στο καλάθι
    cart_items_count = cart.get_total_items()
    cart_items = cart.cartitem_set.all()
    
    context = {
        'products': products,
        'search_query': clean_query,
        'is_search_results': is_search_results,
        'cart_items_count': cart_items_count,
        'cart_items': cart_items
    }
    
    return render(request, 'eshop/catalog.html', context)

@login_required
@require_http_methods(["POST"])
def add_to_cart(request):
    try:
        # Ανάλυση του JSON request
        data = json.loads(request.body)
        product_id = data.get('product_id')
        
        # Έλεγχος εγκυρότητας του product_id
        if not product_id:
            return JsonResponse({'error': 'Missing product_id'}, status=400)
        
        # Ανάκτηση του προϊόντος
        product = get_object_or_404(Product, id=product_id)
        
        # Ανάκτηση ή δημιουργία του καλαθιού του χρήστη
        cart, created = Cart.objects.get_or_create(user=request.user)
        
        # Ανάκτηση ή δημιουργία του CartItem
        cart_item, created = CartItem.objects.get_or_create(
            cart=cart,
            product=product,
            defaults={'quantity': 1}
        )
        
        # Αν το αντικείμενο υπάρχει ήδη, αύξηση της ποσότητας
        if not created:
            cart_item.quantity += 1
            cart_item.save()
        
        # Επιστροφή απάντησης
        return JsonResponse({
            'status': 'success',
            'message': f'{product.name} added to cart',
            'cart_items_count': cart.get_total_items()
        })
    
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error adding to cart: {str(e)}")
        return JsonResponse({'error': 'Server error'}, status=500)

# Θα προσθέσουμε και άλλα views αργότερα