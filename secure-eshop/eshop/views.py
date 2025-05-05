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
from .models import Product, Cart, CartItem, ShippingAddress, Order, OrderItem
import logging
from django.conf import settings
from .emails import send_order_confirmation, send_order_notification_to_admin
from .forms import ShippingAddressForm


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

@login_required
def payment_view(request):
    # Ανάκτηση του καλαθιού του χρήστη
    cart, created = Cart.objects.get_or_create(user=request.user)
    cart_items = cart.cartitem_set.all().select_related('product')
    
    # Υπολογισμός συνολικού ποσού
    total_price = cart.get_total_price()
    cart_items_count = cart.get_total_items()
    
    # Έλεγχος αν το καλάθι είναι άδειο
    if not cart_items.exists():
        messages.warning(request, "Το καλάθι σας είναι άδειο. Προσθέστε προϊόντα πριν προχωρήσετε στην πληρωμή.")
        return redirect('catalog')
    
    # Έλεγχος αν έχει υποβληθεί η φόρμα
    if request.method == 'POST':
        # Εκτύπωση δεδομένων POST για debugging
        print("POST data:", request.POST)
        
        # Έλεγχος αν είναι το βήμα επιβεβαίωσης παραγγελίας
        if 'confirm_order' in request.POST:
            print("Επιβεβαίωση παραγγελίας εντοπίστηκε")
            # Λήψη της διεύθυνσης από το session
            address_id = request.session.get('shipping_address_id')
            print("Address ID από session:", address_id)
            
            if not address_id:
                messages.error(request, "Η διεύθυνση αποστολής δεν βρέθηκε.")
                return redirect('payment')
            
            shipping_address = get_object_or_404(ShippingAddress, id=address_id, user=request.user)
            
            try:
                # Δημιουργία νέας παραγγελίας
                order = Order.objects.create(
                    user=request.user,
                    shipping_address=shipping_address,
                    total_price=total_price,
                    status='pending'
                )
                
                print("Παραγγελία δημιουργήθηκε με ID:", order.id)
                
                # Προσθήκη των αντικειμένων του καλαθιού στην παραγγελία
                for item in cart_items:
                    OrderItem.objects.create(
                        order=order,
                        product=item.product,
                        quantity=item.quantity,
                        price=item.product.price
                    )
                    print(f"Προστέθηκε στην παραγγελία: {item.quantity} x {item.product.name}")
                
                # Αποστολή email στον πελάτη
                user_email = shipping_address.email or request.user.email
                if user_email:
                    success = send_order_confirmation(order, user_email)
                    if success:
                        print(f"Email επιβεβαίωσης στάλθηκε επιτυχώς στον πελάτη ({user_email})")
                    else:
                        print(f"Σφάλμα αποστολής email επιβεβαίωσης στον πελάτη")
                else:
                    print("Δεν βρέθηκε email χρήστη για αποστολή επιβεβαίωσης")
                
                # Αποστολή ειδοποίησης στον διαχειριστή
                admin_notification_success = send_order_notification_to_admin(order)
                if admin_notification_success:
                    print("Email ειδοποίησης στάλθηκε επιτυχώς στον διαχειριστή")
                else:
                    print("Σφάλμα αποστολής email ειδοποίησης στον διαχειριστή")
                
                # Άδειασμα του καλαθιού
                cart_items.delete()
                print("Το καλάθι άδειασε")
                
                # Διαγραφή της διεύθυνσης από το session
                if 'shipping_address_id' in request.session:
                    del request.session['shipping_address_id']
                    print("Η διεύθυνση αφαιρέθηκε από το session")
                
                messages.success(request, f"Η παραγγελία σας καταχωρήθηκε επιτυχώς με κωδικό #{order.id}! Θα λάβετε σύντομα email με όλες τις λεπτομέρειες.")
                return redirect('catalog')
                
            except Exception as e:
                logger.error(f"Σφάλμα κατά τη δημιουργία παραγγελίας: {str(e)}")
                print(f"Σφάλμα κατά τη δημιουργία παραγγελίας: {str(e)}")
                messages.error(request, "Προέκυψε σφάλμα κατά την καταχώρηση της παραγγελίας. Παρακαλώ προσπαθήστε ξανά.")
                return redirect('payment')
            
        # Αλλιώς είναι το πρώτο βήμα (υποβολή διεύθυνσης)
        form = ShippingAddressForm(request.POST)
        print("Επικύρωση φόρμας διεύθυνσης, έγκυρη:", form.is_valid())
        if not form.is_valid():
            print("Σφάλματα φόρμας:", form.errors.as_json())
            
        if form.is_valid():
            # Σύνδεση της διεύθυνσης με τον χρήστη
            address = form.save(commit=False)
            address.user = request.user
            address.save()
            print(f"Διεύθυνση αποθηκεύτηκε με ID: {address.id}")
            
            # Αποθήκευση του ID της διεύθυνσης στο session
            request.session['shipping_address_id'] = address.id
            print(f"ID διεύθυνσης {address.id} αποθηκεύτηκε στο session")
            
            # Προετοιμασία δεδομένων για την οθόνη επιβεβαίωσης
            context = {
                'cart_items': cart_items,
                'cart_items_count': cart_items_count,
                'total_price': total_price,
                'shipping_address': address,
                'is_confirmation': True
            }
            return render(request, 'eshop/payment.html', context)
        else:
            context = {
                'form': form, 
                'cart_items': cart_items,
                'cart_items_count': cart_items_count,
                'total_price': total_price,
                'is_confirmation': False
            }
            return render(request, 'eshop/payment.html', context)
    else:
        # Εμφάνιση της φόρμας διεύθυνσης
        # Προσπάθεια να βρεθεί μια προηγούμενη διεύθυνση του χρήστη
        try:
            last_address = ShippingAddress.objects.filter(user=request.user).order_by('-id').first()
            form = ShippingAddressForm(instance=last_address)
        except:
            form = ShippingAddressForm()
    
    context = {
        'form': form,
        'cart_items': cart_items,
        'cart_items_count': cart_items_count,
        'total_price': total_price,
        'is_confirmation': False
    }
    
    return render(request, 'eshop/payment.html', context)


@login_required
@require_http_methods(["POST"])
def remove_from_cart(request):
    try:
        # Ανάλυση του JSON request
        data = json.loads(request.body)
        cart_item_id = data.get('cart_item_id')
        
        # Έλεγχος εγκυρότητας του cart_item_id
        if not cart_item_id:
            return JsonResponse({'error': 'Missing cart_item_id'}, status=400)
        
        # Ανάκτηση του cart_item και έλεγχος ότι ανήκει στον τρέχοντα χρήστη
        try:
            cart = Cart.objects.get(user=request.user)
            cart_item = CartItem.objects.get(id=cart_item_id, cart=cart)
        except (Cart.DoesNotExist, CartItem.DoesNotExist):
            return JsonResponse({'error': 'Item not found'}, status=404)
        
        # Διαγραφή του αντικειμένου
        cart_item.delete()
        
        # Επιστροφή απάντησης
        return JsonResponse({
            'status': 'success',
            'message': 'Item removed from cart',
            'cart_items_count': cart.get_total_items()
        })
    
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error removing from cart: {str(e)}")
        return JsonResponse({'error': 'Server error'}, status=500)
    
@login_required
@require_http_methods(["POST"])
def update_cart_item(request):
    try:
        # Ανάλυση του JSON request
        data = json.loads(request.body)
        cart_item_id = data.get('cart_item_id')
        new_quantity = data.get('quantity')
        
        # Έλεγχοι εγκυρότητας
        if not cart_item_id or new_quantity is None:
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        try:
            new_quantity = int(new_quantity)
            if new_quantity <= 0:
                return JsonResponse({'error': 'Quantity must be positive'}, status=400)
        except ValueError:
            return JsonResponse({'error': 'Invalid quantity'}, status=400)
        
        # Ανάκτηση του cart_item και έλεγχος ότι ανήκει στον τρέχοντα χρήστη
        try:
            cart = Cart.objects.get(user=request.user)
            cart_item = CartItem.objects.get(id=cart_item_id, cart=cart)
        except (Cart.DoesNotExist, CartItem.DoesNotExist):
            return JsonResponse({'error': 'Item not found'}, status=404)
        
        # Ενημέρωση της ποσότητας
        cart_item.quantity = new_quantity
        cart_item.save()
        
        # Υπολογισμός του νέου συνόλου
        item_total = cart_item.product.price * new_quantity
        cart_total = cart.get_total_price()
        
        # Επιστροφή απάντησης
        return JsonResponse({
            'status': 'success',
            'message': 'Quantity updated',
            'item_total': float(item_total),
            'cart_total': float(cart_total),
            'cart_items_count': cart.get_total_items()
        })
    
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error updating cart item: {str(e)}")
        return JsonResponse({'error': 'Server error'}, status=500)

# Θα προσθέσουμε και άλλα views αργότερα