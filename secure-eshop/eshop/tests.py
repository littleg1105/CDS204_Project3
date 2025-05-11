# eshop/tests.py

# ============================================================================
# IMPORTS
# ============================================================================

# Django testing framework
from django.test import TestCase, Client, TransactionTestCase
from django.urls import reverse
from django.contrib.auth.models import User
from django.core import mail
from django.conf import settings
from django.utils import timezone

# Models για testing
from .models import Product, Cart, CartItem, Order, OrderItem, ShippingAddress

# Forms για testing
from .forms import LoginForm, ShippingAddressForm

# Views για testing
from . import views

# Additional testing utilities
from decimal import Decimal
import json
from unittest.mock import patch, Mock
import tempfile
from django.core.files.uploadedfile import SimpleUploadedFile


# ============================================================================
# MODEL TESTS
# ============================================================================

class ProductModelTests(TestCase):
    """Tests για το Product model."""
    
    def setUp(self):
        """Set up test data."""
        self.product = Product.objects.create(
            name="Test Product",
            description="Test Description",
            price=Decimal("29.99")
        )
    
    def test_product_creation(self):
        """Test δημιουργίας προϊόντος."""
        self.assertEqual(self.product.name, "Test Product")
        self.assertEqual(self.product.price, Decimal("29.99"))
        self.assertIsNotNone(self.product.created_at)
    
    def test_product_str_representation(self):
        """Test string representation του προϊόντος."""
        self.assertEqual(str(self.product), "Test Product")
    
    def test_product_price_validation(self):
        """Test ότι δεν επιτρέπονται αρνητικές τιμές."""
        with self.assertRaises(Exception):
            Product.objects.create(
                name="Invalid Product",
                description="Test",
                price=Decimal("-10.00")
            )
    
    def test_product_image_upload(self):
        """Test upload εικόνας προϊόντος."""
        # Create a test image
        image = SimpleUploadedFile(
            name='test_image.jpg',
            content=b'fake image content',
            content_type='image/jpeg'
        )
        
        product = Product.objects.create(
            name="Product with Image",
            description="Test",
            price=Decimal("19.99"),
            image=image
        )
        
        self.assertTrue(product.image)
        self.assertIn('products/', product.image.name)


class CartModelTests(TestCase):
    """Tests για το Cart model."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.cart = Cart.objects.create(user=self.user)
        self.product = Product.objects.create(
            name="Test Product",
            description="Test",
            price=Decimal("10.00")
        )
    
    def test_cart_creation(self):
        """Test δημιουργίας καλαθιού."""
        self.assertEqual(self.cart.user, self.user)
        self.assertEqual(self.cart.get_total_items(), 0)
        self.assertEqual(self.cart.get_total_price(), 0)
    
    def test_add_item_to_cart(self):
        """Test προσθήκης προϊόντος στο καλάθι."""
        cart_item = CartItem.objects.create(
            cart=self.cart,
            product=self.product,
            quantity=2
        )
        
        self.assertEqual(self.cart.get_total_items(), 2)
        self.assertEqual(self.cart.get_total_price(), Decimal("20.00"))
    
    def test_cart_item_unique_constraint(self):
        """Test ότι το ίδιο προϊόν δεν μπορεί να υπάρχει δύο φορές."""
        CartItem.objects.create(
            cart=self.cart,
            product=self.product,
            quantity=1
        )
        
        with self.assertRaises(Exception):
            CartItem.objects.create(
                cart=self.cart,
                product=self.product,
                quantity=1
            )


class OrderModelTests(TestCase):
    """Tests για το Order model."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.address = ShippingAddress.objects.create(
            user=self.user,
            name="Test User",
            address="123 Test St",
            city="Test City",
            zip_code="12345",
            country="Test Country"
        )
        self.product = Product.objects.create(
            name="Test Product",
            description="Test",
            price=Decimal("10.00")
        )
    
    def test_order_creation(self):
        """Test δημιουργίας παραγγελίας."""
        order = Order.objects.create(
            user=self.user,
            shipping_address=self.address,
            total_price=Decimal("10.00"),
            status='pending'
        )
        
        self.assertEqual(order.user, self.user)
        self.assertEqual(order.status, 'pending')
        self.assertIsNotNone(order.id)
        self.assertTrue(order.id.startswith('ORD-'))
    
    def test_order_item_creation(self):
        """Test δημιουργίας order items."""
        order = Order.objects.create(
            user=self.user,
            shipping_address=self.address,
            total_price=Decimal("20.00")
        )
        
        order_item = OrderItem.objects.create(
            order=order,
            product=self.product,
            quantity=2,
            price=self.product.price
        )
        
        self.assertEqual(order_item.get_total_price(), Decimal("20.00"))
        self.assertEqual(order.items.count(), 1)


# ============================================================================
# FORM TESTS
# ============================================================================

class LoginFormTests(TestCase):
    """Tests για το LoginForm."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.client = Client()
    
    def test_valid_login_form(self):
        """Test έγκυρης φόρμας login."""
        form_data = {
            'username': 'testuser',
            'password': 'testpass123'
        }
        request = self.client.request()
        form = LoginForm(data=form_data, request=request)
        
        self.assertTrue(form.is_valid())
        self.assertEqual(form.user, self.user)
    
    def test_invalid_login_form(self):
        """Test άκυρης φόρμας login."""
        form_data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
        request = self.client.request()
        form = LoginForm(data=form_data, request=request)
        
        self.assertFalse(form.is_valid())
        self.assertIn('Τα στοιχεία σύνδεσης', form.errors['__all__'][0])
    
    def test_timing_attack_protection(self):
        """Test προστασίας από timing attacks."""
        import time
        
        form_data = {
            'username': 'nonexistent',
            'password': 'somepassword'
        }
        request = self.client.request()
        
        start_time = time.time()
        form = LoginForm(data=form_data, request=request)
        form.is_valid()
        end_time = time.time()
        
        # Έλεγχος ότι η απόκριση παίρνει τουλάχιστον 0.3 seconds
        self.assertGreaterEqual(end_time - start_time, 0.3)


class ShippingAddressFormTests(TestCase):
    """Tests για το ShippingAddressForm."""
    
    def test_valid_shipping_form(self):
        """Test έγκυρης φόρμας διεύθυνσης."""
        form_data = {
            'name': 'Test User',
            'address': '123 Test St',
            'city': 'Test City',
            'zip_code': '12345',
            'country': 'Greece',
            'phone': '1234567890',
            'email': 'test@example.com'
        }
        form = ShippingAddressForm(data=form_data)
        
        self.assertTrue(form.is_valid())
    
    def test_xss_protection(self):
        """Test προστασίας από XSS."""
        form_data = {
            'name': '<script>alert("XSS")</script>Test User',
            'address': '123 Test St',
            'city': 'Test City',
            'zip_code': '12345',
            'country': 'Greece'
        }
        form = ShippingAddressForm(data=form_data)
        
        self.assertTrue(form.is_valid())
        # Έλεγχος ότι το script tag αφαιρέθηκε
        self.assertEqual(form.cleaned_data['name'], 'Test User')


# ============================================================================
# VIEW TESTS
# ============================================================================

class ViewTests(TestCase):
    """Tests για τα views."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.product = Product.objects.create(
            name="Test Product",
            description="Test Description",
            price=Decimal("10.00")
        )
    
    def test_login_view_get(self):
        """Test GET request στο login view."""
        response = self.client.get(reverse('login'))
        
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'eshop/login.html')
        self.assertIsInstance(response.context['form'], LoginForm)
    
    def test_login_view_post_valid(self):
        """Test POST με έγκυρα credentials."""
        response = self.client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'testpass123'
        })
        
        self.assertRedirects(response, reverse('catalog'))
        self.assertTrue('_auth_user_id' in self.client.session)
    
    def test_catalog_view_requires_login(self):
        """Test ότι το catalog απαιτεί authentication."""
        response = self.client.get(reverse('catalog'))
        
        self.assertRedirects(response, f"{reverse('login')}?next={reverse('catalog')}")
    
    def test_catalog_view_authenticated(self):
        """Test catalog view για authenticated users."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('catalog'))
        
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'eshop/catalog.html')
        self.assertIn('products', response.context)
        self.assertIn('cart', response.context)
    
    def test_search_functionality(self):
        """Test λειτουργικότητας αναζήτησης."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('catalog'), {'q': 'Test'})
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['products']), 1)
    
    def test_add_to_cart_ajax(self):
        """Test AJAX προσθήκης στο καλάθι."""
        self.client.login(username='testuser', password='testpass123')
        
        response = self.client.post(
            reverse('add_to_cart'),
            json.dumps({'product_id': self.product.id}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['cart_items_count'], 1)
    
    def test_payment_view_empty_cart(self):
        """Test payment view με άδειο καλάθι."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('payment'))
        
        self.assertRedirects(response, reverse('catalog'))
        messages = list(response.wsgi_request._messages)
        self.assertTrue(any('καλάθι σας είναι άδειο' in str(m) for m in messages))


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class CheckoutIntegrationTest(TransactionTestCase):
    """Integration test για όλη τη διαδικασία checkout."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@example.com'
        )
        self.product = Product.objects.create(
            name="Test Product",
            description="Test",
            price=Decimal("10.00")
        )
    
    def test_complete_checkout_process(self):
        """Test ολόκληρης της διαδικασίας checkout."""
        # 1. Login
        self.client.login(username='testuser', password='testpass123')
        
        # 2. Add product to cart
        response = self.client.post(
            reverse('add_to_cart'),
            json.dumps({'product_id': self.product.id}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        
        # 3. Go to payment page
        response = self.client.get(reverse('payment'))
        self.assertEqual(response.status_code, 200)
        
        # 4. Submit shipping address
        response = self.client.post(reverse('payment'), {
            'name': 'Test User',
            'address': '123 Test St',
            'city': 'Test City',
            'zip_code': '12345',
            'country': 'Greece',
            'email': 'test@example.com'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('is_confirmation', response.context)
        
        # 5. Confirm order
        response = self.client.post(reverse('payment'), {
            'confirm_order': 'true'
        })
        self.assertRedirects(response, reverse('catalog'))
        
        # 6. Check order was created
        order = Order.objects.get(user=self.user)
        self.assertEqual(order.status, 'pending')
        self.assertEqual(order.total_price, Decimal("10.00"))
        
        # 7. Check email was sent
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('Επιβεβαίωση Παραγγελίας', mail.outbox[0].subject)


# ============================================================================
# SECURITY TESTS
# ============================================================================

class SecurityTests(TestCase):
    """Tests για security features."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
    
    def test_csrf_protection(self):
        """Test CSRF protection."""
        # Login without CSRF token should fail
        csrf_client = Client(enforce_csrf_checks=True)
        response = csrf_client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'testpass123'
        })
        
        self.assertEqual(response.status_code, 403)
    
    def test_ajax_requires_authentication(self):
        """Test ότι τα AJAX endpoints απαιτούν authentication."""
        response = self.client.post(
            reverse('add_to_cart'),
            json.dumps({'product_id': 1}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 302)  # Redirect to login
    
    def test_user_cannot_access_others_cart(self):
        """Test ότι οι χρήστες δεν μπορούν να προσπελάσουν άλλα καλάθια."""
        # Create another user and cart
        other_user = User.objects.create_user(
            username='otheruser',
            password='otherpass123'
        )
        other_cart = Cart.objects.create(user=other_user)
        other_cart_item = CartItem.objects.create(
            cart=other_cart,
            product=Product.objects.create(
                name="Other Product",
                description="Test",
                price=Decimal("5.00")
            ),
            quantity=1
        )
        
        # Login as first user
        self.client.login(username='testuser', password='testpass123')
        
        # Try to remove item from other user's cart
        response = self.client.post(
            reverse('remove_from_cart'),
            json.dumps({'cart_item_id': other_cart_item.id}),
            content_type='application/json'
        )
        
        data = json.loads(response.content)
        self.assertEqual(response.status_code, 404)
        self.assertIn('error', data)


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

class PerformanceTests(TestCase):
    """Tests για performance και optimization."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        # Create many products
        self.products = []
        for i in range(100):
            product = Product.objects.create(
                name=f"Product {i}",
                description=f"Description {i}",
                price=Decimal(f"{i}.99")
            )
            self.products.append(product)
    
    def test_catalog_query_optimization(self):
        """Test ότι το catalog view δεν κάνει πολλά queries."""
        self.client.login(username='testuser', password='testpass123')
        
        with self.assertNumQueries(5):  # Adjust based on actual queries
            response = self.client.get(reverse('catalog'))
            
        self.assertEqual(response.status_code, 200)
    
    def test_cart_calculation_performance(self):
        """Test performance υπολογισμών καλαθιού."""
        cart = Cart.objects.create(user=self.user)
        
        # Add many items to cart
        for product in self.products[:20]:
            CartItem.objects.create(
                cart=cart,
                product=product,
                quantity=2
            )
        
        # Test performance of total calculation
        import time
        start_time = time.time()
        total_price = cart.get_total_price()
        end_time = time.time()
        
        # Should be fast even with many items
        self.assertLess(end_time - start_time, 0.1)
        self.assertGreater(total_price, 0)


# ============================================================================
# EMAIL TESTS  
# ============================================================================

class EmailTests(TestCase):
    """Tests για email functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@example.com'
        )
        self.address = ShippingAddress.objects.create(
            user=self.user,
            name="Test User",
            address="123 Test St",
            city="Test City",
            zip_code="12345",
            country="Greece",
            email="shipping@example.com"
        )
    
    def test_order_confirmation_email(self):
        """Test αποστολής email επιβεβαίωσης."""
        order = Order.objects.create(
            user=self.user,
            shipping_address=self.address,
            total_price=Decimal("10.00")
        )
        
        # Import and call email function
        from .emails import send_order_confirmation
        result = send_order_confirmation(order, self.user.email)
        
        self.assertTrue(result)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('Επιβεβαίωση Παραγγελίας', mail.outbox[0].subject)
        self.assertEqual(mail.outbox[0].to, [self.user.email])
    
    def test_admin_notification_email(self):
        """Test αποστολής email στον admin."""
        order = Order.objects.create(
            user=self.user,
            shipping_address=self.address,
            total_price=Decimal("10.00")
        )
        
        # Import and call email function
        from .emails import send_order_notification_to_admin
        result = send_order_notification_to_admin(order)
        
        self.assertTrue(result)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('Νέα παραγγελία', mail.outbox[0].subject)
        self.assertEqual(mail.outbox[0].to, [settings.ADMIN_EMAIL])