"""
Combined tests for the eshop application.

This module runs simplified versions of crucial tests from all test categories.
"""

# Django imports
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.cache import cache

# Model imports
from .models import Product, Cart, CartItem, ShippingAddress, Order

# Additional imports
from decimal import Decimal
import json
from unittest.mock import patch, Mock


@override_settings(
    AXES_ENABLED=False,
    SESSION_COOKIE_SECURE=False,
    CSRF_COOKIE_SECURE=False,
    SECURE_SSL_REDIRECT=False
)
class AllInOneTest(TestCase):
    """Combined test class with essential tests from all categories."""
    
    def setUp(self):
        """Set up test data."""
        # Clear cache
        cache.clear()
        
        # Create a test user
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@example.com'
        )
        
        # Create test product
        self.product = Product.objects.create(
            name="Test Product",
            description="Test Description",
            price=Decimal("10.00")
        )
        
        # Create a client
        self.client = Client()
        
        # Mock CAPTCHA validation
        self.captcha_patcher = patch('captcha.fields.CaptchaField.clean', return_value="PASSED")
        self.mock_captcha = self.captcha_patcher.start()
    
    def tearDown(self):
        """Clean up after tests."""
        self.captcha_patcher.stop()
        cache.clear()
    
    def test_model_creation(self):
        """Test basic model creation."""
        # Test product
        self.assertEqual(self.product.name, "Test Product")
        self.assertEqual(self.product.price, Decimal("10.00"))
        
        # Test cart
        cart = Cart.objects.create(user=self.user)
        self.assertEqual(cart.user, self.user)
        self.assertEqual(cart.get_total_items(), 0)
        
        # Test cart item
        cart_item = CartItem.objects.create(
            cart=cart,
            product=self.product,
            quantity=2
        )
        self.assertEqual(cart_item.quantity, 2)
        self.assertEqual(cart.get_total_items(), 2)
        self.assertEqual(cart.get_total_price(), Decimal("20.00"))
    
    def test_login_page_loads(self):
        """Test login page loads correctly."""
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'eshop/login.html')
    
    def test_authenticated_views(self):
        """Test views that require authentication."""
        # Login
        self.client.login(username='testuser', password='testpass123')
        
        # Test catalog view
        response = self.client.get(reverse('catalog'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'eshop/catalog.html')
        self.assertContains(response, 'Test Product')
    
    def test_cart_operations(self):
        """Test cart operations."""
        # Login
        self.client.login(username='testuser', password='testpass123')
        
        # Get or create cart
        cart, _ = Cart.objects.get_or_create(user=self.user)
        
        # Add to cart
        response = self.client.post(
            reverse('add_to_cart'),
            json.dumps({'product_id': self.product.id}),
            content_type='application/json'
        )
        
        # Should be successful
        self.assertEqual(response.status_code, 200)
        
        # Cart should have one item
        self.assertEqual(cart.cartitem_set.count(), 1)
    
    def test_form_validation(self):
        """Test form validation for shipping address form directly."""
        # Import the form
        from .forms import ShippingAddressForm
        
        # Test invalid form
        invalid_form_data = {
            'name': 'Test User',
            'address': '123 Test St',
            'city': 'Test City',
            'zip_code': '123',  # Invalid (not 5 digits)
            'country': 'Greece',
            'phone': '12345',  # Invalid format
            'email': 'invalid-email'  # Invalid email
        }
        
        with patch('eshop.utils.verify_email_domain', return_value=False):
            form = ShippingAddressForm(data=invalid_form_data)
            self.assertFalse(form.is_valid())
            self.assertIn('zip_code', form.errors)
            self.assertIn('phone', form.errors)
            self.assertIn('email', form.errors)
        
        # Test valid form with mocked email verification
        valid_form_data = {
            'name': 'Test User',
            'address': '123 Test St',
            'city': 'Test City',
            'zip_code': '12345',  # Valid
            'country': 'Greece',
            'phone': '+30 2101234567',  # Valid
            'email': 'test@example.com'  # Valid with mocked verification
        }
        
        with patch('eshop.utils.verify_email_domain', return_value=True):
            form = ShippingAddressForm(data=valid_form_data)
            self.assertTrue(form.is_valid())
    
    def test_security_features(self):
        """Test basic security features."""
        # CSRF protection
        csrf_client = Client(enforce_csrf_checks=True)
        response = csrf_client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'testpass123',
            'captcha': 'PASSED'
        })
        
        # Should be forbidden without CSRF token
        self.assertEqual(response.status_code, 403)
        
        # XSS protection in search
        self.client.login(username='testuser', password='testpass123')
        
        # Try with XSS in search query
        with patch('bleach.clean', return_value=''):
            response = self.client.get(reverse('catalog'), {
                'q': '<script>alert("XSS")</script>'
            })
            
            # Page should load
            self.assertEqual(response.status_code, 200)
            # Script should not be in the response
            self.assertNotContains(response, '<script>alert')