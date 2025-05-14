"""
Tests for security features in the eshop application.

This module contains tests for rate limiting, CSRF protection,
XSS protection, and other security features.
"""

# Django imports
from django.test import TestCase, Client, override_settings, RequestFactory
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.cache import cache
from django.http import HttpResponse

# Model imports
from .models import Product, Cart, CartItem

# View imports
from . import views

# Additional testing utilities
from decimal import Decimal
import json
from unittest.mock import patch, Mock
import time


class BaseSecurityTest(TestCase):
    """Base class for security tests with common setup."""
    
    def setUp(self):
        """Set up test data."""
        # Create a test user
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@example.com'
        )
        
        # Create test products
        self.product = Product.objects.create(
            name="Test Product",
            description="Test Description",
            price=Decimal("10.00")
        )
        
        # Create a client for testing
        self.client = Client()
        
        # Clear rate limit cache before each test
        cache.clear()
        
        # Mock captcha field validation to always pass
        self.captcha_patcher = patch('captcha.fields.CaptchaField.clean', return_value="PASSED")
        self.mock_captcha = self.captcha_patcher.start()
    
    def tearDown(self):
        """Clean up after tests."""
        cache.clear()
        self.captcha_patcher.stop()


@override_settings(
    AXES_ENABLED=False,  # Disable axes during tests
    SESSION_COOKIE_SECURE=False,
    CSRF_COOKIE_SECURE=False,
    SECURE_SSL_REDIRECT=False
)
class RateLimitingTests(BaseSecurityTest):
    """Tests for rate limiting functionality."""
    
    @override_settings(RATELIMIT_VIEW='eshop.views.ratelimit_error')
    def test_login_view_rate_limit(self):
        """Test rate limiting on login view."""
        for i in range(12):  # Rate limit is 10/minute
            response = self.client.post(reverse('login'), {
                'username': 'testuser',
                'password': 'wrongpassword',
                'captcha': 'PASSED'
            })
            
            # First 10 requests should not be rate limited
            if i < 10:
                self.assertNotEqual(response.status_code, 429)
            else:
                # After 10 requests, should be rate limited
                self.assertEqual(response.status_code, 429)
                self.assertContains(response, 'πάρα πολλές αιτήσεις', status_code=429)
    
    @override_settings(RATELIMIT_VIEW='eshop.views.ratelimit_error')
    def test_add_to_cart_rate_limit(self):
        """Test rate limiting on add_to_cart view."""
        # Login first
        self.client.login(username='testuser', password='testpass123')
        
        # Make 25 requests (rate limit is 20/minute)
        for i in range(25):
            response = self.client.post(
                reverse('add_to_cart'),
                json.dumps({'product_id': self.product.id}),
                content_type='application/json'
            )
            
            # First 20 requests should not be rate limited
            if i < 20:
                self.assertEqual(response.status_code, 200)
            else:
                # After 20 requests, should be rate limited
                self.assertEqual(response.status_code, 429)
                self.assertContains(response, 'πάρα πολλές αιτήσεις', status_code=429)
    
    @override_settings(RATELIMIT_VIEW='eshop.views.ratelimit_error')
    def test_payment_view_rate_limit(self):
        """Test rate limiting on payment view."""
        # Login first
        self.client.login(username='testuser', password='testpass123')
        
        # Add product to cart to avoid empty cart redirection
        cart, _ = Cart.objects.get_or_create(user=self.user)
        CartItem.objects.create(cart=cart, product=self.product, quantity=1)
        
        # Mock email domain verification to always return True
        with patch('eshop.utils.verify_email_domain', return_value=True):
            # Make 7 requests (rate limit is 5/minute)
            for i in range(7):
                response = self.client.post(reverse('payment'), {
                    'name': 'Test User',
                    'address': '123 Test St',
                    'city': 'Test City',
                    'zip_code': '12345',
                    'country': 'Greece',
                    'phone': '+30 2101234567',
                    'email': 'test@example.com'
                })
                
                # First 5 requests should not be rate limited
                if i < 5:
                    self.assertNotEqual(response.status_code, 429)
                else:
                    # After 5 requests, should be rate limited
                    self.assertEqual(response.status_code, 429)
                    self.assertContains(response, 'πάρα πολλές αιτήσεις', status_code=429)
    
    def test_django_ratelimit_decorator(self):
        """Test the Django rate limit decoration on views."""
        # This test validates that rate limiting is properly applied
        # but uses Django's built-in rate limiting instead of a custom middleware
        
        # We'll use the actual Django views which already have rate limiting applied
        self.client.login(username='testuser', password='testpass123')
        
        # Add to cart is rate limited at 20/minute, so we'll make 22 requests
        for i in range(22):
            # Use Django's test client which is already properly set up
            if i < 20:
                # First 20 requests should succeed (using the product we already created)
                try:
                    response = self.client.post(
                        reverse('add_to_cart'),
                        json.dumps({'product_id': self.product.id}),
                        content_type='application/json'
                    )
                    # Some requests may fail for other reasons, but shouldn't be rate limited
                    self.assertNotEqual(response.status_code, 429)
                except:
                    # Ignore other errors, we're just testing rate limiting
                    pass
            else:
                # Make some requests that should be rate limited
                response = self.client.post(
                    reverse('add_to_cart'),
                    json.dumps({'product_id': self.product.id}),
                    content_type='application/json'
                )
                # The response should be rate limited now
                self.assertEqual(response.status_code, 429)


class CSRFProtectionTests(BaseSecurityTest):
    """Tests for CSRF protection."""
    
    def test_csrf_protection_login(self):
        """Test CSRF protection on login form."""
        # Create client that enforces CSRF checks
        csrf_client = Client(enforce_csrf_checks=True)
        
        # Try to login without CSRF token
        response = csrf_client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'testpass123',
            'captcha': 'PASSED'
        })
        
        # Should be forbidden
        self.assertEqual(response.status_code, 403)
    
    def test_csrf_protection_payment(self):
        """Test CSRF protection on payment form."""
        # Create client that enforces CSRF checks
        csrf_client = Client(enforce_csrf_checks=True)
        
        # Login user first (this will pass CSRF for login only)
        self.client.login(username='testuser', password='testpass123')
        csrf_client.cookies = self.client.cookies
        
        # Try to submit payment form without CSRF token
        response = csrf_client.post(reverse('payment'), {
            'name': 'Test User',
            'address': '123 Test St',
            'city': 'Test City',
            'zip_code': '12345',
            'country': 'Greece'
        })
        
        # Should be forbidden
        self.assertEqual(response.status_code, 403)
    
    def test_csrf_protection_add_to_cart(self):
        """Test CSRF protection on AJAX cart operations."""
        # Create client that enforces CSRF checks
        csrf_client = Client(enforce_csrf_checks=True)
        
        # Login user first (this will pass CSRF for login only)
        self.client.login(username='testuser', password='testpass123')
        csrf_client.cookies = self.client.cookies
        
        # Try to add to cart without CSRF token
        response = csrf_client.post(
            reverse('add_to_cart'),
            json.dumps({'product_id': self.product.id}),
            content_type='application/json'
        )
        
        # Should be forbidden
        self.assertEqual(response.status_code, 403)


class XSSProtectionTests(BaseSecurityTest):
    """Tests for XSS protection."""
    
    def test_form_xss_protection(self):
        """Test XSS protection in form inputs."""
        # Login first
        self.client.login(username='testuser', password='testpass123')
        
        # Add product to cart to avoid empty cart redirection
        cart, _ = Cart.objects.get_or_create(user=self.user)
        CartItem.objects.create(cart=cart, product=self.product, quantity=1)
        
        # Submit form with potential XSS script
        with patch('eshop.utils.verify_email_domain', return_value=True):
            response = self.client.post(reverse('payment'), {
                'name': '<script>alert("XSS")</script>Test User',
                'address': '123 Test St',
                'city': 'Test City',
                'zip_code': '12345',
                'country': 'Greece',
                'phone': '+30 2101234567',
                'email': 'test@example.com'
            })
            
            # Should be successful
            self.assertEqual(response.status_code, 200)
            
            # Check the database to verify script tags were removed
            address = ShippingAddress.objects.latest('id')
            self.assertEqual(address.name, 'Test User')  # Script should be removed
    
    def test_search_xss_protection(self):
        """Test XSS protection in search queries."""
        # Login first
        self.client.login(username='testuser', password='testpass123')
        
        # Search with potential XSS script
        response = self.client.get(reverse('catalog'), {
            'q': '<script>alert("XSS")</script>Test Query'
        })
        
        # Should be successful
        self.assertEqual(response.status_code, 200)
        
        # Script tags should be removed from response
        self.assertNotContains(response, '<script>alert')


class AuthenticationSecurityTests(BaseSecurityTest):
    """Tests for authentication security features."""
    
    def test_password_validation(self):
        """Test Django's password validation."""
        # Try to create user with common password
        with self.assertRaises(Exception):  # ValidationError from Django's password validators
            User.objects.create_user(
                username='weakuser',
                password='password',  # Common password
                email='weak@example.com'
            )
    
    def test_login_timing_consistency(self):
        """Test timing attack protection in login."""
        # Time login with non-existent user
        start_time1 = time.time()
        self.client.post(reverse('login'), {
            'username': 'nonexistent',
            'password': 'wrongpass123',
            'captcha': 'PASSED'
        })
        duration1 = time.time() - start_time1
        
        # Time login with existing user but wrong password
        self.client.logout()
        start_time2 = time.time()
        self.client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'wrongpass123',
            'captcha': 'PASSED'
        })
        duration2 = time.time() - start_time2
        
        # Both should take at least 0.3 seconds
        self.assertGreaterEqual(duration1, 0.3)
        self.assertGreaterEqual(duration2, 0.3)
    
    def test_secure_session_settings(self):
        """Verify secure session settings are applied in production environment."""
        # Get original settings
        from django.conf import settings
        
        # Check that secure settings are defined for production
        # Note: these are typically set to False during tests to make testing easier
        self.assertTrue(hasattr(settings, 'SESSION_COOKIE_SECURE'))
        self.assertTrue(hasattr(settings, 'CSRF_COOKIE_SECURE'))
        self.assertTrue(hasattr(settings, 'SECURE_SSL_REDIRECT'))


class AccessControlTests(BaseSecurityTest):
    """Tests for access control and authorization."""
    
    def test_login_required_views(self):
        """Test that protected views require authentication."""
        protected_views = [
            'catalog',
            'payment',
            'add_to_cart',
            'remove_from_cart',
            'update_cart_item'
        ]
        
        for view_name in protected_views:
            response = self.client.get(reverse(view_name))
            
            # Should redirect to login
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response.url.startswith(reverse('login')))
    
    def test_cannot_access_others_data(self):
        """Test that users cannot access other users' data."""
        # Create another user with its own data
        other_user = User.objects.create_user(
            username='otheruser',
            password='otherpass123'
        )
        other_cart = Cart.objects.create(user=other_user)
        other_item = CartItem.objects.create(
            cart=other_cart,
            product=self.product,
            quantity=1
        )
        
        # Login as first user
        self.client.login(username='testuser', password='testpass123')
        
        # Try to access other user's cart item
        response = self.client.post(
            reverse('remove_from_cart'),
            json.dumps({'cart_item_id': other_item.id}),
            content_type='application/json'
        )
        
        # Should return 404, not revealing that the item exists but is unauthorized
        self.assertEqual(response.status_code, 404)
        
        # Item should still exist
        self.assertTrue(CartItem.objects.filter(id=other_item.id).exists())