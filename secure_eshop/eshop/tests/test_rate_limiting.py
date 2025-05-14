"""
Tests for rate limiting functionality in the e-shop application.

This file contains tests for django-ratelimit implementation,
verifying that rate limits are correctly applied to different views
and that the custom rate limit error view works as expected.
"""

# ============================================================================
# IMPORTS
# ============================================================================

# Django testing framework
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.cache import cache

# Models for testing
from .models import Product, Cart

# For patching and mocking
from unittest.mock import patch, Mock
import json
from decimal import Decimal

# Rate limiting imports
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited

# ============================================================================
# TEST CLASS FOR RATE LIMITING
# ============================================================================

@override_settings(
    # Disable axes for these tests to avoid interference with django-ratelimit
    AXES_ENABLED=False
)
class RateLimitingTests(TestCase):
    """Tests for rate limiting functionality across the application."""
    
    def setUp(self):
        """Set up test data and clear cache before each test."""
        # Clear the cache to ensure clean rate limiting state
        cache.clear()
        
        # Create a test user
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@example.com'
        )
        
        # Create a test product
        self.product = Product.objects.create(
            name="Test Product",
            description="Test Description",
            price=Decimal("10.00")
        )
        
        # Set up client
        self.client = Client()
    
    def tearDown(self):
        """Clean up after each test."""
        # Clear the cache to avoid affecting other tests
        cache.clear()
    
    # ============================================================================
    # LOGIN VIEW RATE LIMITING TESTS
    # ============================================================================

    def test_login_view_rate_limit(self):
        """Test that login view enforces rate limits."""
        # Make multiple login attempts with incorrect credentials to trigger rate limit
        for i in range(12):  # Rate limit is 10/minute
            response = self.client.post(reverse('login'), {
                'username': 'testuser',
                'password': 'wrongpassword'
            })
            
            # For the first 10 requests, we should get normal responses
            if i < 10:
                self.assertNotEqual(response.status_code, 429)
            else:
                # After hitting the limit, we should get a 429 response
                self.assertEqual(response.status_code, 429)
                self.assertIn('Έχετε υποβάλει πάρα πολλές αιτήσεις', response.content.decode())
    
    def test_login_successful_not_counted_towards_limit(self):
        """Test that successful logins don't count towards the limit."""
        # Create a separate test for verifying logins don't affect rate limiting
        # Successful login will probably redirect, but what matters is the counter
        self.client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'testpass123'
        })
        
        # Then log out
        self.client.logout()
        
        # Now make 10 failed attempts (should be counted from 0)
        for i in range(10):
            response = self.client.post(reverse('login'), {
                'username': 'testuser',
                'password': 'wrongpassword'
            })
            # We should not be rate limited yet
            self.assertNotEqual(response.status_code, 429)
        
        # The 11th attempt should be rate limited
        response = self.client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 429)
    
    def test_get_requests_not_rate_limited(self):
        """Test that GET requests to login page are not rate limited."""
        # Make multiple GET requests to login page
        for _ in range(20):  # Way more than our limit
            response = self.client.get(reverse('login'))
            self.assertEqual(response.status_code, 200)
            self.assertTemplateUsed(response, 'eshop/login.html')
    
    # ============================================================================
    # ADD TO CART RATE LIMITING TESTS
    # ============================================================================
    
    def test_add_to_cart_rate_limit(self):
        """Test that add_to_cart view enforces rate limits."""
        # Login first (required for add_to_cart)
        self.client.login(username='testuser', password='testpass123')
        
        # Make multiple requests to add_to_cart
        for i in range(22):  # Rate limit is 20/minute for this view
            response = self.client.post(
                reverse('add_to_cart'),
                json.dumps({'product_id': self.product.id}),
                content_type='application/json'
            )
            
            # For the first 20 requests, we should get normal responses
            if i < 20:
                self.assertEqual(response.status_code, 200)
                data = json.loads(response.content)
                self.assertEqual(data['status'], 'success')
            else:
                # After hitting the limit, we should get a 429 response
                self.assertEqual(response.status_code, 429)
                self.assertIn('Έχετε υποβάλει πάρα πολλές αιτήσεις', response.content.decode())
    
    # ============================================================================
    # PAYMENT VIEW RATE LIMITING TESTS
    # ============================================================================
    
    def test_payment_view_rate_limit(self):
        """Test that payment_view enforces rate limits."""
        # Login first (required for payment_view)
        self.client.login(username='testuser', password='testpass123')
        
        # First, add an item to the cart to avoid empty cart redirection
        self.client.post(
            reverse('add_to_cart'),
            json.dumps({'product_id': self.product.id}),
            content_type='application/json'
        )
        
        # Create dummy form data for shipping address
        form_data = {
            'name': 'Test User',
            'address': '123 Test St',
            'city': 'Test City',
            'zip_code': '12345',
            'country': 'Greece',
            'phone': '1234567890',  # Required field
            'email': 'test@example.com'  # Required field
        }
        
        # Make multiple POST requests to payment_view
        for i in range(7):  # Rate limit is 5/minute for this view
            response = self.client.post(reverse('payment'), form_data)
            
            # For the first 5 requests, we should get normal responses
            if i < 5:
                self.assertNotEqual(response.status_code, 429)
            else:
                # After hitting the limit, we should get a 429 response
                self.assertEqual(response.status_code, 429)
                self.assertIn('Έχετε υποβάλει πάρα πολλές αιτήσεις', response.content.decode())