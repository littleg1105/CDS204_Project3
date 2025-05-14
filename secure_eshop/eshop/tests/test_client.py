"""
Tests for client-side functionality in the eshop application.

This module contains tests for JavaScript functionality and DOM interactions,
using Django's test client to verify the expected client-side behavior.
"""

# Django imports
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile

# Model imports
from .models import Product, Cart, CartItem

# Form imports
from .forms import ShippingAddressForm

# Testing utilities
from decimal import Decimal
import json
from unittest.mock import patch


@override_settings(
    AXES_ENABLED=False,
    SESSION_COOKIE_SECURE=False,
    CSRF_COOKIE_SECURE=False,
    SECURE_SSL_REDIRECT=False
)
class ClientSideTests(TestCase):
    """Test client-side features using Django's test client."""
    
    def setUp(self):
        """Set up test data."""
        # Create a test user
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@example.com'
        )
        
        # Create test products
        self.product1 = Product.objects.create(
            name="Test Product 1",
            description="Test Description 1",
            price=Decimal("10.00")
        )
        
        self.product2 = Product.objects.create(
            name="Test Product 2",
            description="Test Description 2",
            price=Decimal("20.00")
        )
        
        # Create product without image to avoid image handling issues in tests
        self.product_with_image = Product.objects.create(
            name="Product with Image",
            description="Test with image",
            price=Decimal("15.00")
        )
        
        # Create a client for testing
        self.client = Client()
        
        # Login the user
        self.client.login(username='testuser', password='testpass123')
        
        # Get or create cart
        self.cart, _ = Cart.objects.get_or_create(user=self.user)
        
        # Mock captcha field validation to always pass
        self.captcha_patcher = patch('captcha.fields.CaptchaField.clean', return_value="PASSED")
        self.mock_captcha = self.captcha_patcher.start()
    
    def tearDown(self):
        """Clean up after tests."""
        self.captcha_patcher.stop()
    
    def test_cart_icon_updates(self):
        """Test that cart icon updates with items count."""
        # Add item to cart
        response = self.client.post(
            reverse('add_to_cart'),
            json.dumps({'product_id': self.product1.id}),
            content_type='application/json'
        )
        
        # Verify response contains updated cart count
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['cart_items_count'], 1)
        
        # Get catalog page which should display cart count
        response = self.client.get(reverse('catalog'))
        
        # Check that cart count is in the context
        self.assertEqual(response.context['cart_items_count'], 1)
        
        # Add another item
        response = self.client.post(
            reverse('add_to_cart'),
            json.dumps({'product_id': self.product2.id}),
            content_type='application/json'
        )
        
        # Verify response contains updated cart count
        data = json.loads(response.content)
        self.assertEqual(data['cart_items_count'], 2)
    
    def test_cart_item_removal(self):
        """Test removing items from cart via AJAX."""
        # Add items to cart first
        item1 = CartItem.objects.create(cart=self.cart, product=self.product1, quantity=1)
        item2 = CartItem.objects.create(cart=self.cart, product=self.product2, quantity=1)
        
        # Remove first item
        response = self.client.post(
            reverse('remove_from_cart'),
            json.dumps({'cart_item_id': item1.id}),
            content_type='application/json'
        )
        
        # Verify response
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['cart_items_count'], 1)
        
        # Check database
        self.assertFalse(CartItem.objects.filter(id=item1.id).exists())
        self.assertTrue(CartItem.objects.filter(id=item2.id).exists())
    
    def test_cart_quantity_update(self):
        """Test updating cart item quantity via AJAX."""
        # Add item to cart first
        item = CartItem.objects.create(cart=self.cart, product=self.product1, quantity=1)
        
        # Update quantity
        response = self.client.post(
            reverse('update_cart_item'),
            json.dumps({
                'cart_item_id': item.id,
                'quantity': 3
            }),
            content_type='application/json'
        )
        
        # Verify response
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['cart_items_count'], 3)
        
        # Item total should be updated
        self.assertEqual(data['item_total'], float(self.product1.price * 3))
        
        # Check database
        item.refresh_from_db()
        self.assertEqual(item.quantity, 3)
    
    def test_form_validation_errors(self):
        """Test client-side form validation errors."""
        # Add item to cart to avoid empty cart redirection
        CartItem.objects.create(cart=self.cart, product=self.product1, quantity=1)
        
        # Submit form with invalid data
        response = self.client.post(reverse('payment'), {
            'name': 'Test User',
            'address': '123 Test St',
            'city': 'Test City',
            'zip_code': 'ABC12',  # Invalid zip code (should be 5 digits)
            'country': 'Greece',
            'phone': '12345',     # Invalid phone format
            'email': 'invalid-email'  # Invalid email format
        })
        
        # Form should be invalid
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['form'].is_valid())
        
        # Check specific field errors
        self.assertIn('zip_code', response.context['form'].errors)
        self.assertIn('phone', response.context['form'].errors)
        self.assertIn('email', response.context['form'].errors)
        
        # Verification that form errors are stored in the request for the context processor
        self.assertTrue(hasattr(response.wsgi_request, 'form_errors'))
    
    def test_search_functionality(self):
        """Test search functionality."""
        # Search for product1
        response = self.client.get(reverse('catalog'), {'q': 'Test Product 1'})
        
        # Should find product1
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['products']), 1)
        self.assertEqual(response.context['products'][0], self.product1)
        
        # Search query should be in the context
        self.assertEqual(response.context['search_query'], 'Test Product 1')
        self.assertTrue(response.context['is_search_results'])
        
        # Search with no results
        response = self.client.get(reverse('catalog'), {'q': 'Nonexistent Product'})
        
        # Should find no products
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['products']), 0)
        self.assertTrue(response.context['is_search_results'])
    
    def test_checkout_flow(self):
        """Test the complete checkout flow."""
        # Add item to cart
        CartItem.objects.create(cart=self.cart, product=self.product1, quantity=2)
        
        # Step 1: Get payment page
        response = self.client.get(reverse('payment'))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['is_confirmation'])
        
        # Verify cart items are in the context
        self.assertEqual(len(response.context['cart_items']), 1)
        self.assertEqual(response.context['total_price'], Decimal('20.00'))
        
        # Step 2: Submit shipping address
        with patch('eshop.utils.verify_email_domain', return_value=True):
            response = self.client.post(reverse('payment'), {
                'name': 'Test User',
                'address': '123 Test St',
                'city': 'Test City',
                'zip_code': '12345',
                'country': 'Greece',
                'phone': '+30 2101234567',
                'email': 'test@example.com'
            })
            
            # Should show confirmation page
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.context['is_confirmation'])
            
            # Verify address ID is in session
            self.assertIn('shipping_address_id', self.client.session)
            
            # Step 3: Confirm order
            with patch('eshop.emails.send_order_confirmation', return_value=True), \
                 patch('eshop.emails.send_order_notification_to_admin', return_value=True):
                response = self.client.post(reverse('payment'), {
                    'confirm_order': 'true'
                })
                
                # Should redirect to catalog
                self.assertRedirects(response, reverse('catalog'))
                
                # Cart should be empty
                self.assertEqual(CartItem.objects.filter(cart=self.cart).count(), 0)
    
    def test_user_interface_elements(self):
        """Test UI elements are present in the response."""
        # Check catalog page
        response = self.client.get(reverse('catalog'))
        
        # Should contain product elements
        self.assertContains(response, 'Test Product 1')
        self.assertContains(response, 'Test Product 2')
        self.assertContains(response, 'Product with Image')
        
        # Should contain price elements
        self.assertContains(response, '10.00')
        self.assertContains(response, '20.00')
        
        # Should contain buttons/links
        self.assertContains(response, 'Προσθήκη στο Καλάθι')
        self.assertContains(response, 'Αποσύνδεση')
        
        # Check payment page
        CartItem.objects.create(cart=self.cart, product=self.product1, quantity=1)
        response = self.client.get(reverse('payment'))
        
        # Should contain form elements
        self.assertContains(response, 'Ονοματεπώνυμο')
        self.assertContains(response, 'Διεύθυνση')
        self.assertContains(response, 'name="city"')
        self.assertContains(response, 'name="zip_code"')
        
        # Should contain cart summary
        self.assertContains(response, 'Test Product 1')
        self.assertContains(response, '10.00')