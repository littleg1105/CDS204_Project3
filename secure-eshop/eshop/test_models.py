"""
Tests for models in the eshop application.

This module contains tests for all models in the eshop application,
ensuring they function correctly and maintain data integrity.
"""

# Django imports
from django.test import TestCase
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile

# Model imports
from .models import Product, Cart, CartItem, ShippingAddress, Order, OrderItem

# Additional imports
from decimal import Decimal
import uuid
import re

class ProductModelTests(TestCase):
    """Tests for the Product model."""
    
    def setUp(self):
        """Set up test data."""
        self.product = Product.objects.create(
            name="Test Product",
            description="Test Description",
            price=Decimal("29.99")
        )
    
    def test_product_creation(self):
        """Test product creation and basic attributes."""
        self.assertEqual(self.product.name, "Test Product")
        self.assertEqual(self.product.description, "Test Description")
        self.assertEqual(self.product.price, Decimal("29.99"))
        self.assertIsNotNone(self.product.created_at)
        self.assertIsNotNone(self.product.updated_at)
    
    def test_product_str_representation(self):
        """Test string representation of the product."""
        self.assertEqual(str(self.product), "Test Product")
    
    def test_product_price_validation(self):
        """Test that negative prices raise a validation error."""
        product = Product(
            name="Invalid Product",
            description="Test",
            price=Decimal("-10.00")
        )
        
        # This should raise a validation error when full_clean is called
        with self.assertRaises(ValidationError):
            product.full_clean()
    
    def test_product_image_upload(self):
        """Test image upload for a product."""
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
    """Tests for the Cart model."""
    
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
        """Test cart creation and association with user."""
        self.assertEqual(self.cart.user, self.user)
        self.assertEqual(self.cart.get_total_items(), 0)
        self.assertEqual(self.cart.get_total_price(), 0)
    
    def test_add_item_to_cart(self):
        """Test adding a product to the cart."""
        cart_item = CartItem.objects.create(
            cart=self.cart,
            product=self.product,
            quantity=2
        )
        
        self.assertEqual(self.cart.get_total_items(), 2)
        self.assertEqual(self.cart.get_total_price(), Decimal("20.00"))
        self.assertEqual(cart_item.get_total(), Decimal("20.00"))
    
    def test_cart_item_unique_constraint(self):
        """Test that products must be unique in a cart."""
        CartItem.objects.create(
            cart=self.cart,
            product=self.product,
            quantity=1
        )
        
        # Attempting to add the same product again should raise an IntegrityError
        with self.assertRaises(Exception):
            CartItem.objects.create(
                cart=self.cart,
                product=self.product,
                quantity=1
            )
    
    def test_update_cart_item_quantity(self):
        """Test updating the quantity of a cart item."""
        cart_item = CartItem.objects.create(
            cart=self.cart,
            product=self.product,
            quantity=1
        )
        
        # Update quantity
        cart_item.quantity = 3
        cart_item.save()
        
        # Refresh from database
        cart_item.refresh_from_db()
        self.assertEqual(cart_item.quantity, 3)
        self.assertEqual(self.cart.get_total_items(), 3)
        self.assertEqual(self.cart.get_total_price(), Decimal("30.00"))


class ShippingAddressModelTests(TestCase):
    """Tests for the ShippingAddress model."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
    
    def test_shipping_address_creation(self):
        """Test creation of a shipping address."""
        address = ShippingAddress.objects.create(
            user=self.user,
            name="Test User",
            address="123 Test St",
            city="Test City",
            zip_code="12345",
            country="Greece",
            phone="+30 2101234567",
            email="test@example.com"
        )
        
        self.assertEqual(address.user, self.user)
        self.assertEqual(address.name, "Test User")
        self.assertEqual(address.address, "123 Test St")
        self.assertEqual(address.city, "Test City")
        self.assertEqual(address.zip_code, "12345")
        self.assertEqual(address.country, "Greece")
        self.assertEqual(address.phone, "+30 2101234567")
        self.assertEqual(address.email, "test@example.com")
    
    def test_shipping_address_str_representation(self):
        """Test string representation of shipping address."""
        address = ShippingAddress.objects.create(
            user=self.user,
            name="Test User",
            address="123 Test St",
            city="Test City",
            zip_code="12345",
            country="Greece"
        )
        
        self.assertEqual(str(address), "Test User, 123 Test St, Test City")
    
    def test_zip_code_validation(self):
        """Test zip code validation."""
        # Invalid zip code (not 5 digits)
        address = ShippingAddress(
            user=self.user,
            name="Test User",
            address="123 Test St",
            city="Test City",
            zip_code="1234", # Invalid - not 5 digits
            country="Greece"
        )
        
        with self.assertRaises(ValidationError):
            address.full_clean()
    
    def test_phone_validation(self):
        """Test phone number validation for Greek format."""
        # Valid phone (mobile)
        address1 = ShippingAddress(
            user=self.user,
            name="Test User",
            address="123 Test St",
            city="Test City",
            zip_code="12345",
            country="Greece",
            phone="+30 6981234567",
            email="test@example.com"  # Add required email
        )
        address1.full_clean()  # Should not raise error
        
        # Valid phone (landline)
        address2 = ShippingAddress(
            user=self.user,
            name="Test User",
            address="123 Test St",
            city="Test City",
            zip_code="12345",
            country="Greece", 
            phone="2101234567",
            email="test@example.com"  # Add required email
        )
        address2.full_clean()  # Should not raise error
        
        # Invalid phone
        address3 = ShippingAddress(
            user=self.user,
            name="Test User",
            address="123 Test St",
            city="Test City",
            zip_code="12345",
            country="Greece",
            phone="12345",  # Invalid format
            email="test@example.com"  # Add required email
        )
        
        with self.assertRaises(ValidationError):
            address3.full_clean()


class OrderModelTests(TestCase):
    """Tests for the Order model."""
    
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
            country="Greece"
        )
        self.product = Product.objects.create(
            name="Test Product",
            description="Test",
            price=Decimal("10.00")
        )
    
    def test_order_creation(self):
        """Test order creation with basic attributes."""
        order = Order.objects.create(
            user=self.user,
            shipping_address=self.address,
            total_price=Decimal("10.00"),
            status='pending'
        )
        
        self.assertEqual(order.user, self.user)
        self.assertEqual(order.shipping_address, self.address)
        self.assertEqual(order.total_price, Decimal("10.00"))
        self.assertEqual(order.status, 'pending')
        
        # Check that ID is auto-generated with the correct format
        self.assertTrue(order.id.startswith('ORD-'))
        self.assertRegex(order.id, r'^ORD-[A-Z0-9]{5}-[A-Z0-9]{5}$')
    
    def test_order_str_representation(self):
        """Test string representation of order."""
        order = Order.objects.create(
            user=self.user,
            shipping_address=self.address,
            total_price=Decimal("10.00")
        )
        
        self.assertEqual(str(order), f"Παραγγελία {order.id} - testuser")
    
    def test_order_item_creation(self):
        """Test creation of order items and their association with orders."""
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
        self.assertEqual(order_item.quantity, 2)
        self.assertEqual(order_item.price, Decimal("10.00"))
    
    def test_order_with_multiple_items(self):
        """Test an order with multiple items."""
        order = Order.objects.create(
            user=self.user,
            shipping_address=self.address,
            total_price=Decimal("50.00")
        )
        
        product1 = self.product
        product2 = Product.objects.create(
            name="Second Product",
            description="Another test",
            price=Decimal("15.00")
        )
        
        OrderItem.objects.create(
            order=order,
            product=product1,
            quantity=2,
            price=product1.price
        )
        
        OrderItem.objects.create(
            order=order,
            product=product2,
            quantity=2,
            price=product2.price
        )
        
        self.assertEqual(order.items.count(), 2)
        
        # Calculate total price from items
        total = sum(item.get_total_price() for item in order.items.all())
        self.assertEqual(total, Decimal("50.00"))