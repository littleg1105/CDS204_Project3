from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator
import uuid
import random
import string

# This function has been replaced by generate_order_id below.

class Product(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2, validators=[MinValueValidator(0)])
    image = models.ImageField(upload_to='products/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class Cart(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Cart for {self.user.username}"
    
    def get_total_items(self):
        return sum(item.quantity for item in self.cartitem_set.all())
    
    def get_total_price(self):
        return sum(item.quantity * item.product.price for item in self.cartitem_set.all())

class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1, validators=[MinValueValidator(1)])
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('cart', 'product')

    def __str__(self):
        return f"{self.quantity} x {self.product.name}"
        
    def get_total(self):
        return self.quantity * self.product.price

class ShippingAddress(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, verbose_name='Ονοματεπώνυμο')
    address = models.CharField(max_length=200, verbose_name='Διεύθυνση')
    city = models.CharField(max_length=100, verbose_name='Πόλη')
    zip_code = models.CharField(max_length=20, verbose_name='ΤΚ')
    country = models.CharField(max_length=100, verbose_name='Χώρα')
    phone = models.CharField(max_length=20, verbose_name='Τηλέφωνο', blank=True, null=True)
    email = models.EmailField(verbose_name='Email', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)  # Προσθήκη πεδίου
    
    def __str__(self):
        return f"{self.name}, {self.address}, {self.city}"
    
    class Meta:
        verbose_name = 'Διεύθυνση Αποστολής'
        verbose_name_plural = 'Διευθύνσεις Αποστολής'

def generate_order_id():
    """Generate a random order ID format: ORD-XXXXX-XXXXX"""
    prefix = 'ORD'
    part1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    part2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    return f"{prefix}-{part1}-{part2}"

class Order(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Εκκρεμεί'),
        ('processing', 'Σε επεξεργασία'),
        ('shipped', 'Απεστάλη'),
        ('delivered', 'Παραδόθηκε'),
        ('cancelled', 'Ακυρώθηκε'),
    )
    
    id = models.CharField(primary_key=True, max_length=20, default=generate_order_id, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='Χρήστης')
    shipping_address = models.ForeignKey(ShippingAddress, on_delete=models.PROTECT, verbose_name='Διεύθυνση Αποστολής', null=True, blank=True)    
    total_price = models.DecimalField(max_digits=10, decimal_places=2, verbose_name='Συνολικό Ποσό')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', verbose_name='Κατάσταση')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Ημερομηνία Δημιουργίας')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='Τελευταία Ενημέρωση')
    
    def __str__(self):
        return f"Παραγγελία {self.id} - {self.user.username}"
    
    class Meta:
        verbose_name = 'Παραγγελία'
        verbose_name_plural = 'Παραγγελίες'
        ordering = ['-created_at']


class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items', verbose_name='Παραγγελία')
    product = models.ForeignKey(Product, on_delete=models.PROTECT, verbose_name='Προϊόν')
    quantity = models.PositiveIntegerField(default=1, validators=[MinValueValidator(1)], verbose_name='Ποσότητα')
    price = models.DecimalField(max_digits=10, decimal_places=2, verbose_name='Τιμή')
    
    def __str__(self):
        return f"{self.quantity} x {self.product.name}"
    
    def get_total_price(self):
        return self.quantity * self.price
    
    class Meta:
        verbose_name = 'Αντικείμενο Παραγγελίας'
        verbose_name_plural = 'Αντικείμενα Παραγγελίας'