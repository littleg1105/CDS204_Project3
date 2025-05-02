from django.contrib import admin
from .models import Product, Cart, CartItem, ShippingAddress, Order, OrderItem

class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'price', 'created_at')
    search_fields = ('name', 'description')
    list_filter = ('created_at',)

admin.site.register(Product, ProductAdmin)
admin.site.register(Cart)
admin.site.register(CartItem)
admin.site.register(ShippingAddress)
admin.site.register(Order) 
admin.site.register(OrderItem)
# This code is registering the models defined in the `models.py` file with the Django admin interface.
# It allows the admin to manage these models through the Django admin panel.
# The `ProductAdmin` class customizes the admin interface for the `Product` model, allowing for search and filtering. 