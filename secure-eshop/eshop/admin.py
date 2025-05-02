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