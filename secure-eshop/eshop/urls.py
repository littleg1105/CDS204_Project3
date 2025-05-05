from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('', views.catalog_view, name='catalog'),
    path('add-to-cart/', views.add_to_cart, name='add_to_cart'),
    path('remove-from-cart/', views.remove_from_cart, name='remove_from_cart'),  # Νέο URL
    path('payment/', views.payment_view, name='payment'),  # Ενημερωμένο με το σωστό view
    path('update-cart-item/', views.update_cart_item, name='update_cart_item'),
]