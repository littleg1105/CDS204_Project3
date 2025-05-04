from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('', views.catalog_view, name='catalog'),
    path('add-to-cart/', views.add_to_cart, name='add_to_cart'),
    path('payment/', views.payment_view, name='payment'),  # Ενημερωμένο με το σωστό view
]