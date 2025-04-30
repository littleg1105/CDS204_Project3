from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    # Θα προσθέσουμε περισσότερα URLs αργότερα
    path('', views.catalog_view, name='catalog'),  # Προσωρινά για να δουλεύουν τα links
    path('payment/', views.login_view, name='payment'),  # Προσωρινά για να δουλεύουν τα links
]