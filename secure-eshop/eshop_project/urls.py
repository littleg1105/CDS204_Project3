from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('eshop.urls')),  # Προσθέτουμε τα URLs της εφαρμογής
]

# Αν είμαστε σε debug mode, προσθέτουμε URLs για τα στατικά αρχεία
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)