# ============================================================================
# PROJECT URL CONFIGURATION
# Κεντρικό αρχείο URL routing για το Django project
# ============================================================================

# ============================================================================
# IMPORTS - Εισαγωγή απαραίτητων modules
# ============================================================================

# Django admin module
from django.contrib import admin
# Χρησιμότητα:
# - Παρέχει το admin.site.urls για το Django admin interface
# - Δημιουργεί αυτόματα URLs για όλα τα registered models
# - Το built-in administration panel του Django

# URL configuration functions
from django.urls import path, include
# Χρησιμότητα:
# - path(): Ορίζει URL patterns με exact path matching
# - include(): Συμπεριλαμβάνει URL configurations από άλλα apps
# - Επιτρέπει modular URL organization

# Django settings
from django.conf import settings
# Χρησιμότητα:
# - Πρόσβαση στο settings.py configuration
# - Χρησιμοποιείται για DEBUG check και MEDIA_URL/MEDIA_ROOT
# - Central configuration access

# Static/Media files serving για development
from django.conf.urls.static import static
# Χρησιμότητα:
# - Helper function για serving media files σε development
# - Δημιουργεί URL patterns για static/media files
# - ΜΟΝΟ για development - production χρησιμοποιεί web server


# ============================================================================
# MAIN URL PATTERNS
# Κεντρικοί URL patterns του project
# ============================================================================

urlpatterns = [
    # Django Admin Interface
    path('admin/', admin.site.urls),
    # Χρησιμότητα:
    # - URL: /admin/
    # - Παρέχει πρόσβαση στο Django admin panel
    # - Automatic CRUD interface για όλα τα registered models
    # - Authentication required (staff users only)
    # - Customizable μέσω admin.py
    
    # CAPTCHA URLs
    path('captcha/', include('captcha.urls')),
    # Χρησιμότητα:
    # - URL: /captcha/
    # - Παρέχει τα URLs για να λειτουργήσει το CAPTCHA
    # - Περιλαμβάνει το endpoint για τις εικόνες CAPTCHA
    # - Απαραίτητο για την ασφαλή λειτουργία του CAPTCHA
    
    # E-shop Application URLs
    path('', include('eshop.urls')),  # Προσθέτουμε τα URLs της εφαρμογής
    # Χρησιμότητα:
    # - URL: / (root)
    # - Include όλα τα URLs από eshop/urls.py
    # - Delegation pattern - το app διαχειρίζεται τα δικά του URLs
    # - Clean separation of concerns
    # - Prefix: '' σημαίνει ότι τα eshop URLs ξεκινούν από το root
]


# ============================================================================
# MEDIA FILES CONFIGURATION (Development Only)
# Ρύθμιση για serving media files σε development environment
# ============================================================================

# Αν είμαστε σε debug mode, προσθέτουμε URLs για τα στατικά αρχεία
if settings.DEBUG:
    # Serve static files
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    # Χρησιμότητα:
    # - Conditional: Μόνο όταν DEBUG=True (development)
    # - Serves static files (CSS, JS, images)
    # - STATIC_URL: URL prefix για static files (π.χ. /static/)
    # - STATIC_ROOT: Filesystem path για collected static files
    # - Απαραίτητο για την εμφάνιση του CAPTCHA και άλλων στοιχείων
    
    # Serve media files
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    # Χρησιμότητα:
    # - Conditional: Μόνο όταν DEBUG=True (development)
    # - Serves uploaded files (product images, etc.)
    # - MEDIA_URL: URL prefix για media files (π.χ. /media/)
    # - MEDIA_ROOT: Filesystem path για media files
    # - Security: ΠΟΤΕ μην το κάνετε σε production!
    # - Production: Χρησιμοποιείτε nginx/apache για media serving