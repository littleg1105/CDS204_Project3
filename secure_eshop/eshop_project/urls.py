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

# =============================================================================
# ΑΣΦΑΛΕΙΑ ΣΤΟ URL ROUTING
# =============================================================================
# Το σύστημα URL routing του Django είναι σχεδιασμένο με ασφάλεια:
# 1. Αποφεύγει Path Traversal επιθέσεις - δεν επιτρέπει πρόσβαση σε αρχεία
#    έξω από τους καθορισμένους φακέλους με ειδικές ακολουθίες (..)
# 2. Προστατεύει από URL Manipulation - τα patterns ορίζονται ρητά με regex
# 3. Το include() διαχωρίζει το namespace προστατεύοντας από conflicts
# 4. Το admin interface προστατεύεται αυτόματα με authentication

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
    path('', include('eshop.urls')), # Προσθέτουμε τα URLs της εφαρμογής
    # Χρησιμότητα:
    # - URL: / (root)
    # - Include όλα τα URLs από eshop/urls.py
    # - Delegation pattern - το app διαχειρίζεται τα δικά του URLs
    # - Clean separation of concerns
    # - Prefix: '' σημαίνει ότι τα eshop URLs ξεκινούν από το root
]

# =============================================================================
# ΠΡΟΣΤΑΣΙΑ ΔΙΑΧΕΙΡΙΣΤΙΚΟΥ ΠΕΡΙΒΑΛΛΟΝΤΟΣ
# =============================================================================
# Το διαχειριστικό περιβάλλον (/admin/) προστατεύεται με:
# 1. Αυθεντικοποίηση χρήστη με δικαιώματα staff
# 2. Αυθεντικοποίηση δύο παραγόντων (2FA) με OTP
# 3. Προστασία από brute force με django-axes
# 4. CSRF protection σε όλες τις φόρμες
# 5. Περιορισμός πρόσβασης με συγκεκριμένα IP (σε production)
# 
# ΠΟΤΕ μην αλλάζετε το URL path του admin σε περίπτωση που αποκαλυφθεί.
# Η "ασφάλεια μέσω αφάνειας" δεν είναι αποτελεσματική στρατηγική!

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

# =============================================================================
# ΑΣΦΑΛΗΣ ΔΙΑΧΕΙΡΙΣΗ ΣΤΑΤΙΚΩΝ ΑΡΧΕΙΩΝ
# =============================================================================
# ΠΡΟΣΟΧΗ: Στην παραγωγή:
# 1. ΠΟΤΕ μη χρησιμοποιείτε το Django για serving static/media files!
#    Είναι επικίνδυνο για την απόδοση και την ασφάλεια.
# 2. Χρησιμοποιήστε Nginx/Apache/CDN για τα στατικά αρχεία
# 3. Για τα media files (αρχεία χρηστών), εφαρμόστε επιπλέον:
#    - Περιορισμός μεγέθους αρχείων
#    - Έλεγχος τύπου αρχείου (MIME validation)
#    - Σάρωση για κακόβουλο περιεχόμενο
#    - Διαφορετικό domain για security isolation