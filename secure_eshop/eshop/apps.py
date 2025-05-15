# ============================================================================
# DJANGO APP CONFIGURATION FILE
# Αρχείο διαμόρφωσης για το Django application
# ============================================================================

# Import της βασικής κλάσης AppConfig
from django.apps import AppConfig
# Χρησιμότητα:
# - Παρέχει την base class για app configuration
# - Επιτρέπει customization του app initialization
# - Part of Django's app registry system


# ============================================================================
# ESHOP APP CONFIGURATION CLASS
# Κλάση διαμόρφωσης για το eshop application
# ============================================================================

class EshopConfig(AppConfig):
    """
    Configuration class για το eshop Django app.
    
    Χρησιμότητα:
    - Ορίζει metadata για το app
    - Επιτρέπει custom initialization
    - Καταχωρεί το app στο Django registry
    - Παρέχει hooks για app startup
    """
    
    # Default field type για auto-generated primary keys
    default_auto_field = 'django.db.models.BigAutoField'
    # Χρησιμότητα:
    # - Ορίζει τον τύπο για auto-incrementing primary keys
    # - BigAutoField: 64-bit integer (supports huge number of records)
    # - Overrides το project-wide DEFAULT_AUTO_FIELD setting
    # - Future-proof για μεγάλες βάσεις δεδομένων
    # - Range: 1 to 9,223,372,036,854,775,807
    
    # Όνομα του Django app
    name = 'eshop'
    # Χρησιμότητα:
    # - Μοναδικό identifier για το app
    # - Πρέπει να ταιριάζει με το όνομα του directory
    # - Χρησιμοποιείται στο INSTALLED_APPS
    # - Reference για migrations, models, κλπ
    
    def ready(self):
        """
        Called when Django starts up. This is where we can perform app initialization.
        
        Χρησιμότητα:
        - Εκτελείται όταν το Django φορτώνει το app
        - Σημείο για register signals, connect event handlers, κλπ
        - Custom initialization logic
        """
        # Make sure the User model is properly registered
        # The User model is now defined in models.py

#     Django Startup Process:
# 1. Django reads INSTALLED_APPS
# 2. Loads each app's AppConfig
# 3. Calls django.setup()
# 4. Apps registry populated
# 5. Each AppConfig.ready() called
# 6. Signals connected
# 7. Middleware loaded
# 8. URL patterns loaded
# 9. Server ready