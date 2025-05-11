# ============================================================================
# WSGI CONFIGURATION FILE  
# Αρχείο διαμόρφωσης για Web Server Gateway Interface
# ============================================================================

"""
WSGI config for eshop_project project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/wsgi/
"""
# Χρησιμότητα του docstring:
# - Επίσημη τεκμηρίωση του αρχείου
# - Εξηγεί τον σκοπό (WSGI configuration)
# - Παρέχει link στην τεκμηρίωση του Django για deployment
# - Standard Django boilerplate από django-admin startproject


# ============================================================================
# IMPORTS - Εισαγωγή απαραίτητων modules
# ============================================================================

# Operating system interface
import os
# Χρησιμότητα:
# - Παρέχει πρόσβαση σε environment variables
# - Χρησιμοποιείται για να ορίσει το DJANGO_SETTINGS_MODULE
# - Cross-platform compatibility για διαφορετικά OS

# Django WSGI application handler
from django.core.wsgi import get_wsgi_application
# Χρησιμότητα:
# - Βασική function του Django για δημιουργία WSGI application
# - Επιστρέφει WSGI-compatible callable object
# - Γέφυρα μεταξύ Django και WSGI servers


# ============================================================================
# ENVIRONMENT CONFIGURATION
# Ρύθμιση environment variables
# ============================================================================

# Ορισμός του Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eshop_project.settings')
# Χρησιμότητα:
# - Καθορίζει ποιο settings module θα χρησιμοποιήσει το Django
# - setdefault: Θέτει τιμή μόνο αν δεν υπάρχει ήδη στο environment
# - Επιτρέπει override από production environment settings
# - Κρίσιμο για την εκκίνηση του Django application


# ============================================================================
# WSGI APPLICATION CREATION
# Δημιουργία του WSGI application instance
# ============================================================================

# Δημιουργία και export του WSGI application
application = get_wsgi_application()
# Χρησιμότητα:
# - Δημιουργεί το WSGI application object
# - Αυτό το object χειρίζεται όλα τα HTTP requests
# - Module-level variable για πρόσβαση από WSGI servers
# - Entry point για WSGI-compatible servers (Apache/mod_wsgi, Gunicorn, uWSGI)
# - Standard interface που γνωρίζουν όλοι οι Python web servers

# Αναλυτική Επεξήγηση WSGI
# 1. Τι είναι το WSGI;
# WSGI (Web Server Gateway Interface) είναι:

# Το standard interface μεταξύ Python web apps και web servers
# Synchronous protocol (ένα request τη φορά ανά worker)
# PEP 3333 specification
# Υποστηρίζεται από όλους τους Python web servers
# Το παραδοσιακό protocol για Django deployment