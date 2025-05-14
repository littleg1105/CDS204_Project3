#!/usr/bin/env python
# Χρησιμότητα του shebang:
# - Καθορίζει ότι το script πρέπει να εκτελεστεί με Python
# - Επιτρέπει direct execution: ./manage.py αντί για python manage.py
# - Cross-platform compatibility (Linux/Unix/Mac)

"""Django's command-line utility for administrative tasks."""
# Χρησιμότητα του docstring:
# - Τεκμηρίωση του αρχείου
# - Εξηγεί τον σκοπό του manage.py
# - Εμφανίζεται με help() function

# ============================================================================
# IMPORTS
# ============================================================================

import os
# Χρησιμότητα:
# - Παρέχει πρόσβαση σε environment variables
# - Χρησιμοποιείται για να ορίσει DJANGO_SETTINGS_MODULE
# - Cross-platform path operations

import sys
# Χρησιμότητα:
# - Παρέχει πρόσβαση σε command line arguments (sys.argv)
# - Επιτρέπει system-level operations
# - Error handling και exit codes


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    """Run administrative tasks."""
    # Χρησιμότητα της main function:
    # - Encapsulation του κύριου κώδικα
    # - Καθαρότερη δομή
    # - Επιτρέπει import χωρίς execution
    
    # Ορισμός του Django settings module
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eshop_project.settings')
    # Χρησιμότητα:
    # - Καθορίζει ποιο settings file θα χρησιμοποιήσει το Django
    # - setdefault: Θέτει τιμή μόνο αν δεν υπάρχει ήδη
    # - Επιτρέπει override: DJANGO_SETTINGS_MODULE=myproject.settings.prod python manage.py
    
    try:
        # Import του Django management module
        from django.core.management import execute_from_command_line
        # Χρησιμότητα:
        # - Εισάγει την κύρια function για εκτέλεση Django commands
        # - Lazy import: μόνο όταν χρειάζεται
        # - Μέσα σε try για proper error handling
        
    except ImportError as exc:
        # Error handling για missing Django installation
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
        # Χρησιμότητα:
        # - Παρέχει clear error message
        # - Suggests common solutions (virtual environment)
        # - Maintains exception chaining με 'from exc'
    
    # Εκτέλεση του Django command
    execute_from_command_line(sys.argv)
    # Χρησιμότητα:
    # - Παίρνει command line arguments (sys.argv)
    # - Εκτελεί το αντίστοιχο Django command
    # - Handles routing σε appropriate management commands


# ============================================================================
# SCRIPT ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    main()
# Χρησιμότητα:
# - Εκτελεί τη main() μόνο όταν το script τρέχει directly
# - Όχι όταν γίνεται import ως module
# - Standard Python pattern για executable scripts

# # Server Management
# python manage.py runserver              # Start development server
# python manage.py runserver 0.0.0.0:8080 # Custom host/port

# # Database Management
# python manage.py makemigrations         # Create migration files
# python manage.py migrate                # Apply migrations
# python manage.py dbshell               # Database shell

# # User Management
# python manage.py createsuperuser       # Create admin user
# python manage.py changepassword        # Change user password

# # Data Management
# python manage.py dumpdata              # Export data
# python manage.py loaddata              # Import data
# python manage.py flush                 # Delete all data

# # Static Files
# python manage.py collectstatic         # Collect static files
# python manage.py findstatic            # Find static file location

# # Testing
# python manage.py test                  # Run tests
# python manage.py test app_name         # Run specific app tests

# # Shell Access
# python manage.py shell                 # Python shell with Django
# python manage.py shell_plus            # Enhanced shell (django-extensions)

# # App Management
# python manage.py startapp app_name     # Create new app
# python manage.py startproject          # Create new project

# # Inspection
# python manage.py showmigrations        # Show migration status
# python manage.py sqlmigrate            # Show SQL for migration
# python manage.py inspectdb             # Generate models from DB