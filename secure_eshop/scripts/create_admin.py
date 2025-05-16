from django.core.management import execute_from_command_line
import os
import sys
import django

# Ρύθμιση του περιβάλλοντος Django - Καθορίζουμε το module ρυθμίσεων
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eshop_project.settings')

# Ενεργοποίηση του Django framework ώστε να μπορούμε να χρησιμοποιήσουμε τα μοντέλα
django.setup()

# Εισαγωγή του μοντέλου χρήστη μετά την αρχικοποίηση του Django
# Χρησιμοποιούμε get_user_model() αντί για απευθείας import του User 
# για συμβατότητα με προσαρμοσμένα μοντέλα χρήστη
from django.contrib.auth import get_user_model
User = get_user_model()

# Δημιουργία διαχειριστή (superuser) για πρόσβαση στο admin panel
# Ελέγχουμε πρώτα αν υπάρχει ήδη χρήστης με όνομα 'admin'
if not User.objects.filter(username='admin').exists():
    # Δημιουργία superuser με πλήρη διαχειριστικά δικαιώματα
    User.objects.create_superuser(username='admin', 
                                 email='admin@example.com', 
                                 password='admin123')
    print('Admin user created successfully.')
else:
    # Ενημερωτικό μήνυμα αν ο χρήστης υπάρχει ήδη
    print('Admin user already exists.')