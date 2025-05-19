#!/usr/bin/env python
import os
import django

# Καθορισμός της μεταβλητής περιβάλλοντος για τις ρυθμίσεις Django
# Αυτό είναι απαραίτητο ώστε το script να γνωρίζει πού βρίσκονται οι ρυθμίσεις του project
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eshop_project.settings')

# Αρχικοποίηση του Django framework
# Απαραίτητο για να μπορούμε να χρησιμοποιήσουμε τα μοντέλα και τις λειτουργίες του Django
django.setup()

# Εισαγωγή του μοντέλου User από το Django
from django.contrib.auth.models import User

# Αλλαγή κωδικού πρόσβασης για τον χρήστη 'admin'
try:
    # Αναζήτηση του χρήστη 'admin' στη βάση δεδομένων
    admin = User.objects.get(username='admin')
    
    # Ορισμός νέου κωδικού πρόσβασης με ασφαλή τρόπο
    # Η μέθοδος set_password() κρυπτογραφεί αυτόματα τον κωδικό με Argon2
    admin.set_password('Admin123!')
    
    # Αποθήκευση των αλλαγών στη βάση δεδομένων
    admin.save()
    
    print("Password set for admin user.")
except User.DoesNotExist:
    # Χειρισμός περίπτωσης όπου ο χρήστης 'admin' δεν υπάρχει
    print("Admin user does not exist")