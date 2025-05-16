from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid

class CustomUser(AbstractUser):
    """
    Custom User model που χρησιμοποιεί UUID ως primary key αντί για auto-incrementing integer.
    
    Χρησιμότητα:
    - Ασφαλέστερη υλοποίηση με μη-προβλέψιμα IDs για αποφυγή επιθέσεων
    - Αποφυγή enumeration attacks (επιθέσεις απαρίθμησης) όπου οι επιτιθέμενοι 
      μαντεύουν διαδοχικά IDs για πρόσβαση σε δεδομένα
    - Συμβατότητα με το υπόλοιπο σχήμα της βάσης που χρησιμοποιεί UUIDs
    - Προσαρμοσμένα πεδία για επιπλέον λειτουργικότητα χρήστη
    
    Κληρονομικότητα:
    - Επεκτείνει το AbstractUser που παρέχει όλα τα βασικά πεδία χρήστη 
      (username, email, password, first_name, last_name, κλπ.)
    - Διατηρεί όλες τις βασικές λειτουργίες Django authentication
    """
    
    # Override του πεδίου id για χρήση UUID
    id = models.UUIDField(
        primary_key=True,        # Ορισμός ως primary key του μοντέλου
        default=uuid.uuid4,      # Αυτόματη δημιουργία UUID κατά την εισαγωγή νέου χρήστη
        editable=False,          # Δεν επιτρέπεται η τροποποίηση του ID από το UI
        verbose_name='ID'        # Φιλική ονομασία για το admin interface
    )
    # Χρησιμότητα: Αντικαθιστά το αυτόματα αυξανόμενο ID με ένα UUID
    # Ασφάλεια: Τα UUIDs είναι πρακτικά αδύνατο να μαντευτούν ή να προβλεφθούν
    
    # Προσθήκη πεδίου για εικόνα προφίλ
    profile_picture = models.ImageField(
        upload_to='profile_pictures/', # Καθορίζει τον φάκελο αποθήκευσης των εικόνων
        null=True,                     # Επιτρέπει NULL στη βάση δεδομένων
        blank=True,                    # Επιτρέπει κενό πεδίο στις φόρμες (προαιρετικό)
        verbose_name='Εικόνα Προφίλ'   # Φιλική ονομασία για το admin interface
    )
    # Χρησιμότητα: Επιτρέπει στους χρήστες να προσθέτουν εικόνα προφίλ
    # UX: Βελτιώνει την προσωποποίηση του λογαριασμού χρήστη
    # Flexibilty: Προαιρετικό πεδίο (null=True, blank=True)
    
    class Meta(AbstractUser.Meta):
        """
        Metadata για το μοντέλο χρήστη.
        
        Χρησιμότητα:
        - Καθορίζει το μοντέλο ως εναλλάξιμο (swappable) για το Django
        - Παρέχει φιλικές ονομασίες στα ελληνικά για το admin interface
        """
        swappable = 'AUTH_USER_MODEL'   # Επιτρέπει την αντικατάσταση σε settings.py
        verbose_name = 'Χρήστης'        # Ονομασία στο ενικό
        verbose_name_plural = 'Χρήστες' # Ονομασία στον πληθυντικό
        # Κληρονομεί επίσης τις άλλες Meta options από το AbstractUser