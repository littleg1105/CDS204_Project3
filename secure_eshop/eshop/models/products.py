from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator
import uuid


class Product(models.Model):
    """
    Μοντέλο που αναπαριστά ένα προϊόν στο e-shop.
    
    Χρησιμότητα:
    - Αποθηκεύει όλες τις πληροφορίες προϊόντων (όνομα, περιγραφή, τιμή)
    - Διαχειρίζεται εικόνες προϊόντων με αυτόματη οργάνωση φακέλων
    - Παρέχει validation για τιμές ώστε να μην επιτρέπονται αρνητικές τιμές
    - Χρησιμοποιεί UUID για ασφάλεια από enumeration attacks
    
    Χαρακτηριστικά ασφαλείας:
    - Μη προβλέψιμα IDs αντί για διαδοχικούς αριθμούς
    - Αυτόματη καταγραφή χρονικών σημάνσεων για λόγους ελέγχου
    """
    
    # Primary key με UUID αντί για auto-increment integer
    id = models.UUIDField(
        primary_key=True,       # Ορισμός ως primary key του μοντέλου
        default=uuid.uuid4,     # Αυτόματη δημιουργία UUID κατά την εισαγωγή
        editable=False          # Δεν επιτρέπεται η τροποποίηση του ID
    )
    # Χρησιμότητα: Μη προβλέψιμα IDs για αποφυγή enumeration attacks
    # Ασφάλεια: Αποτρέπει επιθέσεις όπου ο επιτιθέμενος δοκιμάζει διαδοχικά IDs
    
    # Όνομα προϊόντος
    name = models.CharField(max_length=200)
    # Χρησιμότητα: Κύριος τίτλος προϊόντος, περιορισμός στους 200 χαρακτήρες
    # UX: Εμφανίζεται στις λίστες προϊόντων και στις σελίδες προϊόντων
    
    # Περιγραφή προϊόντος
    description = models.TextField()
    # Χρησιμότητα: Αναλυτική περιγραφή χωρίς όριο χαρακτήρων
    # UX: Παρέχει λεπτομερείς πληροφορίες για το προϊόν στον χρήστη
    
    # Τιμή προϊόντος με validation
    price = models.DecimalField(
        max_digits=10,                     # Μέγιστο 10 ψηφία συνολικά
        decimal_places=2,                  # 2 δεκαδικά ψηφία (για cents/λεπτά)
        validators=[MinValueValidator(0)]  # Όχι αρνητικές τιμές
    )
    # Χρησιμότητα: Ακριβής αποθήκευση τιμών χρήματος με protection από αρνητικές τιμές
    # Data Integrity: Το DecimalField αποφεύγει σφάλματα στρογγυλοποίησης στα οικονομικά ποσά
    # Validation: Ο MinValueValidator εξασφαλίζει ότι οι τιμές είναι πάντα ≥ 0
    
    # Εικόνα προϊόντος (προαιρετική)
    image = models.ImageField(
        upload_to='products/',   # Directory για αποθήκευση - οργάνωση ανά τύπο περιεχομένου
        null=True,               # Επιτρέπεται NULL στη database
        blank=True               # Επιτρέπεται κενό στις forms
    )
    # Χρησιμότητα: Αποθήκευση εικόνων με οργάνωση σε φάκελο products/
    # UX: Βελτίωση εμπειρίας χρήστη με οπτική αναπαράσταση προϊόντων
    # Flexibility: Προαιρετικό πεδίο για προϊόντα χωρίς διαθέσιμη εικόνα
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    # Χρησιμότητα: Αυτόματη καταγραφή χρόνου δημιουργίας
    # Auditing: Επιτρέπει την παρακολούθηση του πότε προστέθηκε ένα προϊόν
    
    updated_at = models.DateTimeField(auto_now=True)
    # Χρησιμότητα: Αυτόματη ενημέρωση χρόνου τελευταίας αλλαγής
    # Auditing: Επιτρέπει την παρακολούθηση του πότε ενημερώθηκε τελευταία φορά ένα προϊόν
    
    def __str__(self):
        """String representation του προϊόντος."""
        return self.name
    # Χρησιμότητα: Εμφάνιση ονόματος στο admin και debugging
    # UX Admin: Ευκολότερη αναγνώριση προϊόντων στο Django admin interface


class Cart(models.Model):
    """
    Μοντέλο που αναπαριστά το καλάθι αγορών ενός χρήστη.
    
    Χρησιμότητα:
    - One-to-one relationship με User (ένας χρήστης = ένα καλάθι)
    - Container για CartItems (τα προϊόντα του καλαθιού)
    - Παρέχει μεθόδους για υπολογισμούς συνόλων (ποσότητες, τιμές)
    - Χρησιμοποιεί UUID για ασφάλεια από enumeration attacks
    
    Σχέσεις:
    - Ένα Cart ανήκει σε έναν User
    - Ένα Cart περιέχει πολλά CartItems
    """
    
    # Primary key με UUID αντί για auto-increment integer
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4, 
        editable=False
    )
    # Χρησιμότητα: Μη προβλέψιμα IDs για αποφυγή enumeration attacks
    # Ασφάλεια: Προστασία από επιθέσεις που βασίζονται σε διαδοχικά IDs
    
    # Σύνδεση με χρήστη (1-1 relationship)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,        # Αναφορά στο μοντέλο χρήστη από τις ρυθμίσεις
        on_delete=models.CASCADE         # Διαγραφή καλαθιού αν διαγραφεί ο χρήστης
    )
    # Χρησιμότητα: Κάθε χρήστης έχει ακριβώς ένα καλάθι
    # Relationship: OneToOne εξασφαλίζει την αντιστοιχία 1-1 μεταξύ χρηστών και καλαθιών
    
    # Timestamps - Χρονικές σημάνσεις
    created_at = models.DateTimeField(auto_now_add=True)  # Πότε δημιουργήθηκε
    updated_at = models.DateTimeField(auto_now=True)      # Πότε ενημερώθηκε τελευταία φορά
    
    def __str__(self):
        """String representation του καλαθιού."""
        return f"Cart for {self.user.username}"
    
    def get_total_items(self):
        """
        Υπολογίζει το συνολικό αριθμό αντικειμένων στο καλάθι.
        
        Χρησιμότητα:
        - Εμφάνιση counter στο UI (π.χ. "5 προϊόντα στο καλάθι")
        - Έλεγχος αν το καλάθι είναι άδειο
        - Χρήση για επαληθεύσεις πριν το checkout
        
        Returns:
            int: Συνολικός αριθμός προϊόντων στο καλάθι
        """
        # Χρήση του sum με generator expression για αποδοτικότητα
        return sum(item.quantity for item in self.cartitem_set.all())
    
    def get_total_price(self):
        """
        Υπολογίζει τη συνολική αξία του καλαθιού.
        
        Χρησιμότητα:
        - Εμφάνιση συνολικού κόστους στη σελίδα καλαθιού
        - Χρήση στη διαδικασία checkout για υπολογισμό τελικού ποσού
        - Παρέχει τη βάση για περαιτέρω υπολογισμούς (φόροι, έκπτωση, κλπ)
        
        Returns:
            Decimal: Συνολική αξία όλων των προϊόντων στο καλάθι
        """
        # Υπολογισμός με generator expression: ποσότητα × τιμή για κάθε αντικείμενο
        return sum(item.quantity * item.product.price for item in self.cartitem_set.all())


class CartItem(models.Model):
    """
    Μοντέλο που αναπαριστά ένα προϊόν μέσα στο καλάθι.
    
    Χρησιμότητα:
    - Συνδέει προϊόντα με καλάθια (many-to-many relationship με επιπλέον δεδομένα)
    - Διαχειρίζεται ποσότητες για κάθε προϊόν στο καλάθι
    - Εμποδίζει διπλότυπα (unique_together) - ένα προϊόν εμφανίζεται μόνο μία φορά
    - Χρησιμοποιεί UUID για ασφάλεια από enumeration attacks
    
    Σχέσεις:
    - Ένα CartItem ανήκει σε ένα Cart
    - Ένα CartItem αναφέρεται σε ένα Product
    """
    
    # Primary key με UUID αντί για auto-increment integer
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4, 
        editable=False
    )
    # Χρησιμότητα: Μη προβλέψιμα IDs για αποφυγή enumeration attacks
    # Ασφάλεια: Αποτρέπει επιθέσεις με διαδοχικές δοκιμές IDs
    
    # Foreign key στο καλάθι
    cart = models.ForeignKey(
        Cart,
        on_delete=models.CASCADE  # Διαγραφή items αν διαγραφεί το καλάθι
    )
    # Χρησιμότητα: Σύνδεση με το parent καλάθι
    # Cascade Delete: Εξασφαλίζει ότι τα items διαγράφονται όταν διαγράφεται το καλάθι
    
    # Foreign key στο προϊόν
    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE  # Διαγραφή από καλάθι αν διαγραφεί το προϊόν
    )
    # Χρησιμότητα: Σύνδεση με το προϊόν
    # Data Integrity: Αποτρέπει την ύπαρξη "ορφανών" αντικειμένων στο καλάθι
    
    # Ποσότητα με validation
    quantity = models.PositiveIntegerField(
        default=1,                        # Προεπιλεγμένη ποσότητα: 1
        validators=[MinValueValidator(1)] # Τουλάχιστον 1 τεμάχιο
    )
    # Χρησιμότητα: Διαχείριση ποσοτήτων με protection από μη έγκυρες τιμές
    # Validation: Εξασφαλίζει ότι η ποσότητα είναι τουλάχιστον 1 (θετικός ακέραιος)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)  # Πότε προστέθηκε στο καλάθι
    updated_at = models.DateTimeField(auto_now=True)      # Πότε ενημερώθηκε τελευταία φορά
    
    class Meta:
        # Εμποδίζει το ίδιο προϊόν να μπει 2 φορές στο ίδιο καλάθι
        unique_together = ['cart', 'product']
        # Χρησιμότητα: Database constraint για αποφυγή διπλότυπων
        # UX: Επιτρέπει την αύξηση ποσότητας αντί για προσθήκη διπλών εγγραφών
        
    def __str__(self):
        """String representation του cart item."""
        return f"{self.quantity} x {self.product.name} in {self.cart}"
    
    def get_total_price(self):
        """
        Υπολογίζει το συνολικό κόστος αυτού του item (quantity * price).
        
        Χρησιμότητα:
        - Εμφάνιση υποσυνόλου ανά προϊόν στη σελίδα καλαθιού
        - Χρήση σε υπολογισμούς συνολικής αξίας καλαθιού
        - Εμφάνιση στη σύνοψη παραγγελίας
        
        Returns:
            Decimal: Το γινόμενο της ποσότητας επί την τιμή του προϊόντος
        """
        return self.quantity * self.product.price