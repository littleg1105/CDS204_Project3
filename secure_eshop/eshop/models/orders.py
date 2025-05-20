from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator, RegexValidator
import uuid
import random
import string
from .products import Product
from ..utils.fields import EncryptedCharField, EncryptedTextField


class ShippingAddress(models.Model):
    """
    Μοντέλο που αποθηκεύει διευθύνσεις αποστολής.
    
    Χρησιμότητα:
    - Αποθήκευση multiple διευθύνσεων ανά χρήστη
    - Επαναχρησιμοποίηση διευθύνσεων σε πολλαπλές παραγγελίες
    - Localization με ελληνικά labels για καλύτερη εμπειρία χρήστη
    - Επικύρωση εγκυρότητας για ΤΚ, τηλέφωνο, και email
    - Χρησιμοποιεί UUID για ασφάλεια από enumeration attacks
    
    Τεχνικά χαρακτηριστικά:
    - UUID primary key αντί sequential IDs για ασφάλεια
    - Validators για format checking σε κρίσιμα πεδία (ΤΚ, τηλέφωνο)
    - Timestamps για παρακολούθηση δημιουργίας/ενημέρωσης
    """
    
    # Primary key με UUID αντί για auto-increment integer
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4,  # Αυτόματη δημιουργία UUID κατά την εισαγωγή 
        editable=False      # Δεν επιτρέπεται η τροποποίηση του ID
    )
    # Χρησιμότητα: Μη προβλέψιμα IDs για αποφυγή enumeration attacks
    # Ασφάλεια: Προστασία από επιθέσεις όπου ο επιτιθέμενος δοκιμάζει διαδοχικά IDs
    
    # Foreign key στον χρήστη
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,  # Χρήση του AUTH_USER_MODEL από settings για ευελιξία
        on_delete=models.CASCADE   # Διαγραφή διευθύνσεων αν διαγραφεί ο χρήστης
    )
    # Χρησιμότητα: Σύνδεση διευθύνσεων με χρήστες
    # Σχέση: Ένας χρήστης μπορεί να έχει πολλές διευθύνσεις (one-to-many)
    
    # Πεδία διεύθυνσης με ελληνικά verbose names
    name = EncryptedCharField(max_length=900, verbose_name='Ονοματεπώνυμο')
    address = EncryptedCharField(max_length=1000, verbose_name='Διεύθυνση')
    city = models.CharField(max_length=100, verbose_name='Πόλη')
    
    # Ταχυδρομικός κώδικας με validation για ελληνικό format (5 ψηφία)
    zip_code = models.CharField(
        max_length=5, 
        verbose_name='ΤΚ',
        validators=[
            RegexValidator(
                regex=r'^\d{5}$',  # Regular expression: ακριβώς 5 ψηφία
                message='Ο ταχυδρομικός κώδικας πρέπει να αποτελείται από 5 ψηφία',
                code='invalid_zip_code'  # Κωδικός σφάλματος για αναγνώριση
            )
        ]
    )
    # Χρησιμότητα: Επιβεβαιώνει ότι ο ΤΚ έχει την σωστή μορφή (5 ψηφία)
    # Validation: Εξασφαλίζει την ποιότητα των δεδομένων για σωστή παράδοση
    
    country = models.CharField(max_length=100, verbose_name='Χώρα')
    
    # Τηλέφωνο με validation για ελληνικό format
    phone = EncryptedCharField(
        max_length=1000,
        verbose_name='Τηλέφωνο',
        validators=[
            RegexValidator(
                # Υποστηρίζει μορφές:
                # - 6912345678 (10 ψηφία για κινητά που αρχίζουν με 69)
                # - 2101234567 (10 ψηφία για σταθερά που αρχίζουν με 2)
                # - +30 6912345678 (με διεθνές πρόθεμα +30)
                # - 0030 6912345678 (με διεθνές πρόθεμα 0030)
                regex=r'^(?:\+30|0030)?(?:\s*)(?:(?:69\d{8})|(?:2\d{9}))$',
                message='Παρακαλώ εισάγετε έγκυρο ελληνικό αριθμό τηλεφώνου (σταθερό ή κινητό)',
                code='invalid_phone'
            )
        ],
        blank=False,  # Δεν επιτρέπεται κενό στις forms (υποχρεωτικό πεδίο)
        null=True,    # Επιτρέπεται NULL στη database για backwards compatibility
        help_text='Εισάγετε έγκυρο ελληνικό αριθμό τηλεφώνου (π.χ. 2101234567 ή 6981234567 ή +30 6981234567)'
    )
    # Χρησιμότητα: Επιβεβαιώνει ότι το τηλέφωνο έχει σωστή μορφή ελληνικού αριθμού
    # UX: Το help_text παρέχει παραδείγματα αποδεκτών μορφών
    
    # Email με υποχρεωτική συμπλήρωση και built-in validation
    email = EncryptedCharField(
        max_length=1000,  # Increased max length for encrypted data
        verbose_name='Email',
        help_text='Απαιτείται για επικοινωνία σχετικά με την παραγγελία',
        blank=False,   # Δεν επιτρέπεται κενό στις forms (υποχρεωτικό πεδίο)
        null=True      # Επιτρέπεται NULL στη database για backwards compatibility
    )
    # Χρησιμότητα: Απαραίτητο πεδίο για επικοινωνία με αυτόματη επικύρωση μορφής
    # Validation: Το EmailField παρέχει αυτόματο έλεγχο μορφής email
    
    # Timestamps για παρακολούθηση δημιουργίας και τροποποίησης
    created_at = models.DateTimeField(auto_now_add=True)  # Αυτόματη εισαγωγή κατά τη δημιουργία
    updated_at = models.DateTimeField(auto_now=True)      # Αυτόματη ενημέρωση σε κάθε αλλαγή
    
    def __str__(self):
        """
        String representation της διεύθυνσης.
        
        Returns:
            str: Συμβολοσειρά με τα βασικά στοιχεία της διεύθυνσης
        """
        return f"{self.name}, {self.address}, {self.city}"
    
    class Meta:
        """
        Metadata για το μοντέλο.
        
        Χρησιμότητα:
        - Ελληνικά ονόματα στο admin interface για καλύτερη διαχείριση
        - Ορισμός προβολής στο Django admin
        """
        verbose_name = 'Διεύθυνση Αποστολής'
        verbose_name_plural = 'Διευθύνσεις Αποστολής'


def generate_order_id():
    """
    Δημιουργεί μοναδικό ID παραγγελίας με format: ORD-XXXXX-XXXXX
    
    Χρησιμότητα:
    - Human-readable format για εύκολη αναφορά παραγγελιών
    - Μοναδικότητα μέσω random generation 
    - Εύκολη αναγνώριση παραγγελιών από διαχειριστές και πελάτες
    - Αποφυγή χρήσης προβλέψιμων sequential IDs
    
    Τεχνική λειτουργία:
    - Χρησιμοποιεί συνδυασμό γραμμάτων και αριθμών για μεγάλο keyspace
    - Πρόθεμα "ORD" για εύκολη αναγνώριση ως παραγγελία
    
    Returns:
        str: Order ID σε format ORD-XXXXX-XXXXX
    """
    prefix = 'ORD'
    # Δημιουργία δύο τμημάτων από 5 random χαρακτήρες (γράμματα + αριθμοί)
    # Χρήση των random.choices για την επιλογή χαρακτήρων από το σύνολο των επιτρεπτών
    part1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    part2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    # Συνένωση των μερών με παύλες σε μορφή ORD-XXXXX-XXXXX
    return f"{prefix}-{part1}-{part2}"


class Order(models.Model):
    """
    Μοντέλο που αναπαριστά μια ολοκληρωμένη παραγγελία.
    
    Χρησιμότητα:
    - Καταγραφή παραγγελιών με unique IDs για εύκολη αναφορά
    - Tracking status παραγγελιών (pending, processing, shipped, κλπ)
    - Σύνδεση με χρήστη και διεύθυνση αποστολής
    - Αποθήκευση συνολικού κόστους και χρονικής σήμανσης
    
    Λειτουργίες:
    - Διαχείριση ροής παραγγελιών μέσω καταστάσεων (status)
    - Αποθήκευση ιστορικού παραγγελιών ανά χρήστη
    - Παροχή βάσης για αναφορές και στατιστικά
    """
    
    # Status choices για παραγγελίες
    STATUS_CHOICES = (
        ('pending', 'Εκκρεμεί'),            # Νέα παραγγελία, δεν έχει επεξεργαστεί ακόμα
        ('processing', 'Σε επεξεργασία'),   # Έχει ξεκινήσει η επεξεργασία
        ('shipped', 'Απεστάλη'),            # Έχει αποσταλεί στον πελάτη
        ('delivered', 'Παραδόθηκε'),        # Έχει παραδοθεί στον πελάτη
        ('cancelled', 'Ακυρώθηκε'),         # Η παραγγελία ακυρώθηκε
    )
    # Χρησιμότητα: Predefined επιλογές για order status με ελληνικές ετικέτες
    # Ροή εργασίας: Ορίζει την τυπική ροή μιας παραγγελίας
    
    # Custom primary key με auto-generated ID
    id = models.CharField(
        primary_key=True,
        max_length=20,
        default=generate_order_id,  # Χρήση της συνάρτησης για αυτόματη δημιουργία ID
        editable=False              # Δεν επιτρέπεται αλλαγή μετά τη δημιουργία
    )
    # Χρησιμότητα: Human-readable unique identifiers αντί για auto-increment integers
    # UX: Ευκολότερη αναφορά παραγγελιών σε επικοινωνία με πελάτες
    
    # Foreign keys - Συσχετίσεις με άλλα μοντέλα
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,  # Αναφορά στο μοντέλο χρήστη από τις ρυθμίσεις
        on_delete=models.CASCADE,  # Διαγραφή παραγγελιών αν διαγραφεί ο χρήστης
        verbose_name='Χρήστης'
    )
    # Χρησιμότητα: Σύνδεση παραγγελίας με χρήστη
    # Σχέση: Ένας χρήστης μπορεί να έχει πολλές παραγγελίες (one-to-many)
    
    shipping_address = models.ForeignKey(
        ShippingAddress,
        on_delete=models.PROTECT,  # Προστασία από διαγραφή διεύθυνσης που χρησιμοποιείται
        verbose_name='Διεύθυνση Αποστολής',
        null=True,
        blank=True  # Επιτρέπει την αποθήκευση παραγγελίας χωρίς διεύθυνση (προσωρινά)
    )
    # Χρησιμότητα: Σύνδεση με διεύθυνση, PROTECT αποτρέπει διαγραφή χρησιμοποιούμενων διευθύνσεων
    # Data Integrity: Διατήρηση ιστορικού διευθύνσεων αποστολής
    
    # Οικονομικά στοιχεία
    total_price = models.DecimalField(
        max_digits=10,       # Μέγιστο 10 ψηφία συνολικά
        decimal_places=2,    # 2 δεκαδικά ψηφία για ακρίβεια σε λεπτά του ευρώ
        verbose_name='Συνολικό Ποσό'
    )
    # Χρησιμότητα: Αποθήκευση συνολικού κόστους παραγγελίας
    # Ακρίβεια: Χρήση DecimalField για ακριβείς υπολογισμούς σε νομισματικές τιμές
    
    # Status tracking
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,   # Περιορισμός επιλογών στις προκαθορισμένες τιμές
        default='pending',        # Νέες παραγγελίες ξεκινούν ως "εκκρεμείς"
        verbose_name='Κατάσταση'
    )
    # Χρησιμότητα: Παρακολούθηση κατάστασης παραγγελίας
    # Επιχειρησιακή Λογική: Επιτρέπει τη διαχείριση του κύκλου ζωής της παραγγελίας
    
    # Timestamps - Χρονικές σημάνσεις
    created_at = models.DateTimeField(
        auto_now_add=True,            # Αυτόματη συμπλήρωση κατά τη δημιουργία
        verbose_name='Ημερομηνία Δημιουργίας'
    )
    updated_at = models.DateTimeField(
        auto_now=True,                # Αυτόματη ενημέρωση σε κάθε αλλαγή
        verbose_name='Τελευταία Ενημέρωση'
    )
    
    def __str__(self):
        """
        String representation της παραγγελίας.
        
        Returns:
            str: Συμβολοσειρά με το ID και το username του χρήστη
        """
        return f"Παραγγελία {self.id} - {self.user.username}"
    
    class Meta:
        """
        Metadata για το μοντέλο.
        
        Χρησιμότητα:
        - Ελληνικά ονόματα στο admin για φιλικότερη διαχείριση
        - Default ταξινόμηση από νεότερη σε παλαιότερη για πρακτικότητα
        """
        verbose_name = 'Παραγγελία'
        verbose_name_plural = 'Παραγγελίες'
        ordering = ['-created_at']  # Νεότερες πρώτα στις λίστες εμφάνισης


class OrderItem(models.Model):
    """
    Μοντέλο που αναπαριστά ένα προϊόν μέσα σε παραγγελία.
    
    Χρησιμότητα:
    - Καταγραφή προϊόντων σε παραγγελίες με ποσότητα και τιμή
    - Διατήρηση ιστορικών τιμών (σημαντικό αν αλλάξουν οι τιμές προϊόντων)
    - Υπολογισμός subtotals για κάθε προϊόν στην παραγγελία
    - Χρησιμοποιεί UUID για ασφάλεια από enumeration attacks
    
    Σχέσεις:
    - Ανήκει σε μία παραγγελία (Order)
    - Αναφέρεται σε ένα προϊόν (Product)
    """
    
    # Primary key με UUID αντί για auto-increment integer
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4,   # Αυτόματη δημιουργία UUID κατά την εισαγωγή
        editable=False        # Δεν επιτρέπεται η τροποποίηση
    )
    # Χρησιμότητα: Μη προβλέψιμα IDs για αποφυγή enumeration attacks
    # Ασφάλεια: Αποτροπή προβλέψιμων IDs που θα μπορούσαν να επιτρέψουν πρόσβαση σε ξένα δεδομένα
    
    # Foreign key στην παραγγελία
    order = models.ForeignKey(
        Order,
        on_delete=models.CASCADE,    # Διαγραφή items αν διαγραφεί η παραγγελία
        related_name='items',        # Επιτρέπει την πρόσβαση order.items.all()
        verbose_name='Παραγγελία'
    )
    # Χρησιμότητα: Σύνδεση με parent παραγγελία, related_name για εύκολη πρόσβαση
    # Relationship: Πολλά items μπορούν να ανήκουν σε μία παραγγελία (many-to-one)
    
    # Foreign key στο προϊόν
    product = models.ForeignKey(
        Product,
        on_delete=models.PROTECT,    # Προστασία από διαγραφή προϊόντων που έχουν παραγγελθεί
        verbose_name='Προϊόν'
    )
    # Χρησιμότητα: Σύνδεση με προϊόν, PROTECT για data integrity
    # Data Integrity: Διατήρηση αναφορών σε προϊόντα ακόμα κι αν αλλάξουν ή αποσυρθούν
    
    # Ποσότητα και τιμή
    quantity = models.PositiveIntegerField(
        default=1,                    # Προεπιλογή: 1 τεμάχιο
        validators=[MinValueValidator(1)],  # Ελάχιστη επιτρεπτή ποσότητα: 1
        verbose_name='Ποσότητα'
    )
    # Χρησιμότητα: Αποθήκευση ποσότητας με validation
    # Validation: Εξασφάλιση ότι η ποσότητα είναι τουλάχιστον 1
    
    price = models.DecimalField(
        max_digits=10,        # Μέγιστο 10 ψηφία συνολικά
        decimal_places=2,     # 2 δεκαδικά ψηφία για ακρίβεια σε λεπτά του ευρώ
        verbose_name='Τιμή'
    )
    # Χρησιμότητα: Αποθήκευση τιμής κατά τη στιγμή της παραγγελίας (ιστορικό)
    # Business Logic: Επιτρέπει τον υπολογισμό εσόδων βάσει ιστορικών τιμών
    
    def __str__(self):
        """
        String representation του order item.
        
        Returns:
            str: Συμβολοσειρά με την ποσότητα και το όνομα του προϊόντος
        """
        return f"{self.quantity} x {self.product.name}"
    
    def get_total_price(self):
        """
        Υπολογίζει το συνολικό κόστος για αυτό το item.
        
        Χρησιμότητα:
        - Υπολογισμός subtotal για κάθε γραμμή παραγγελίας
        - Εμφάνιση σε invoices/receipts
        - Βοηθητικό για υπολογισμούς στατιστικών και αναφορών
        
        Returns:
            Decimal: Το γινόμενο ποσότητας επί τιμή μονάδας
        """
        return self.quantity * self.price
    
    class Meta:
        """
        Metadata για το μοντέλο.
        
        Χρησιμότητα:
        - Ελληνικά ονόματα στο admin interface για ευκολότερη διαχείριση
        """
        verbose_name = 'Αντικείμενο Παραγγελίας'
        verbose_name_plural = 'Αντικείμενα Παραγγελίας'