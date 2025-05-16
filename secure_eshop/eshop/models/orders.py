from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator, RegexValidator
import uuid
import random
import string
from .products import Product


class ShippingAddress(models.Model):
    """
    Μοντέλο που αποθηκεύει διευθύνσεις αποστολής.
    
    Χρησιμότητα:
    - Αποθήκευση multiple διευθύνσεων ανά χρήστη
    - Επαναχρησιμοποίηση διευθύνσεων
    - Localization με ελληνικά labels
    - Επικύρωση εγκυρότητας για ΤΚ, τηλέφωνο, και email
    - Χρησιμοποιεί UUID για ασφάλεια από enumeration attacks
    """
    
    # Primary key με UUID αντί για auto-increment integer
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4, 
        editable=False
    )
    # Χρησιμότητα: Μη προβλέψιμα IDs για αποφυγή enumeration attacks
    
    # Foreign key στον χρήστη
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE  # Διαγραφή διευθύνσεων αν διαγραφεί ο χρήστης
    )
    # Χρησιμότητα: Σύνδεση διευθύνσεων με χρήστες
    
    # Πεδία διεύθυνσης με ελληνικά verbose names
    name = models.CharField(max_length=100, verbose_name='Ονοματεπώνυμο')
    address = models.CharField(max_length=200, verbose_name='Διεύθυνση')
    city = models.CharField(max_length=100, verbose_name='Πόλη')
    
    # Ταχυδρομικός κώδικας με validation για ελληνικό format (5 ψηφία)
    zip_code = models.CharField(
        max_length=5, 
        verbose_name='ΤΚ',
        validators=[
            RegexValidator(
                regex=r'^\d{5}$',
                message='Ο ταχυδρομικός κώδικας πρέπει να αποτελείται από 5 ψηφία',
                code='invalid_zip_code'
            )
        ]
    )
    # Χρησιμότητα: Επιβεβαιώνει ότι ο ΤΚ έχει την σωστή μορφή (5 ψηφία)
    
    country = models.CharField(max_length=100, verbose_name='Χώρα')
    
    # Τηλέφωνο με validation για ελληνικό format
    phone = models.CharField(
        max_length=20,
        verbose_name='Τηλέφωνο',
        validators=[
            RegexValidator(
                regex=r'^(?:\+30|0030)?(?:\s*)(?:(?:69\d{8})|(?:2\d{9}))$',
                message='Παρακαλώ εισάγετε έγκυρο ελληνικό αριθμό τηλεφώνου (σταθερό ή κινητό)',
                code='invalid_phone'
            )
        ],
        blank=False,  # Δεν επιτρέπεται κενό στις forms
        null=True,    # Επιτρέπεται NULL στη database για backwards compatibility
        help_text='Εισάγετε έγκυρο ελληνικό αριθμό τηλεφώνου (π.χ. 2101234567 ή 6981234567 ή +30 6981234567)'
    )
    # Χρησιμότητα: Επιβεβαιώνει ότι το τηλέφωνο έχει σωστή μορφή ελληνικού αριθμού
    
    # Email με υποχρεωτική συμπλήρωση και built-in validation
    email = models.EmailField(
        verbose_name='Email',
        help_text='Απαιτείται για επικοινωνία σχετικά με την παραγγελία',
        blank=False,   # Δεν επιτρέπεται κενό στις forms
        null=True      # Επιτρέπεται NULL στη database για backwards compatibility
    )
    # Χρησιμότητα: Απαραίτητο πεδίο για επικοινωνία με αυτόματη επικύρωση μορφής
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        """String representation της διεύθυνσης."""
        return f"{self.name}, {self.address}, {self.city}"
    
    class Meta:
        """
        Metadata για το μοντέλο.
        
        Χρησιμότητα:
        - Ελληνικά ονόματα στο admin interface
        """
        verbose_name = 'Διεύθυνση Αποστολής'
        verbose_name_plural = 'Διευθύνσεις Αποστολής'


def generate_order_id():
    """
    Δημιουργεί μοναδικό ID παραγγελίας με format: ORD-XXXXX-XXXXX
    
    Χρησιμότητα:
    - Human-readable format
    - Μοναδικότητα μέσω random generation
    - Εύκολη αναγνώριση παραγγελιών
    
    Returns:
        str: Order ID σε format ORD-XXXXX-XXXXX
    """
    prefix = 'ORD'
    # Δημιουργία δύο τμημάτων από 5 random χαρακτήρες (γράμματα + αριθμοί)
    part1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    part2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    return f"{prefix}-{part1}-{part2}"


class Order(models.Model):
    """
    Μοντέλο που αναπαριστά μια ολοκληρωμένη παραγγελία.
    
    Χρησιμότητα:
    - Καταγραφή παραγγελιών με unique IDs
    - Tracking status παραγγελιών
    - Σύνδεση με χρήστη και διεύθυνση
    """
    
    # Status choices για παραγγελίες
    STATUS_CHOICES = (
        ('pending', 'Εκκρεμεί'),
        ('processing', 'Σε επεξεργασία'),
        ('shipped', 'Απεστάλη'),
        ('delivered', 'Παραδόθηκε'),
        ('cancelled', 'Ακυρώθηκε'),
    )
    # Χρησιμότητα: Predefined επιλογές για order status με ελληνικές ετικέτες
    
    # Custom primary key με auto-generated ID
    id = models.CharField(
        primary_key=True,
        max_length=20,
        default=generate_order_id,  # Automatic generation
        editable=False             # Δεν επιτρέπεται αλλαγή
    )
    # Χρησιμότητα: Human-readable unique identifiers αντί για auto-increment integers
    
    # Foreign keys
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        verbose_name='Χρήστης'
    )
    # Χρησιμότητα: Σύνδεση παραγγελίας με χρήστη
    
    shipping_address = models.ForeignKey(
        ShippingAddress,
        on_delete=models.PROTECT,  # Προστασία από διαγραφή διεύθυνσης
        verbose_name='Διεύθυνση Αποστολής',
        null=True,
        blank=True
    )
    # Χρησιμότητα: Σύνδεση με διεύθυνση, PROTECT αποτρέπει διαγραφή χρησιμοποιούμενων διευθύνσεων
    
    # Οικονομικά στοιχεία
    total_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        verbose_name='Συνολικό Ποσό'
    )
    # Χρησιμότητα: Αποθήκευση συνολικού κόστους παραγγελίας
    
    # Status tracking
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending',
        verbose_name='Κατάσταση'
    )
    # Χρησιμότητα: Παρακολούθηση κατάστασης παραγγελίας
    
    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Ημερομηνία Δημιουργίας'
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name='Τελευταία Ενημέρωση'
    )
    
    def __str__(self):
        """String representation της παραγγελίας."""
        return f"Παραγγελία {self.id} - {self.user.username}"
    
    class Meta:
        """
        Metadata για το μοντέλο.
        
        Χρησιμότητα:
        - Ελληνικά ονόματα στο admin
        - Default ταξινόμηση από νεότερη σε παλαιότερη
        """
        verbose_name = 'Παραγγελία'
        verbose_name_plural = 'Παραγγελίες'
        ordering = ['-created_at']  # Νεότερες πρώτα


class OrderItem(models.Model):
    """
    Μοντέλο που αναπαριστά ένα προϊόν μέσα σε παραγγελία.
    
    Χρησιμότητα:
    - Καταγραφή προϊόντων σε παραγγελίες
    - Διατήρηση ιστορικών τιμών
    - Υπολογισμός subtotals
    - Χρησιμοποιεί UUID για ασφάλεια από enumeration attacks
    """
    
    # Primary key με UUID αντί για auto-increment integer
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4, 
        editable=False
    )
    # Χρησιμότητα: Μη προβλέψιμα IDs για αποφυγή enumeration attacks
    
    # Foreign key στην παραγγελία
    order = models.ForeignKey(
        Order,
        on_delete=models.CASCADE,
        related_name='items',  # Allows order.items.all()
        verbose_name='Παραγγελία'
    )
    # Χρησιμότητα: Σύνδεση με parent παραγγελία, related_name για εύκολη πρόσβαση
    
    # Foreign key στο προϊόν
    product = models.ForeignKey(
        Product,
        on_delete=models.PROTECT,  # Προστασία από διαγραφή προϊόντων
        verbose_name='Προϊόν'
    )
    # Χρησιμότητα: Σύνδεση με προϊόν, PROTECT για data integrity
    
    # Ποσότητα και τιμή
    quantity = models.PositiveIntegerField(
        default=1,
        validators=[MinValueValidator(1)],
        verbose_name='Ποσότητα'
    )
    # Χρησιμότητα: Αποθήκευση ποσότητας με validation
    
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        verbose_name='Τιμή'
    )
    # Χρησιμότητα: Αποθήκευση τιμής κατά τη στιγμή της παραγγελίας (ιστορικό)
    
    def __str__(self):
        """String representation του order item."""
        return f"{self.quantity} x {self.product.name}"
    
    def get_total_price(self):
        """
        Υπολογίζει το συνολικό κόστος για αυτό το item.
        
        Χρησιμότητα:
        - Υπολογισμός subtotal
        - Εμφάνιση σε invoices/receipts
        """
        return self.quantity * self.price
    
    class Meta:
        """
        Metadata για το μοντέλο.
        
        Χρησιμότητα:
        - Ελληνικά ονόματα στο admin interface
        """
        verbose_name = 'Αντικείμενο Παραγγελίας'
        verbose_name_plural = 'Αντικείμενα Παραγγελίας'