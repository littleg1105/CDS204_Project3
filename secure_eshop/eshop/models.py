# ============================================================================
# IMPORTS - Εισαγωγή απαραίτητων modules
# ============================================================================

# Django models module - βασικές κλάσεις για δημιουργία models
from django.db import models
# Χρησιμότητα: Παρέχει Model class και όλα τα field types

# Custom User model για authentication
from django.conf import settings
# Χρησιμότητα: Αναφορά στο custom User model για σύνδεση με τους χρήστες του συστήματος

# Import the User model definition
from django.contrib.auth.models import AbstractUser
import uuid

# Define the CustomUser model directly within models.py for discoverability
class CustomUser(AbstractUser):
    """
    Custom User model that uses UUID as primary key instead of auto-incrementing integer.
    
    Χρησιμότητα:
    - Ασφαλέστερη υλοποίηση με μη-προβλέψιμα IDs
    - Αποφυγή enumeration attacks
    - Συμβατότητα με το υπόλοιπο σχήμα της βάσης
    - Προσαρμοσμένα πεδία για επιπλέον λειτουργικότητα
    """
    
    # Override the id field to use UUID
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        verbose_name='ID'
    )
    
    # Add a profile picture field
    profile_picture = models.ImageField(
        upload_to='profile_pictures/',
        null=True,
        blank=True,
        verbose_name='Εικόνα Προφίλ'
    )
    
    class Meta(AbstractUser.Meta):
        swappable = 'AUTH_USER_MODEL'
        verbose_name = 'Χρήστης'
        verbose_name_plural = 'Χρήστες'

# Validators για field validation
from django.core.validators import MinValueValidator, RegexValidator
# Χρησιμότητα: Εξασφαλίζει ότι οι τιμές δεν είναι αρνητικές και επιβάλλει μορφή σε πεδία

# UUID module για unique identifiers
import uuid
# Χρησιμότητα: Δημιουργία μοναδικών identifiers (αν και δεν χρησιμοποιείται εδώ)

# Random module για τυχαίους αριθμούς
import random
# Χρησιμότητα: Χρησιμοποιείται στη δημιουργία order IDs

# String module για χαρακτήρες
import string
# Χρησιμότητα: Παρέχει ASCII characters και digits για order ID generation


# This function has been replaced by generate_order_id below.
# Σχόλιο που υποδεικνύει ότι υπήρχε παλαιότερη υλοποίηση


# ============================================================================
# PRODUCT MODEL - Μοντέλο για τα προϊόντα του καταστήματος
# ============================================================================

class Product(models.Model):
    """
    Μοντέλο που αναπαριστά ένα προϊόν στο e-shop.
    
    Χρησιμότητα:
    - Αποθηκεύει όλες τις πληροφορίες προϊόντων
    - Διαχειρίζεται εικόνες προϊόντων
    - Παρέχει validation για τιμές
    - Χρησιμοποιεί UUID για ασφάλεια από enumeration attacks
    """
    
    # Primary key με UUID αντί για auto-increment integer
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4, 
        editable=False
    )
    # Χρησιμότητα: Μη προβλέψιμα IDs για αποφυγή enumeration attacks
    
    # Όνομα προϊόντος
    name = models.CharField(max_length=200)
    # Χρησιμότητα: Κύριος τίτλος προϊόντος, περιορισμός στους 200 χαρακτήρες
    
    # Περιγραφή προϊόντος
    description = models.TextField()
    # Χρησιμότητα: Αναλυτική περιγραφή χωρίς όριο χαρακτήρων
    
    # Τιμή προϊόντος με validation
    price = models.DecimalField(
        max_digits=10,           # Μέγιστο 10 ψηφία συνολικά
        decimal_places=2,        # 2 δεκαδικά ψηφία (για cents/λεπτά)
        validators=[MinValueValidator(0)]  # Όχι αρνητικές τιμές
    )
    # Χρησιμότητα: Ακριβής αποθήκευση τιμών χρήματος με protection από αρνητικές τιμές
    
    # Εικόνα προϊόντος (προαιρετική)
    image = models.ImageField(
        upload_to='products/',   # Directory για αποθήκευση
        null=True,              # Επιτρέπεται NULL στη database
        blank=True              # Επιτρέπεται κενό στις forms
    )
    # Χρησιμότητα: Αποθήκευση εικόνων με οργάνωση σε φάκελο products/
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    # Χρησιμότητα: Αυτόματη καταγραφή χρόνου δημιουργίας
    
    updated_at = models.DateTimeField(auto_now=True)
    # Χρησιμότητα: Αυτόματη ενημέρωση χρόνου τελευταίας αλλαγής
    
    def __str__(self):
        """String representation του προϊόντος."""
        return self.name
    # Χρησιμότητα: Εμφάνιση ονόματος στο admin και debugging


# ============================================================================
# CART MODEL - Μοντέλο για το καλάθι αγορών
# ============================================================================

class Cart(models.Model):
    """
    Μοντέλο που αναπαριστά το καλάθι αγορών ενός χρήστη.
    
    Χρησιμότητα:
    - One-to-one relationship με User (ένας χρήστης = ένα καλάθι)
    - Container για CartItems
    - Υπολογισμοί συνόλων
    - Χρησιμοποιεί UUID για ασφάλεια από enumeration attacks
    """
    
    # Primary key με UUID αντί για auto-increment integer
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4, 
        editable=False
    )
    # Χρησιμότητα: Μη προβλέψιμα IDs για αποφυγή enumeration attacks
    
    # Σύνδεση με χρήστη (1-1 relationship)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE  # Διαγραφή καλαθιού αν διαγραφεί ο χρήστης
    )
    # Χρησιμότητα: Κάθε χρήστης έχει ακριβώς ένα καλάθι
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        """String representation του καλαθιού."""
        return f"Cart for {self.user.username}"
    
    def get_total_items(self):
        """
        Υπολογίζει το συνολικό αριθμό αντικειμένων στο καλάθι.
        
        Χρησιμότητα:
        - Εμφάνιση counter στο UI
        - Έλεγχος αν το καλάθι είναι άδειο
        """
        return sum(item.quantity for item in self.cartitem_set.all())
    
    def get_total_price(self):
        """
        Υπολογίζει τη συνολική αξία του καλαθιού.
        
        Χρησιμότητα:
        - Εμφάνιση συνολικού κόστους
        - Χρήση στη διαδικασία checkout
        """
        return sum(item.quantity * item.product.price for item in self.cartitem_set.all())


# ============================================================================
# CART ITEM MODEL - Μοντέλο για τα αντικείμενα στο καλάθι
# ============================================================================

class CartItem(models.Model):
    """
    Μοντέλο που αναπαριστά ένα προϊόν μέσα στο καλάθι.
    
    Χρησιμότητα:
    - Συνδέει προϊόντα με καλάθια
    - Διαχειρίζεται ποσότητες
    - Εμποδίζει διπλότυπα (unique_together)
    - Χρησιμοποιεί UUID για ασφάλεια από enumeration attacks
    """
    
    # Primary key με UUID αντί για auto-increment integer
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4, 
        editable=False
    )
    # Χρησιμότητα: Μη προβλέψιμα IDs για αποφυγή enumeration attacks
    
    # Foreign key στο καλάθι
    cart = models.ForeignKey(
        Cart,
        on_delete=models.CASCADE  # Διαγραφή items αν διαγραφεί το καλάθι
    )
    # Χρησιμότητα: Σύνδεση με το parent καλάθι
    
    # Foreign key στο προϊόν
    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE  # Διαγραφή από καλάθι αν διαγραφεί το προϊόν
    )
    # Χρησιμότητα: Σύνδεση με το actual προϊόν
    
    # Ποσότητα με validation
    quantity = models.PositiveIntegerField(
        default=1,
        validators=[MinValueValidator(1)]  # Τουλάχιστον 1
    )
    # Χρησιμότητα: Αποθήκευση ποσότητας με validation για θετικούς αριθμούς
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        """
        Metadata για το μοντέλο.
        
        Χρησιμότητα:
        - Εμποδίζει το ίδιο προϊόν να υπάρχει δύο φορές στο ίδιο καλάθι
        """
        unique_together = ('cart', 'product')  # Μοναδικός συνδυασμός cart-product
    
    def __str__(self):
        """String representation του cart item."""
        return f"{self.quantity} x {self.product.name}"
    
    def get_total(self):
        """
        Υπολογίζει το συνολικό κόστος για αυτό το item.
        
        Χρησιμότητα:
        - Εμφάνιση subtotal ανά προϊόν
        - Χρήση σε υπολογισμούς καλαθιού
        """
        return self.quantity * self.product.price


# ============================================================================
# SHIPPING ADDRESS MODEL - Μοντέλο για διευθύνσεις αποστολής
# ============================================================================

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


# ============================================================================
# ORDER ID GENERATOR - Συνάρτηση δημιουργίας μοναδικού ID παραγγελίας
# ============================================================================

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


# ============================================================================
# ORDER MODEL - Μοντέλο για παραγγελίες
# ============================================================================

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


# ============================================================================
# ORDER ITEM MODEL - Μοντέλο για προϊόντα σε παραγγελίες
# ============================================================================

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

# ============================================================================
# Ανάλυση Χρησιμότητας ανά Model
# 1. Product Model

# Βασικό model του e-shop: Αποθηκεύει όλες τις πληροφορίες προϊόντων
# Image handling: Upload και οργάνωση εικόνων
# Price validation: Προστασία από αρνητικές τιμές
# Timestamps: Tracking δημιουργίας/ενημέρωσης

# 2. Cart Model

# One-to-one με User: Κάθε χρήστης έχει ένα μοναδικό καλάθι
# Container pattern: Περιέχει CartItems
# Aggregate calculations: Υπολογισμοί συνόλων
# Session persistence: Το καλάθι παραμένει μεταξύ sessions

# 3. CartItem Model

# Junction table: Συνδέει Products με Carts
# Quantity management: Διαχείριση ποσοτήτων
# Unique constraint: Αποτρέπει διπλότυπα
# Subtotal calculations: Υπολογισμοί ανά προϊόν

# 4. ShippingAddress Model

# Multiple addresses: Πολλές διευθύνσεις ανά χρήστη
# Greek localization: Ελληνικά labels και verbose names
# Optional fields: Phone/email προαιρετικά
# Reusability: Επαναχρησιμοποίηση διευθύνσεων

# 5. Order Model

# Custom primary key: Human-readable order IDs
# Status tracking: Lifecycle management
# Foreign key protection: PROTECT για shipping addresses
# Historical record: Αμετάβλητο αρχείο παραγγελιών

# 6. OrderItem Model

# Order details: Προϊόντα σε κάθε παραγγελία
# Price history: Αποθήκευση τιμών κατά την παραγγελία
# Data integrity: PROTECT για προϊόντα
# Related name: Εύκολη πρόσβαση από Order

# Database Relationships

# User ↔ Cart: One-to-One
# Cart ↔ CartItem: One-to-Many
# Product ↔ CartItem: One-to-Many
# User ↔ ShippingAddress: One-to-Many
# User ↔ Order: One-to-Many
# Order ↔ OrderItem: One-to-Many
# ShippingAddress ↔ Order: One-to-Many
# Product ↔ OrderItem: One-to-Many

# Security & Best Practices

# Cascade deletions: Όπου είναι λογικό
# Protect deletions: Για data integrity
# Validation: MinValueValidator για ποσότητες/τιμές
# Unique constraints: Αποφυγή διπλότυπων
# Decimal fields: Για ακριβείς χρηματικές τιμές
# Timestamps: Audit trail σε όλα τα models