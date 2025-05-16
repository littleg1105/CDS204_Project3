from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator
import uuid


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
    # Χρησιμότητα: Σύνδεση με το προϊόν
    
    # Ποσότητα με validation
    quantity = models.PositiveIntegerField(
        default=1,
        validators=[MinValueValidator(1)]  # Τουλάχιστον 1 τεμάχιο
    )
    # Χρησιμότητα: Διαχείριση ποσοτήτων με protection από μη έγκυρες τιμές
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        # Εμποδίζει το ίδιο προϊόν να μπει 2 φορές στο ίδιο καλάθι
        unique_together = ['cart', 'product']
        # Χρησιμότητα: Database constraint για αποφυγή διπλότυπων
        
    def __str__(self):
        """String representation του cart item."""
        return f"{self.quantity} x {self.product.name} in {self.cart}"
    
    def get_total_price(self):
        """
        Υπολογίζει το συνολικό κόστος αυτού του item (quantity * price).
        
        Χρησιμότητα:
        - Εμφάνιση υποσυνόλου ανά item
        - Χρήση σε υπολογισμούς καλαθιού
        """
        return self.quantity * self.product.price