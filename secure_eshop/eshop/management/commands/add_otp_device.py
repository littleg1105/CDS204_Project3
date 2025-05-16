from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
import qrcode
from io import BytesIO
import base64

User = get_user_model()

class Command(BaseCommand):
    """
    Django management command για τη ρύθμιση διπλού παράγοντα αυθεντικοποίησης (2FA) για χρήστες.
    
    Αυτή η εντολή δημιουργεί:
    1. Μια συσκευή TOTP (Time-based One-Time Password) για τον καθορισμένο χρήστη
    2. Ένα QR code που ο χρήστης μπορεί να σκανάρει με εφαρμογή 2FA (π.χ. Google Authenticator)
    3. Εφεδρικούς κωδικούς μιας χρήσης για περιπτώσεις όπου ο χρήστης δεν έχει πρόσβαση στην εφαρμογή 2FA
    
    Χρήση: python manage.py setup_otp_device username [--backup-codes=5]
    """
    help = 'Set up OTP device for a user'
    
    def add_arguments(self, parser):
        """
        Προσθέτει τα απαραίτητα arguments στην εντολή.
        
        Arguments:
            username: Το όνομα χρήστη για τον οποίο θα ρυθμιστεί η συσκευή OTP
            --backup-codes: Αριθμός εφεδρικών κωδικών που θα δημιουργηθούν (προεπιλογή: 5)
        """
        parser.add_argument('username', type=str)
        parser.add_argument('--backup-codes', type=int, default=5, help='Number of backup codes to generate')
    
    def handle(self, *args, **options):
        """
        Εκτελεί την κύρια λειτουργία της εντολής.
        
        Ροή εργασίας:
        1. Εύρεση του χρήστη με το καθορισμένο username
        2. Δημιουργία συσκευής TOTP
        3. Δημιουργία QR code και αποθήκευση σε αρχείο
        4. Δημιουργία εφεδρικών κωδικών
        5. Εμφάνιση πληροφοριών στην κονσόλα
        
        Θέματα ασφαλείας:
        - Το μυστικό κλειδί και οι εφεδρικοί κωδικοί εμφανίζονται στην κονσόλα
        - Το QR code αποθηκεύεται σε αρχείο στον τοπικό δίσκο
        - Αυτές οι πληροφορίες πρέπει να μεταδοθούν με ασφάλεια στον χρήστη
        """
        username = options['username']
        backup_code_count = options['backup_codes']
        
        try:
            # Αναζήτηση του χρήστη στη βάση δεδομένων
            user = User.objects.get(username=username)
            
            # Δημιουργία συσκευής TOTP για τον χρήστη
            device = TOTPDevice.objects.create(user=user, name='Default')
            
            # Δημιουργία URI για το QR code που μπορεί να σκαναριστεί από εφαρμογές όπως Google Authenticator
            uri = device.config_url
            
            # Δημιουργία QR code από το URI
            img = qrcode.make(uri)
            buffer = BytesIO()
            img.save(buffer)
            
            # Αποθήκευση του QR code σε αρχείο PNG
            # ΣΗΜΑΝΤΙΚΟ: Αυτό το αρχείο περιέχει ευαίσθητες πληροφορίες και πρέπει να διαγραφεί μετά τη χρήση
            with open(f'{username}_qrcode.png', 'wb') as f:
                f.write(buffer.getvalue())
            
            self.stdout.write(self.style.SUCCESS(
                f'OTP device created for {username}. QR code saved to {username}_qrcode.png'
            ))
            self.stdout.write(f'Secret key: {device.key}')
            
            # Δημιουργία εφεδρικών κωδικών μιας χρήσης
            static_device, created = StaticDevice.objects.get_or_create(user=user, name='Backup')
            
            # Διαγραφή υπαρχόντων κωδικών (αν η συσκευή δεν είναι νέα)
            if not created:
                static_device.token_set.all().delete()
            
            # Δημιουργία νέων εφεδρικών κωδικών
            backup_tokens = []
            for _ in range(backup_code_count):  # Διορθωμένη σύνταξη, χρήση _ αντί *
                token = StaticToken.random_token()
                static_device.token_set.create(token=token)
                backup_tokens.append(token)
            
            self.stdout.write(self.style.SUCCESS(f'Generated {backup_code_count} backup codes:'))
            for token in backup_tokens:
                self.stdout.write(f' {token}')
            
        except User.DoesNotExist:
            # Χειρισμός σφάλματος αν ο χρήστης δεν υπάρχει
            self.stdout.write(self.style.ERROR(f'User {username} does not exist'))