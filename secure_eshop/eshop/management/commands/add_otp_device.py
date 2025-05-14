from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
import qrcode
from io import BytesIO
import base64

User = get_user_model()

class Command(BaseCommand):
    help = 'Set up OTP device for a user'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str)
        parser.add_argument('--backup-codes', type=int, default=5, help='Number of backup codes to generate')

    def handle(self, *args, **options):
        username = options['username']
        backup_code_count = options['backup_codes']
        
        try:
            user = User.objects.get(username=username)
            
            # Create TOTP device
            device = TOTPDevice.objects.create(user=user, name='Default')
            
            # Generate provisioning URI for QR code
            uri = device.config_url
            
            # Generate QR code
            img = qrcode.make(uri)
            buffer = BytesIO()
            img.save(buffer)
            
            # Save the QR code to a file
            with open(f'{username}_qrcode.png', 'wb') as f:
                f.write(buffer.getvalue())
            
            self.stdout.write(self.style.SUCCESS(
                f'OTP device created for {username}. QR code saved to {username}_qrcode.png'
            ))
            self.stdout.write(f'Secret key: {device.key}')
            
            # Create backup codes
            static_device, created = StaticDevice.objects.get_or_create(user=user, name='Backup')
            
            # Clear any existing tokens
            if not created:
                static_device.token_set.all().delete()
                
            # Generate new backup tokens
            backup_tokens = []
            for _ in range(backup_code_count):
                token = StaticToken.random_token()
                static_device.token_set.create(token=token)
                backup_tokens.append(token)
                
            self.stdout.write(self.style.SUCCESS(f'Generated {backup_code_count} backup codes:'))
            for token in backup_tokens:
                self.stdout.write(f'  {token}')
                
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'User {username} does not exist'))