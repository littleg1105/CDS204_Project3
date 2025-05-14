# Adding OTP to Django's Default Admin Panel

You can add One-Time Password (OTP) functionality to Django's admin panel using the `django-otp` package. Here's how to implement it:

## 1. Install Required Packages

```bash
pip install django-otp
pip install qrcode  # For generating QR codes
```

## 2. Update Settings

Add the necessary apps and middleware to your `settings.py`:

```python
INSTALLED_APPS = [
    # ... existing apps
    'django_otp',
    'django_otp.plugins.otp_totp',  # For time-based OTP
    'django_otp.plugins.otp_static',  # For backup codes
]

MIDDLEWARE = [
    # ... existing middleware
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_otp.middleware.OTPMiddleware',  # Add this after AuthenticationMiddleware
]
```

## 3. Customize Admin Site

Create a custom admin site in a new file, e.g., `admin.py`:

```python
from django.contrib.admin import AdminSite
from django_otp.admin import OTPAdminSite

class OTPAdmin(OTPAdminSite):
    site_title = 'Django Admin with OTP'
    site_header = 'Django Administration with OTP'

# Replace the default admin site
from django.contrib import admin
admin.site.__class__ = OTPAdmin
```

## 4. Update URLs

In your `urls.py`:

```python
from django.urls import path, include
from django.contrib import admin

urlpatterns = [
    path('admin/', admin.site.urls),
    # ... other URLs
]
```

## 5. Set Up OTP for Users

Create a management command to help users set up their OTP devices:

```python
# management/commands/add_otp_device.py
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django_otp.plugins.otp_totp.models import TOTPDevice
import qrcode
from io import BytesIO
import base64

User = get_user_model()

class Command(BaseCommand):
    help = 'Set up OTP device for a user'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str)

    def handle(self, *args, **options):
        username = options['username']
        try:
            user = User.objects.get(username=username)
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
            
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'User {username} does not exist'))
```

Run the command to set up OTP for a user:

```bash
python manage.py add_otp_device username
```

## 6. Generate Backup Codes (Optional)

```python
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken

def create_backup_codes(user, count=10):
    device = StaticDevice.objects.create(user=user, name='Backup')
    tokens = []
    for _ in range(count):
        token = StaticToken.random_token()
        device.token_set.create(token=token)
        tokens.append(token)
    return tokens
```

## Testing

After setup, when you visit the admin panel, you'll now be prompted for:
1. Username and password (first factor)
2. OTP code (second factor)

Users should scan the QR code with an authenticator app like Google Authenticator, Microsoft Authenticator, or Authy.

Would you like me to explain any specific part of this implementation in more detail?