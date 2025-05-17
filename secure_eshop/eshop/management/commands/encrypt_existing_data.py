"""
Management command to encrypt existing data after adding encryption to models.
Usage: python manage.py encrypt_existing_data
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from eshop.models.orders import ShippingAddress
from eshop.models.users import CustomUser


class Command(BaseCommand):
    help = 'Encrypts existing data in the database'

    def handle(self, *args, **options):
        self.stdout.write('Starting data encryption...')
        
        # Encrypt ShippingAddress data
        addresses_count = 0
        with transaction.atomic():
            for address in ShippingAddress.objects.all():
                # Re-save each address to trigger encryption
                address.save()
                addresses_count += 1
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully encrypted {addresses_count} shipping addresses'
            )
        )
        
        # Encrypt CustomUser data
        users_count = 0
        with transaction.atomic():
            for user in CustomUser.objects.all():
                # Re-save each user to trigger encryption
                user.save()
                users_count += 1
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully encrypted {users_count} user records'
            )
        )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Encryption complete! Total records encrypted: {addresses_count + users_count}'
            )
        )