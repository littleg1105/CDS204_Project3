"""
Custom Django model fields for encrypted data storage.
"""

from django.db import models
from .encryption import encrypt_value, decrypt_value


class EncryptedTextField(models.TextField):
    """
    A TextField that automatically encrypts data before saving 
    and decrypts when retrieving from the database.
    """
    
    def get_prep_value(self, value):
        """Encrypt value before saving to database."""
        if value is None:
            return value
        return encrypt_value(str(value))
    
    def from_db_value(self, value, expression, connection):
        """Decrypt value when loading from database."""
        if value is None:
            return value
        try:
            return decrypt_value(value)
        except Exception:
            # If decryption fails, return the original value
            # This helps during migration from unencrypted to encrypted
            return value
    
    def to_python(self, value):
        """Convert value to Python string."""
        if isinstance(value, str) or value is None:
            return value
        return str(value)


class EncryptedCharField(models.CharField):
    """
    A CharField that automatically encrypts data before saving 
    and decrypts when retrieving from the database.
    """
    
    def __init__(self, *args, **kwargs):
        # Encrypted values are longer than original, adjust max_length
        if 'max_length' in kwargs:
            kwargs['max_length'] = kwargs.get('max_length', 255) * 3
        super().__init__(*args, **kwargs)
    
    def get_prep_value(self, value):
        """Encrypt value before saving to database."""
        if value is None:
            return value
        return encrypt_value(str(value))
    
    def from_db_value(self, value, expression, connection):
        """Decrypt value when loading from database."""
        if value is None:
            return value
        try:
            return decrypt_value(value)
        except Exception:
            # If decryption fails, return the original value
            return value
    
    def to_python(self, value):
        """Convert value to Python string."""
        if isinstance(value, str) or value is None:
            return value
        return str(value)