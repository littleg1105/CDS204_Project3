"""
Encryption utilities for sensitive data fields.

This module provides simple encryption/decryption functions for protecting
sensitive data at rest using Fernet symmetric encryption.
"""

import os
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
from django.conf import settings


def get_encryption_key():
    """Get or generate encryption key from settings or environment."""
    # Try to get key from environment
    key = os.getenv('FIELD_ENCRYPTION_KEY')
    
    if not key:
        # Try to get from Django settings
        key = getattr(settings, 'FIELD_ENCRYPTION_KEY', None)
    
    if not key:
        # Generate a new key if none exists (only for development)
        if settings.DEBUG:
            key = Fernet.generate_key()
            print(f"Generated new encryption key: {key.decode()}")
            print("Add this to your environment as FIELD_ENCRYPTION_KEY")
        else:
            raise ValueError("FIELD_ENCRYPTION_KEY must be set in production")
    
    if isinstance(key, str):
        key = key.encode()
    
    return key


def encrypt_value(value):
    """Encrypt a string value."""
    if not value:
        return value
        
    key = get_encryption_key()
    f = Fernet(key)
    
    # Convert to bytes if necessary
    if isinstance(value, str):
        value = value.encode('utf-8')
    
    # Encrypt and return as string
    encrypted = f.encrypt(value)
    return encrypted.decode('utf-8')


def decrypt_value(encrypted_value):
    """Decrypt an encrypted string value."""
    if not encrypted_value:
        return encrypted_value
    
    key = get_encryption_key()
    f = Fernet(key)
    
    # Convert to bytes if necessary
    if isinstance(encrypted_value, str):
        encrypted_value = encrypted_value.encode('utf-8')
    
    # Decrypt and return as string
    decrypted = f.decrypt(encrypted_value)
    return decrypted.decode('utf-8')