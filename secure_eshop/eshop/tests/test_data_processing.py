"""
Unit tests for data processing functions.
Tests encryption/decryption and data manipulation functions.
"""

from django.test import TestCase
from unittest.mock import patch, Mock
import os
from eshop.utils.encryption import get_encryption_key, encrypt_value, decrypt_value
from cryptography.fernet import Fernet
from django.conf import settings


class EncryptionTests(TestCase):
    """Test cases for encryption/decryption functionality."""
    
    def setUp(self):
        """Set up test encryption key."""
        # Generate a test key
        self.test_key = Fernet.generate_key()
        os.environ['FIELD_ENCRYPTION_KEY'] = self.test_key.decode()
    
    def tearDown(self):
        """Clean up environment."""
        if 'FIELD_ENCRYPTION_KEY' in os.environ:
            del os.environ['FIELD_ENCRYPTION_KEY']
    
    def test_get_encryption_key_from_env(self):
        """Test getting encryption key from environment."""
        key = get_encryption_key()
        self.assertEqual(key, self.test_key)
    
    @patch.dict(os.environ, {}, clear=True)
    @patch('eshop.utils.encryption.settings')
    def test_get_encryption_key_from_settings(self, mock_settings):
        """Test getting encryption key from Django settings."""
        mock_settings.DEBUG = False
        mock_settings.FIELD_ENCRYPTION_KEY = self.test_key
        
        key = get_encryption_key()
        self.assertEqual(key, self.test_key)
    
    @patch.dict(os.environ, {}, clear=True)
    @patch('eshop.utils.encryption.settings')
    def test_generate_key_in_debug(self, mock_settings):
        """Test key generation in DEBUG mode."""
        mock_settings.DEBUG = True
        mock_settings.FIELD_ENCRYPTION_KEY = None
        
        key = get_encryption_key()
        # Should generate a valid key
        self.assertIsInstance(key, bytes)
        # Should be a valid Fernet key
        Fernet(key)  # This will raise if invalid
    
    @patch.dict(os.environ, {}, clear=True)
    @patch('eshop.utils.encryption.settings')
    def test_missing_key_in_production(self, mock_settings):
        """Test missing key raises error in production."""
        mock_settings.DEBUG = False
        mock_settings.FIELD_ENCRYPTION_KEY = None
        
        with self.assertRaises(ValueError) as context:
            get_encryption_key()
        
        self.assertIn("FIELD_ENCRYPTION_KEY must be set", str(context.exception))
    
    def test_encrypt_decrypt_string(self):
        """Test encrypting and decrypting a string."""
        original = "This is sensitive data"
        
        # Encrypt
        encrypted = encrypt_value(original)
        self.assertIsInstance(encrypted, str)
        self.assertNotEqual(encrypted, original)
        
        # Decrypt
        decrypted = decrypt_value(encrypted)
        self.assertEqual(decrypted, original)
    
    def test_encrypt_decrypt_empty_string(self):
        """Test handling of empty strings."""
        # Empty string should return empty
        self.assertEqual(encrypt_value(""), "")
        self.assertEqual(decrypt_value(""), "")
        
        # None should return None
        self.assertIsNone(encrypt_value(None))
        self.assertIsNone(decrypt_value(None))
    
    def test_encrypt_decrypt_unicode(self):
        """Test encrypting Unicode characters."""
        original = "Τεστ με ελληνικά 🔐"
        
        encrypted = encrypt_value(original)
        decrypted = decrypt_value(encrypted)
        
        self.assertEqual(decrypted, original)
    
    def test_encrypt_same_value_different_output(self):
        """Test that encrypting same value gives different output (due to IV)."""
        original = "Test data"
        
        encrypted1 = encrypt_value(original)
        encrypted2 = encrypt_value(original)
        
        # Should be different due to initialization vector
        self.assertNotEqual(encrypted1, encrypted2)
        
        # But both should decrypt to same value
        self.assertEqual(decrypt_value(encrypted1), original)
        self.assertEqual(decrypt_value(encrypted2), original)
    
    def test_invalid_encrypted_data(self):
        """Test handling of invalid encrypted data."""
        with self.assertRaises(Exception):
            decrypt_value("invalid_encrypted_data")
    
    def test_encrypt_bytes_input(self):
        """Test encrypting bytes input."""
        original_bytes = b"Binary data"
        
        encrypted = encrypt_value(original_bytes)
        self.assertIsInstance(encrypted, str)
        
        # Note: decrypt_value returns string, not bytes
        decrypted = decrypt_value(encrypted)
        self.assertEqual(decrypted, original_bytes.decode('utf-8'))
    
    def test_key_consistency(self):
        """Test that the same key is used consistently."""
        # Get key multiple times
        key1 = get_encryption_key()
        key2 = get_encryption_key()
        
        self.assertEqual(key1, key2)
    
    def test_string_key_conversion(self):
        """Test that string keys are properly converted to bytes."""
        # Set a string key in environment
        string_key = self.test_key.decode()
        os.environ['FIELD_ENCRYPTION_KEY'] = string_key
        
        key = get_encryption_key()
        self.assertIsInstance(key, bytes)
        self.assertEqual(key, self.test_key)


class DataValidationTests(TestCase):
    """Test cases for data validation functions."""
    
    def test_credit_card_masking(self):
        """Test credit card number masking."""
        # If there's a function for masking credit cards, test it here
        # This is a placeholder for actual function tests
        pass
    
    def test_phone_number_validation(self):
        """Test phone number validation."""
        # If there's a function for validating phone numbers, test it here
        pass
    
    def test_address_validation(self):
        """Test address validation."""
        # If there's a function for validating addresses, test it here
        pass


# Additional test classes for other data processing functions
# can be added here as needed