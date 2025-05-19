"""
Simple test to verify test environment setup.
"""

import os
from cryptography.fernet import Fernet

# Set up test encryption key BEFORE importing Django
os.environ['FIELD_ENCRYPTION_KEY'] = Fernet.generate_key().decode()

from django.test import TestCase
from django.contrib.auth import get_user_model

User = get_user_model()


class SimpleTest(TestCase):
    """Basic test to verify testing works."""
    
    def test_user_creation(self):
        """Test that we can create a user."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword123'
        )
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@example.com')
        self.assertTrue(user.check_password('testpassword123'))
    
    def test_basic_math(self):
        """Test that 1 + 1 = 2."""
        self.assertEqual(1 + 1, 2)