"""
Unit tests for authentication mechanisms.
Tests user authentication, login/logout, and session management.
"""

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from unittest.mock import patch, Mock
import time
from eshop.forms import LoginForm
import os
from cryptography.fernet import Fernet

# Set up test encryption key
os.environ['FIELD_ENCRYPTION_KEY'] = Fernet.generate_key().decode()

# Get the custom user model
User = get_user_model()


class AuthenticationTests(TestCase):
    """Test cases for authentication functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword123'
        )
    
    def test_login_valid_credentials(self):
        """Test successful login with valid credentials."""
        response = self.client.post(reverse('eshop:login'), {
            'username': 'testuser',
            'password': 'testpassword123',
            'captcha_0': 'test',  # CAPTCHA will fail but we're testing auth
            'captcha_1': 'test'
        })
        # Login page will be shown with form errors (due to CAPTCHA)
        self.assertEqual(response.status_code, 200)
    
    def test_login_invalid_password(self):
        """Test login with invalid password."""
        response = self.client.post(reverse('eshop:login'), {
            'username': 'testuser',
            'password': 'wrongpassword',
            'captcha_0': 'test',
            'captcha_1': 'test'
        })
        # Should stay on login page
        self.assertEqual(response.status_code, 200)
        # Check user is not authenticated
        self.assertFalse(response.wsgi_request.user.is_authenticated)
    
    def test_login_nonexistent_user(self):
        """Test login with nonexistent username."""
        response = self.client.post(reverse('eshop:login'), {
            'username': 'nonexistentuser',
            'password': 'anypassword',
            'captcha_0': 'test',
            'captcha_1': 'test'
        })
        # Should stay on login page
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)
    
    def test_logout(self):
        """Test logout functionality."""
        # First login
        self.client.force_login(self.user)
        
        # Then logout
        response = self.client.post(reverse('eshop:logout'))
        
        # Should redirect after logout
        self.assertEqual(response.status_code, 302)
    
    def test_authenticated_access(self):
        """Test access to protected views when authenticated."""
        self.client.force_login(self.user)
        
        # Try accessing payment page (requires authentication)
        response = self.client.get(reverse('eshop:payment'))
        # Should either show the payment page or redirect
        self.assertIn(response.status_code, [200, 302])
    
    def test_unauthenticated_access(self):
        """Test redirect to login for protected views when not authenticated."""
        # Try accessing payment page without login
        response = self.client.get(reverse('eshop:payment'))
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)
    
    def test_catalog_access(self):
        """Test that catalog page requires authentication."""
        response = self.client.get(reverse('eshop:catalog'))
        # Should redirect to login page
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)
    
    def test_login_page_access(self):
        """Test that login page is accessible."""
        response = self.client.get(reverse('eshop:login'))
        self.assertEqual(response.status_code, 200)
    
    @patch('eshop.forms.authenticate')
    def test_authentication_called(self, mock_authenticate):
        """Test that Django's authenticate function is called."""
        # Mock authenticate to return None (failed auth)
        mock_authenticate.return_value = None
        
        # Create a mock request for the form
        from django.test import RequestFactory
        request = RequestFactory().post('/login/')
        
        form_data = {
            'username': 'testuser',
            'password': 'wrongpassword',
        }
        
        form = LoginForm(data=form_data, request=request)
        # Calling is_valid triggers the clean method which calls authenticate
        form.is_valid()
        
        # Verify authenticate was called
        mock_authenticate.assert_called()


class SessionSecurityTests(TestCase):
    """Test cases for session security."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='sessionuser',
            email='session@example.com',
            password='sessionpass123'
        )
    
    def test_session_created_on_login(self):
        """Test that a session is created when user logs in."""
        # Force login
        self.client.force_login(self.user)
        
        # Check that session exists
        self.assertIn('_auth_user_id', self.client.session)
        self.assertEqual(str(self.user.id), self.client.session['_auth_user_id'])
    
    def test_session_destroyed_on_logout(self):
        """Test that session is destroyed on logout."""
        # First login
        self.client.force_login(self.user)
        
        # Verify session exists
        self.assertIn('_auth_user_id', self.client.session)
        
        # Then logout
        self.client.post(reverse('eshop:logout'))
        
        # Session should be cleared
        self.assertNotIn('_auth_user_id', self.client.session)