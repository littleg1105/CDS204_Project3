import os
from cryptography.fernet import Fernet

# Set up test encryption key
os.environ['FIELD_ENCRYPTION_KEY'] = Fernet.generate_key().decode()

# Import all settings from the base settings
from .settings import *

# Override any settings for testing
DEBUG = True
FIELD_ENCRYPTION_KEY = os.environ['FIELD_ENCRYPTION_KEY']

# Test database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Disable security features for testing
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 0

# Use custom test runner for documentation
TEST_RUNNER = 'eshop.tests.test_runner.DocumentingTestRunner'