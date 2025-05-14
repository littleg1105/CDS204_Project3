"""
Utils package for the eshop application.

This package provides utility functions and classes used across the application.
Modules are organized by functionality.
"""

# Import and expose JSON utilities
from .json_utils import UUIDEncoder, dumps

# Import and expose verification utilities
from .verification import verify_email_domain

# Define exports to limit what's imported with "from .utils import *"
__all__ = [
    'UUIDEncoder',
    'dumps',
    'verify_email_domain',
]