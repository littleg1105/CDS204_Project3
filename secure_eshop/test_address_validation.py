#!/usr/bin/env python

import os
import django

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eshop_project.settings')
django.setup()

# Now we can import Django models and forms
from eshop.forms import ShippingAddressForm
from django.contrib.auth.models import User

def test_valid_data():
    """Test with valid shipping address data."""
    print("\n===== Testing valid data =====")
    form_data = {
        'name': 'Γιώργος Παπαδόπουλος',
        'address': 'Οδός Μακεδονίας 123',
        'city': 'Αθήνα',
        'zip_code': '15341',  # Valid Greek postal code (5 digits)
        'country': 'Ελλάδα',
        'phone': '+30 2101234567',  # Valid Greek phone
        'email': 'test@example.com'  # Valid email
    }
    
    form = ShippingAddressForm(data=form_data)
    if form.is_valid():
        print("✅ Form is valid!")
        print("Cleaned data:", form.cleaned_data)
    else:
        print("❌ Form is invalid!")
        print("Errors:", form.errors)

def test_invalid_zip_code():
    """Test with invalid zip code formats."""
    print("\n===== Testing invalid zip code =====")
    
    # Test with non-digit characters
    form_data = {
        'name': 'Γιώργος Παπαδόπουλος',
        'address': 'Οδός Μακεδονίας 123',
        'city': 'Αθήνα',
        'zip_code': '153AB',  # Contains letters
        'country': 'Ελλάδα',
        'phone': '+30 2101234567',
        'email': 'test@example.com'
    }
    
    form = ShippingAddressForm(data=form_data)
    if form.is_valid():
        print("❌ Form with non-digit zip code should be invalid!")
    else:
        print("✅ Form correctly rejected non-digit zip code.")
        print("Zip code error:", form.errors.get('zip_code', 'No error'))
    
    # Test with incorrect length
    form_data['zip_code'] = '1534'  # Only 4 digits
    form = ShippingAddressForm(data=form_data)
    if form.is_valid():
        print("❌ Form with wrong-length zip code should be invalid!")
    else:
        print("✅ Form correctly rejected wrong-length zip code.")
        print("Zip code error:", form.errors.get('zip_code', 'No error'))

def test_invalid_phone():
    """Test with invalid phone formats."""
    print("\n===== Testing invalid phone =====")
    
    form_data = {
        'name': 'Γιώργος Παπαδόπουλος',
        'address': 'Οδός Μακεδονίας 123',
        'city': 'Αθήνα',
        'zip_code': '15341',
        'country': 'Ελλάδα',
        'phone': '1234567890',  # Invalid Greek phone (starts with 1)
        'email': 'test@example.com'
    }
    
    form = ShippingAddressForm(data=form_data)
    if form.is_valid():
        print("❌ Form with invalid phone number should be invalid!")
    else:
        print("✅ Form correctly rejected invalid phone number.")
        print("Phone error:", form.errors.get('phone', 'No error'))

def test_invalid_email():
    """Test with invalid email formats and non-existent domains."""
    print("\n===== Testing invalid email =====")
    
    # Test with invalid format
    form_data = {
        'name': 'Γιώργος Παπαδόπουλος',
        'address': 'Οδός Μακεδονίας 123',
        'city': 'Αθήνα',
        'zip_code': '15341',
        'country': 'Ελλάδα',
        'phone': '+30 2101234567',
        'email': 'invalid-email'  # Missing @ and domain
    }
    
    form = ShippingAddressForm(data=form_data)
    if form.is_valid():
        print("❌ Form with invalid email format should be invalid!")
    else:
        print("✅ Form correctly rejected invalid email format.")
        print("Email error:", form.errors.get('email', 'No error'))
    
    # Test with non-existent domain
    form_data['email'] = 'test@nonexistentdomain123456789.com'
    form = ShippingAddressForm(data=form_data)
    if form.is_valid():
        print("❌ Form with non-existent domain should be invalid!")
    else:
        print("✅ Form correctly rejected non-existent domain.")
        print("Email error:", form.errors.get('email', 'No error'))

if __name__ == "__main__":
    print("Testing ShippingAddressForm validation...")
    test_valid_data()
    test_invalid_zip_code()
    test_invalid_phone()
    test_invalid_email()
    print("\nValidation testing complete.")