#!/usr/bin/env python
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eshop_project.settings')
django.setup()

from django.contrib.auth.models import User

# Set the password for the admin user
try:
    admin = User.objects.get(username='admin')
    admin.set_password('Admin123!')
    admin.save()
    print("Password set for admin user.")
except User.DoesNotExist:
    print("Admin user does not exist")