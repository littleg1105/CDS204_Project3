from django.core.management import execute_from_command_line
import os
import sys
import django

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eshop_project.settings')
django.setup()

# Import the user model after Django is set up
from django.contrib.auth import get_user_model
User = get_user_model()

# Create superuser
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser(username='admin', email='admin@example.com', password='admin123')
    print('Admin user created successfully.')
else:
    print('Admin user already exists.')