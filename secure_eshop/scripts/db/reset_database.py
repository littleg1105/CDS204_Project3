#!/usr/bin/env python
"""
Database reset script for implementing encryption changes.
This script will:
1. Backup current data (optional)
2. Drop all tables
3. Delete migration files
4. Recreate migrations
5. Apply migrations
6. Create superuser (optional)
"""

import os
import sys
import django
from django.core.management import call_command
from pathlib import Path
import shutil
import json
from datetime import datetime

# Add the project directory to the Python path
project_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_dir))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eshop_project.settings')
django.setup()

from django.db import connection
from django.contrib.auth import get_user_model
from django.conf import settings


def backup_data():
    """Backup current data to JSON files"""
    backup_dir = project_dir / 'backups' / f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Backing up data to {backup_dir}")
    
    # List of models to backup
    apps_to_backup = [
        'eshop',
        'auth',
    ]
    
    for app in apps_to_backup:
        backup_file = backup_dir / f'{app}.json'
        try:
            call_command('dumpdata', app, output=str(backup_file), indent=2)
            print(f"Backed up {app} to {backup_file}")
        except Exception as e:
            print(f"Error backing up {app}: {e}")
    
    return backup_dir


def drop_all_tables():
    """Drop all tables from the database"""
    print("Dropping all tables...")
    
    with connection.cursor() as cursor:
        # Disable foreign key checks
        if connection.vendor == 'sqlite':
            cursor.execute('PRAGMA foreign_keys = OFF;')
            # Get all table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            for table in tables:
                if table[0] != 'sqlite_sequence':
                    cursor.execute(f'DROP TABLE IF EXISTS {table[0]};')
                    print(f"Dropped table: {table[0]}")
        
        elif connection.vendor == 'mysql':
            cursor.execute('SET FOREIGN_KEY_CHECKS = 0;')
            cursor.execute('SHOW TABLES;')
            tables = cursor.fetchall()
            for table in tables:
                cursor.execute(f'DROP TABLE IF EXISTS {table[0]};')
                print(f"Dropped table: {table[0]}")
            cursor.execute('SET FOREIGN_KEY_CHECKS = 1;')
        
        elif connection.vendor == 'postgresql':
            cursor.execute("""
                SELECT tablename 
                FROM pg_tables 
                WHERE schemaname = 'public';
            """)
            tables = cursor.fetchall()
            for table in tables:
                cursor.execute(f'DROP TABLE IF EXISTS {table[0]} CASCADE;')
                print(f"Dropped table: {table[0]}")


def delete_migrations():
    """Delete all migration files except __init__.py"""
    print("Deleting migration files...")
    
    migrations_dir = project_dir / 'eshop' / 'migrations'
    
    for file in migrations_dir.glob('*.py'):
        if file.name != '__init__.py':
            file.unlink()
            print(f"Deleted: {file}")
    
    # Also delete pycache
    pycache_dir = migrations_dir / '__pycache__'
    if pycache_dir.exists():
        shutil.rmtree(pycache_dir)
        print(f"Deleted: {pycache_dir}")


def create_fresh_migrations():
    """Create new migrations"""
    print("Creating fresh migrations...")
    call_command('makemigrations', 'eshop')
    print("Migrations created successfully")


def apply_migrations():
    """Apply all migrations"""
    print("Applying migrations...")
    call_command('migrate')
    print("Migrations applied successfully")


def create_superuser():
    """Create a superuser account"""
    print("Creating superuser...")
    
    User = get_user_model()
    
    username = input("Enter superuser username (default: admin): ") or "admin"
    email = input("Enter superuser email (default: admin@example.com): ") or "admin@example.com"
    password = input("Enter superuser password (default: admin123): ") or "admin123"
    
    try:
        user = User.objects.create_superuser(
            username=username,
            email=email,
            password=password
        )
        print(f"Superuser '{username}' created successfully")
        return user
    except Exception as e:
        print(f"Error creating superuser: {e}")
        return None


def generate_encryption_key():
    """Generate a new encryption key"""
    from cryptography.fernet import Fernet
    
    key = Fernet.generate_key()
    print("\n" + "="*50)
    print("NEW ENCRYPTION KEY GENERATED")
    print("="*50)
    print(f"FIELD_ENCRYPTION_KEY={key.decode()}")
    print("="*50)
    print("Add this to your .env file before running the application!")
    print("="*50 + "\n")


def restore_data(backup_dir):
    """Restore data from backup"""
    print(f"Restoring data from {backup_dir}")
    
    # Order matters for foreign key constraints
    restore_order = [
        'auth.json',
        'eshop.json',
    ]
    
    for filename in restore_order:
        backup_file = backup_dir / filename
        if backup_file.exists():
            try:
                call_command('loaddata', str(backup_file))
                print(f"Restored data from {filename}")
            except Exception as e:
                print(f"Error restoring {filename}: {e}")


def main():
    print("Database Reset Script for Encryption Implementation")
    print("="*50)
    
    # Check if we should backup first
    backup_choice = input("Do you want to backup current data? (y/N): ").lower()
    backup_dir = None
    if backup_choice == 'y':
        backup_dir = backup_data()
    
    # Confirm reset
    confirm = input("\nThis will DELETE ALL DATA. Are you sure? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Operation cancelled")
        return
    
    try:
        # Reset database
        drop_all_tables()
        delete_migrations()
        create_fresh_migrations()
        apply_migrations()
        
        # Generate new encryption key
        generate_encryption_key()
        
        # Ask about restoring data
        if backup_dir:
            restore_choice = input("\nDo you want to restore the backed up data? (y/N): ").lower()
            if restore_choice == 'y':
                restore_data(backup_dir)
                print("\nNOTE: Restored data is NOT encrypted. Run 'python manage.py encrypt_existing_data' after setting the encryption key.")
        
        # Create superuser
        create_user = input("\nDo you want to create a superuser? (y/N): ").lower()
        if create_user == 'y':
            create_superuser()
        
        print("\n" + "="*50)
        print("Database reset completed successfully!")
        print("="*50)
        print("\nNext steps:")
        print("1. Add the generated FIELD_ENCRYPTION_KEY to your .env file")
        print("2. Run 'python manage.py runserver' to start the application")
        if backup_dir and restore_choice == 'y':
            print("3. Run 'python manage.py encrypt_existing_data' to encrypt existing data")
        print("="*50)
        
    except Exception as e:
        print(f"\nError during reset: {e}")
        print("Database may be in an inconsistent state")


if __name__ == '__main__':
    main()