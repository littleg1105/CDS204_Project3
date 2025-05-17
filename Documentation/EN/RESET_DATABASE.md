# Database Reset Guide

This guide explains how to reset your database to implement the encryption changes.

## Quick Reset (Development Only)

For a quick reset in development, use the bash script:

```bash
cd secure_eshop/scripts
./reset_db.sh
```

This will:
1. Delete the SQLite database
2. Remove all migration files
3. Create fresh migrations
4. Apply migrations
5. Generate a new encryption key
6. Optionally create a superuser

## Complete Reset with Backup

For a more comprehensive reset with data backup:

```bash
cd secure_eshop
python scripts/reset_database.py
```

This will:
1. Optionally backup your current data
2. Drop all database tables
3. Delete migration files
4. Create fresh migrations with encryption
5. Apply migrations
6. Generate a new encryption key
7. Optionally restore data from backup
8. Optionally create a superuser

## Manual Reset Steps

If you prefer to do it manually:

### 1. Backup Current Data (Optional)
```bash
python manage.py dumpdata > backup.json
```

### 2. Delete Database
```bash
# For SQLite
rm db.sqlite3

# For PostgreSQL
psql -U postgres -c "DROP DATABASE secure_eshop;"
psql -U postgres -c "CREATE DATABASE secure_eshop;"

# For MySQL
mysql -u root -p -e "DROP DATABASE secure_eshop;"
mysql -u root -p -e "CREATE DATABASE secure_eshop;"
```

### 3. Remove Migrations
```bash
find . -path "*/migrations/*.py" -not -name "__init__.py" -delete
find . -path "*/migrations/*.pyc" -delete
```

### 4. Create New Migrations
```bash
python manage.py makemigrations
```

### 5. Apply Migrations
```bash
python manage.py migrate
```

### 6. Generate Encryption Key
```python
from cryptography.fernet import Fernet
key = Fernet.generate_key()
print(f"FIELD_ENCRYPTION_KEY={key.decode()}")
```

### 7. Update .env File
Add the generated key to your `.env` file:
```
FIELD_ENCRYPTION_KEY=your-generated-key-here
```

### 8. Create Superuser
```bash
python manage.py createsuperuser
```

### 9. Restore Data (Optional)
```bash
python manage.py loaddata backup.json
```

### 10. Encrypt Existing Data
If you restored data from backup:
```bash
python manage.py encrypt_existing_data
```

## Important Notes

1. **Always backup important data** before resetting the database
2. **Save your encryption key** - without it, encrypted data cannot be recovered
3. **Different keys for different environments** - use separate keys for dev/staging/production
4. **Migration files** - After reset, commit the new migration files to version control

## Troubleshooting

### Migration Conflicts
If you encounter migration conflicts:
1. Delete all migration files except `__init__.py`
2. Run `python manage.py makemigrations --empty eshop`
3. Then run `python manage.py makemigrations`

### Foreign Key Constraints
If you get foreign key constraint errors:
1. Use the Python reset script which handles this automatically
2. Or manually disable foreign key checks before dropping tables

### Encryption Key Issues
If encryption/decryption fails:
1. Ensure the `FIELD_ENCRYPTION_KEY` is set in your environment
2. Check that the key is valid (44 characters, base64 encoded)
3. Verify the key hasn't changed between encryption and decryption

## After Reset

Once the database is reset:

1. **Test encryption**: Create a new user/address and verify fields are encrypted in the database
2. **Run tests**: `python manage.py test`
3. **Check admin**: Ensure encrypted fields display correctly in Django admin
4. **Verify SSL**: Test database SSL connections if configured