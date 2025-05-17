#!/bin/bash

# Quick database reset script
# Usage: ./reset_db.sh

echo "Quick Database Reset for Encryption Implementation"
echo "================================================"

# Navigate to project directory
cd "$(dirname "$0")/.."

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
elif [ -d "../venv" ]; then
    source ../venv/bin/activate
fi

# Delete SQLite database
echo "Removing SQLite database..."
rm -f db.sqlite3

# Delete migration files
echo "Removing migration files..."
find . -path "*/migrations/*.py" -not -name "__init__.py" -delete
find . -path "*/migrations/*.pyc" -delete
find . -path "*/__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Create new migrations
echo "Creating new migrations..."
python manage.py makemigrations

# Apply migrations
echo "Applying migrations..."
python manage.py migrate

# Generate encryption key
echo ""
echo "================================================"
echo "GENERATING NEW ENCRYPTION KEY"
echo "================================================"
python -c "from cryptography.fernet import Fernet; key = Fernet.generate_key(); print(f'FIELD_ENCRYPTION_KEY={key.decode()}')"
echo "================================================"
echo "Add the above key to your .env file!"
echo "================================================"

# Create superuser
echo ""
read -p "Create superuser? (y/N): " create_super
if [ "$create_super" = "y" ] || [ "$create_super" = "Y" ]; then
    python manage.py createsuperuser
fi

echo ""
echo "Database reset completed!"
echo ""
echo "Next steps:"
echo "1. Add the FIELD_ENCRYPTION_KEY to your .env file"
echo "2. Run 'python manage.py runserver_plus --cert-file=certificates/cert.pem --key-file=certificates/key.pem'"