# Suggested File Structure Improvements

## Current Issues:
1. Utility scripts mixed with main app files
2. Models split into both files and directory
3. User-related code scattered
4. __pycache__ directories visible

## Suggested Structure:

```
secure_eshop/
├── manage.py
├── requirements.txt
├── .gitignore                  # Add to exclude __pycache__, db.sqlite3, etc.
│
├── scripts/                    # Move utility scripts here
│   ├── create_admin.py
│   └── set_password.py
│
├── config/                     # Configuration files
│   ├── certificates/
│   │   ├── cert.pem
│   │   └── key.pem
│   └── admin_qrcode.png
│
├── eshop_project/             # Project settings
│   ├── __init__.py
│   ├── asgi.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
│
├── eshop/                     # Main app
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── urls.py
│   ├── views.py
│   ├── forms.py
│   ├── middleware.py
│   ├── emails.py
│   ├── context_processors.py
│   │
│   ├── models/                # Models directory (remove models.py)
│   │   ├── __init__.py        # Import all models here
│   │   ├── users.py           # User model
│   │   ├── products.py        # Product, Cart, CartItem models
│   │   └── orders.py          # Order, OrderItem, ShippingAddress models
│   │
│   ├── management/
│   │   └── commands/
│   │       └── add_otp_device.py
│   │
│   ├── migrations/
│   │   ├── __init__.py
│   │   └── 0001_initial.py
│   │
│   ├── static/
│   │   ├── css/
│   │   ├── js/
│   │   └── img/
│   │
│   ├── templates/
│   │   ├── eshop/
│   │   ├── emails/
│   │   └── two_factor/
│   │
│   ├── tests/
│   │   └── *.py
│   │
│   └── utils/
│       ├── __init__.py
│       ├── json_utils.py
│       └── verification.py
│
├── static/                    # Project-wide static files
├── staticfiles/              # Collected static files
├── media/                    # User uploads
├── logs/
└── templates/
    └── admin/
        └── login.html
```

## Implementation Steps:

1. Create `.gitignore`:
```
*.pyc
__pycache__/
db.sqlite3
*.log
media/
staticfiles/
.env
```

2. Move scripts:
```bash
mkdir scripts
mv create_admin.py scripts/
mv set_password.py scripts/
```

3. Move config files:
```bash
mkdir config
mv certificates config/
mv admin_qrcode.png config/
```

4. Update imports in settings.py:
```python
# Update certificate paths
CERT_FILE = BASE_DIR / 'config' / 'certificates' / 'cert.pem'
KEY_FILE = BASE_DIR / 'config' / 'certificates' / 'key.pem'
```

5. Reorganize models:
- Split models.py into separate files by domain
- Update __init__.py to import all models
- Remove duplicate users.py

6. Consider removing the duplicate nested structure (`secure_eshop/secure_eshop/`)
</content>