# Secure E-Shop

A secure e-commerce application developed with Django 5.2 LTS, designed with security best practices at its core.

## Features

- **User Authentication**: Secure login system with protection against timing attacks and user enumeration
- **Product Catalog**: Browse and search products with secure input handling
- **Shopping Cart**: Add products to cart with AJAX (no page reload required)
- **Checkout Process**: Complete orders with shipping information
- **Admin Interface**: Protected with Two-Factor Authentication (added May 14, 2025)
- **Security Focus**: Comprehensive security measures against common web vulnerabilities

## Documentation

- [Installation Guide](INSTALLATION.md) - Setup instructions for local development
- [Deployment Guide](DEPLOYMENT.md) - Instructions for deploying to PythonAnywhere
- [Security Documentation](SECURITY.md) - Overview of security features and protections
- [Admin Guide](ADMIN_GUIDE.md) - Guide for administrators, including OTP setup
- [Developer Guide](DEVELOPER_GUIDE.md) - Technical documentation for developers

## Quick Start

### Prerequisites
- Python 3.8 or higher
- Git
- OpenSSL for certificate generation

### Setup
```bash
# Clone the repository
git clone <repository-url>
cd secure-eshop

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create log directory
mkdir -p logs
touch logs/app.log

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Generate SSL certificate
mkdir -p config/certificates
openssl req -x509 -newkey rsa:4096 -keyout config/certificates/key.pem -out config/certificates/cert.pem -days 365 -nodes

# Start server with HTTPS
python manage.py runserver_plus --cert-file=config/certificates/cert.pem --key-file=config/certificates/key.pem
```

### Access the Application
- **Website**: https://localhost:8000/
- **Admin Interface**: https://localhost:8000/admin/ (protected with two-factor authentication)

## Recent Updates

- **May 14, 2025**: Added Two-Factor Authentication (2FA) for the admin panel
- **May 11, 2025**: Updated documentation and instructions for PythonAnywhere deployment
- **May 5, 2025**: Completed security analysis of the application

## Development Status

This application was developed as a project for the CDS204 course. It implements a basic but secure e-commerce platform with a focus on security best practices rather than comprehensive e-commerce functionality.

## License

[MIT License](LICENSE)
