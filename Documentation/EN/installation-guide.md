# Installation Guide

This guide provides detailed instructions for setting up the Secure E-Shop application in a local development environment.

## Prerequisites

- Python 3.8 or higher
- Git
- OpenSSL for certificate generation
- (Optional) A Gmail account for email functionality

## Step 1: Clone the Repository

```bash
git clone <repository-url>
cd secure-eshop
```

## Step 2: Set Up Python Environment

Create and activate a virtual environment:

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

## Step 3: Install Dependencies

Install all required packages:

```bash
pip install -r requirements.txt
```

## Step 4: Create Log Directory

Ensure the logs directory exists:

```bash
mkdir -p logs
touch logs/app.log
```

## Step 5: Configure Environment Variables (Optional)

Create a `.env` file in the project root for email functionality:

```bash
# Create .env file
touch .env

# Add email configuration (edit with your details)
echo "EMAIL_HOST_USER=youremail@gmail.com" >> .env
echo "EMAIL_HOST_PASSWORD=your-app-password" >> .env
```

Note: For Gmail, you'll need to use an "App Password" rather than your account password. You can generate one in your Google Account security settings.

## Step 6: Set Up the Database

Run database migrations:

```bash
python manage.py migrate
```

## Step 7: Create Admin User

Create a superuser for admin access:

```bash
python manage.py createsuperuser
```

Follow the prompts to create your admin username, email, and password.

## Step 8: Set Up Two-Factor Authentication for Admin

Set up OTP for the admin user:

```bash
python manage.py add_otp_device admin
```

This will generate a QR code at `admin_qrcode.png` in the project root that you can scan with an authenticator app like Google Authenticator, Microsoft Authenticator, or Authy.

For more details, see the [Admin Guide](ADMIN_GUIDE.md).

## Step 9: Generate SSL Certificate

Generate a self-signed SSL certificate for HTTPS:

```bash
mkdir -p config/certificates
openssl req -x509 -newkey rsa:4096 -keyout config/certificates/key.pem -out config/certificates/cert.pem -days 365 -nodes
```

When prompted, provide the required information or press Enter to use defaults.

## Step 10: Start the Development Server

Start the development server with SSL:

```bash
python manage.py runserver_plus --cert-file=config/certificates/cert.pem --key-file=config/certificates/key.pem
```

## Step 11: Access the Application

Open your browser and navigate to:
- **Website**: https://localhost:8000/
- **Admin Interface**: https://localhost:8000/admin/ (now protected with two-factor authentication)

## Browser Security Warning

When you first access the site, your browser will warn about the self-signed certificate. This is expected in development. You can proceed by:
- In Chrome: Click "Advanced" and then "Proceed to localhost (unsafe)"
- In Firefox: Click "Advanced" > "Accept the Risk and Continue"
- In Safari: Click "Show Details" > "visit this website"

## Troubleshooting

- **Certificate Issues**: Ensure certificates are correctly generated and the paths match in the runserver command
- **Database Errors**: Try deleting `db.sqlite3` and running migrations again
- **Static Files Not Loading**: Run `python manage.py collectstatic`
- **Email Errors**: Check your `.env` configuration and Gmail security settings
- **OTP Issues**: If you're having issues with OTP authentication, you can regenerate the OTP device using the management command

## Common Development Commands

```bash
# Run tests
python manage.py test

# Run specific test
python manage.py test eshop.tests.TestClassName.test_method_name

# Create migrations after model changes
python manage.py makemigrations eshop

# Apply migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic
```

For more details on day-to-day development, refer to the [Developer Guide](DEVELOPER_GUIDE.md).
