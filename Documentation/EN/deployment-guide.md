# Deployment Guide

This guide provides detailed instructions for deploying the Secure E-Shop application on PythonAnywhere.

## Prerequisites

- An existing Secure E-Shop project ready for deployment
- A PythonAnywhere account (free or paid)
- Your project hosted on GitHub, GitLab, or Bitbucket (recommended)

## Step 1: Upload Your Code to PythonAnywhere

### Using Git (Recommended)

If your code is on GitHub, GitLab, or Bitbucket, clone it from a Bash console:

```bash
# Set up SSH key if you haven't already
# See: https://help.pythonanywhere.com/pages/ExternalVCS

# Clone your repository
git clone git@github.com:yourusername/secure-eshop.git
```

### Important Note About Directory Names

Python module names cannot contain hyphens. If your project directory has a hyphen (e.g., `secure-eshop`), you must either:
- Rename it to use underscores (`secure_eshop`)
- Create a symlink: `ln -s secure-eshop secure_eshop`

## Step 2: Create a Virtual Environment

In your Bash console, create a virtualenv using the built-in `mkvirtualenv` command:

```bash
# Create virtualenv (using mkvirtualenv for easier management)
mkvirtualenv --python=/usr/bin/python3.10 secure-eshop-virtualenv

# Or if you prefer a specific Python version:
mkvirtualenv --python=/usr/bin/python3.13 secure-eshop-virtualenv

# Your prompt will change to show the virtualenv is active:
(secure-eshop-virtualenv)$ pip install django

# Install all dependencies from requirements.txt:
(secure-eshop-virtualenv)$ pip install -r requirements.txt
```

**Note**: If you see `mkvirtualenv: command not found`, check out [Installing Virtualenv Wrapper](https://help.pythonanywhere.com/pages/InstallingVirtualenvWrapper).

## Step 3: Configure the Web App

### Create a Web App with Manual Configuration

1. Go to the **Web** tab on PythonAnywhere
2. Click **Add a new web app**
3. Choose **Manual configuration** (not Django)
   - **Important**: Choose Manual Configuration, not "Django" - that's only for new projects
4. Select your Python version (same as your virtualenv)
5. Click through to create the web app

### Configure Virtualenv

1. In the Web tab, scroll to the "Virtualenv" section
2. Enter the name of your virtualenv: `secure-eshop-virtualenv`
3. Click OK (it will auto-complete to the full path)

### Set Working Directory

1. In the "Code" section, set both:
   - Source code: `/home/username/secure-eshop`
   - Working directory: `/home/username/secure-eshop`

## Step 4: Configure the WSGI File

### Edit the WSGI File

1. In the Web tab, click on the WSGI configuration file link
   - It will be named like `/var/www/username_pythonanywhere_com_wsgi.py`
2. Delete everything in the file
3. Replace with the Django configuration:

```python
# +++++++++++ DJANGO +++++++++++
# To use your own Django app use code like this:
import os
import sys

# assuming your Django settings file is at '/home/username/secure-eshop/eshop_project/settings.py'
path = '/home/username/secure-eshop'
if path not in sys.path:
    sys.path.insert(0, path)

os.environ['DJANGO_SETTINGS_MODULE'] = 'eshop_project.settings'

# then:
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
```

Replace:
- `username` with your PythonAnywhere username
- `/home/username/secure-eshop` with the actual path to your project (contains `manage.py`)
- `eshop_project.settings` with your actual settings module path

## Step 5: Set Up MySQL Database

### Create a MySQL Database

1. Go to the **Databases** tab
2. Create a database (e.g., `username$secure_eshop`)
3. Note your database credentials:
   - Host: `username.mysql.pythonanywhere-services.com`
   - Username: `username`
   - Database name: `username$secure_eshop`
   - Password: (set by you)

### Configure Django Database Settings

Install MySQL client:
```bash
pip install mysqlclient
```

Update your `.env` file with database settings (see Environment Variables section below).

## Step 6: Configure Static Files

### Update settings.py

Ensure your `settings.py` has the following configuration:

```python
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# For development, if you have app-specific static files
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'eshop/static'),
]
```

### Collect Static Files

```bash
cd /home/username/secure-eshop
workon secure-eshop-virtualenv
python manage.py collectstatic --noinput
```

### Configure Static Files on PythonAnywhere

1. Go to the **Web** tab
2. Scroll to **Static files**
3. Add mappings:
   - URL: `/static/`
   - Directory: `/home/username/secure-eshop/staticfiles`
   - URL: `/media/` (if you have media files)
   - Directory: `/home/username/secure-eshop/media`

## Step 7: Environment Variables (Security)

### Install python-dotenv

```bash
pip install python-dotenv
```

### Create .env File

Create `/home/username/secure-eshop/.env`:

```ini
# Django settings
SECRET_KEY=your-secret-key-here
DEBUG=False
ALLOWED_HOSTS=username.pythonanywhere.com

# Database settings
DB_NAME=username$secure_eshop
DB_USER=username
DB_PASSWORD=your-mysql-password
DB_HOST=username.mysql.pythonanywhere-services.com
DB_PORT=3306

# Email settings
EMAIL_HOST_USER=your-email@example.com
EMAIL_HOST_PASSWORD=your-email-password
```

**Important Security Step**: Set proper file permissions: `chmod 600 .env`

### Ensure settings.py Uses Environment Variables

Make sure your `settings.py` loads and uses environment variables:

```python
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables
load_dotenv(os.path.join(BASE_DIR, '.env'))

SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', '').split(',')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST'),
        'PORT': os.getenv('DB_PORT', '3306'),
        'OPTIONS': {
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
            'charset': 'utf8mb4',
        }
    }
}
```

## Step 8: Configure HTTPS

Enable **Force HTTPS** in the Web tab security settings.

## Step 9: Run Migrations and Create Superuser

```bash
cd /home/username/secure-eshop
workon secure-eshop-virtualenv
python manage.py migrate
python manage.py createsuperuser
```

## Step 10: Set Up OTP for Admin

If you're using OTP for admin authentication, set it up:

```bash
python manage.py add_otp_device admin
```

The QR code will be generated in the project root. You'll need to download it to scan with your authenticator app.

## Step 11: Reload Your Web App

Click the green **Reload** button in the Web tab.

## Maintenance Tasks

### Updating Your Application

1. Pull latest changes
2. Activate virtual environment
3. Install new dependencies: `pip install -r requirements.txt`
4. Run migrations: `python manage.py migrate`
5. Collect static files: `python manage.py collectstatic`
6. Reload web app

### Viewing Logs

- **Error log**: Web tab → Log files → Error log
- **Server log**: Web tab → Log files → Server log
- **Access log**: Web tab → Log files → Access log

### Database Backups

Use PythonAnywhere's scheduled tasks to create regular backups:
```bash
mysqldump -u username -h username.mysql.pythonanywhere-services.com 'username$secure_eshop' > backup.sql
```

## Production Checklist

- [ ] `DEBUG = False` in production
- [ ] Secret key is unique and secure
- [ ] Database passwords are strong
- [ ] Static files are properly configured
- [ ] HTTPS is enabled
- [ ] Error logging is configured
- [ ] Backups are scheduled
- [ ] Environment variables are used for sensitive data
- [ ] `.env` file is not in version control
- [ ] File permissions are properly set

## Common Issues and Solutions

### Issue: ModuleNotFoundError
**Error**: `ModuleNotFoundError: No module named 'your-app'`
**Solution**: Python modules can't have hyphens. Rename your directory or create a symlink.

### Issue: Static Files Not Loading
**Error**: `The resource was blocked due to MIME type mismatch`
**Solution**: 
- Check static files are collected to the right directory
- Verify static files mapping in Web tab points to correct location
- Ensure you've run `collectstatic`

### Issue: Database Connection Errors
**Solution**: 
- Verify database credentials
- Ensure database name follows format `username$dbname`
- Check you've created the database in the Databases tab

### Issue: Database needs reset
**Solution**:
- Open mySQL terminal
- DROP DATABASE `georgeg$default`;
- CREATE DATABASE `georgeg$default` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
- In secure_eshop dir
    - python manage.py migrate
    - python manage.py createsuperuser
    - python manage.py add_otp_device {admin_user}
- use georgeg$default; show tables; to check; (in SQL terminal)
- Reload from web app gui

### Issue: 500 Internal Server Error
**Solution**: 
1. Check the error log (link in Web tab)
2. Ensure `DEBUG=False` for production
3. Verify all dependencies are installed in virtualenv
4. Check for syntax errors in settings.py

## Additional Resources

- [Official PythonAnywhere deployment guide](https://help.pythonanywhere.com/pages/DeployExistingDjangoProject/)
- [Django Deployment Checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/)


## If You've done the above and just pulled from repository, open terminal and

cd CDS204_Project3/
git pull origin main
git stash (if above fails you have stashed changes - usually settings.py)
git pull origin main
cd secure_eshop/eshop_project/
nano settings.py (change databases - change debug to false)
cd ..  (now in CDS204_Project3/secure_eshop)
source ../.venv/bin/activate
python manage.py makemigrations 
python manage.py makemigrations eshop
python manage.py migrate
python manage.py createsuperuser;
python manage.py add_otp_device admin
python manage.py collectstatic