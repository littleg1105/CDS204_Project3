# Complete Guide: Deploying Django on PythonAnywhere

This comprehensive guide covers the complete process of deploying an existing Django application on PythonAnywhere, including common issues and their solutions. It combines official PythonAnywhere documentation with real-world troubleshooting experience.

## Overview

Deploying Django on PythonAnywhere is similar to running it on your local PC - you'll use a virtualenv and have a copy of your code that you can edit and commit to version control. The main difference is that instead of using `manage.py runserver`, you'll create a Web app via the Web tab and configure it with a WSGI file to make your site live on the public internet.

## Prerequisites

- An existing Django project ready for deployment
- A PythonAnywhere account (free or paid)
- Your project uploaded to PythonAnywhere (via git or file upload)

## Step 1: Upload Your Code to PythonAnywhere

### 1.1 Using Git (Recommended)

If your code is on GitHub, GitLab, or Bitbucket, clone it from a Bash console:

```bash
# Set up SSH key if you haven't already
# See: https://help.pythonanywhere.com/pages/ExternalVCS

# Clone your repository
git clone git@github.com:yourusername/yourproject.git
```

### 1.2 Alternative Upload Methods

See the [uploading and downloading files](/pages/UploadingAndDownloadingFiles) help page for other methods like ZIP upload or direct file editing.

### 1.3 Verify Your Project Structure

Your Django project should have a structure similar to this:

```
/home/username/your_project/
├── manage.py
├── your_app/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
└── other_apps/
```

**Important**: Note three key pieces of information you'll need later:
1. The path to your Django project's top folder (contains `manage.py`): e.g., `/home/username/mysite`
2. The name of your project folder (contains `settings.py`): e.g., `mysite`
3. The name of your virtualenv: e.g., `mysite-virtualenv`

### 1.4 Important Note About Directory Names

Python module names cannot contain hyphens. If your project directory has a hyphen (e.g., `secure-eshop`), you must either:
- Rename it to use underscores (`secure_eshop`)
- Create a symlink: `ln -s secure-eshop secure_eshop`

## Step 2: Create a Virtual Environment

In your Bash console, create a virtualenv using the built-in `mkvirtualenv` command:

```bash
# Create virtualenv (using mkvirtualenv for easier management)
mkvirtualenv --python=/usr/bin/python3.10 mysite-virtualenv

# Or if you prefer a specific Python version:
mkvirtualenv --python=/usr/bin/python3.13 mysite-virtualenv

# Your prompt will change to show the virtualenv is active:
(mysite-virtualenv)$ pip install django

# Or if you have a requirements.txt:
(mysite-virtualenv)$ pip install -r requirements.txt
```

**Note**: If you see `mkvirtualenv: command not found`, check out [Installing Virtualenv Wrapper](/pages/InstallingVirtualenvWrapper).

**Warning**: Django installation might take a while due to filesystem access speeds on PythonAnywhere.

## Step 3: Configure the Web App

### 3.1 Create a Web App with Manual Configuration

1. Go to the **Web** tab on PythonAnywhere
2. Click **Add a new web app**
3. Choose **Manual configuration** (not Django)
   - **Important**: Choose Manual Configuration, not "Django" - that's only for new projects
4. Select your Python version (same as your virtualenv)
5. Click through to create the web app

### 3.2 Configure Virtualenv

1. In the Web tab, scroll to the "Virtualenv" section
2. Enter the name of your virtualenv: `mysite-virtualenv`
3. Click OK (it will auto-complete to the full path)

### 3.3 Optional: Set Working Directory

For convenience, set your project paths:
1. In the "Code" section, set both:
   - Source code: `/home/username/mysite`
   - Working directory: `/home/username/mysite`
2. This gives you a convenient link to your source files from the web tab

## Step 4: Configure the WSGI File

### 4.1 Understanding WSGI Files

**Important**: Your Django project has its own `wsgi.py` file, but PythonAnywhere ignores it. You need to edit the WSGI file that PythonAnywhere creates for you.

### 4.2 Edit the WSGI File

1. In the Web tab, click on the WSGI configuration file link
   - It will be named like `/var/www/username_pythonanywhere_com_wsgi.py`
2. Delete everything in the file
3. Replace with the Django configuration:

```python
# +++++++++++ DJANGO +++++++++++
# To use your own Django app use code like this:
import os
import sys

# assuming your Django settings file is at '/home/username/mysite/mysite/settings.py'
path = '/home/username/mysite'
if path not in sys.path:
    sys.path.insert(0, path)

os.environ['DJANGO_SETTINGS_MODULE'] = 'mysite.settings'

# then:
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
```

Replace:
- `username` with your PythonAnywhere username
- `/home/username/mysite` with the path to your project (contains `manage.py`)
- `mysite.settings` with your actual settings module path

### 4.3 Common WSGI Mistakes to Avoid

- Don't confuse this with your project's `wsgi.py` file
- Make sure the path points to the directory containing `manage.py`
- Ensure `DJANGO_SETTINGS_MODULE` matches your project structure
- Don't forget to save and reload after changes

## Step 5: Set Up MySQL Database

### 5.1 Create a MySQL Database

1. Go to the **Databases** tab
2. Create a database (e.g., `username$project`)
3. Note your database credentials:
   - Host: `username.mysql.pythonanywhere-services.com`
   - Username: `username`
   - Database name: `username$project`
   - Password: (set by you)

### 5.2 Configure Django Database Settings

Install MySQL client:
```bash
pip install mysqlclient
```

Update your `settings.py`:
```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'username$project',
        'USER': 'username',
        'PASSWORD': 'your_mysql_password',
        'HOST': 'username.mysql.pythonanywhere-services.com',
        'PORT': '3306',
        'OPTIONS': {
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
            'charset': 'utf8mb4',
        }
    }
}
```

### 5.3 Migrate Database

Navigate to your project directory and run migrations:

```bash
cd /home/username/mysite
workon mysite-virtualenv  # Activate your virtualenv
python manage.py migrate
python manage.py createsuperuser
```

If you have existing data in SQLite that you want to migrate:
```bash
# Dump data from SQLite (before changing to MySQL)
python manage.py dumpdata > data.json

# After switching to MySQL and running migrations
python manage.py loaddata data.json
```

## Step 6: Configure Static Files

### 6.1 Update settings.py

```python
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# For development, if you have app-specific static files
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'app_name/static'),
]
```

### 6.2 Collect Static Files

```bash
cd /home/username/mysite
workon mysite-virtualenv
python manage.py collectstatic --noinput
```

This will copy all static files (including Django admin files) to your STATIC_ROOT.

### 6.3 Configure Static Files on PythonAnywhere

1. Go to the **Web** tab
2. Scroll to **Static files**
3. Add mappings:
   - URL: `/static/`
   - Directory: `/home/username/your_project/staticfiles`
   - URL: `/media/` (if you have media files)
   - Directory: `/home/username/your_project/media`

**Note**: The directory path must match where `collectstatic` actually puts your files.

## Step 7: Environment Variables (Security)

### 7.1 Install python-dotenv

```bash
pip install python-dotenv
```

### 7.2 Create .env File

Create `/home/username/your_project/.env`:

```ini
# Django settings
SECRET_KEY=your-secret-key-here
DEBUG=False
ALLOWED_HOSTS=username.pythonanywhere.com

# Database settings
DB_NAME=username$project
DB_USER=username
DB_PASSWORD=your-mysql-password
DB_HOST=username.mysql.pythonanywhere-services.com
DB_PORT=3306

# Email settings (optional)
EMAIL_HOST_USER=your-email@example.com
EMAIL_HOST_PASSWORD=your-email-password
```

**Important**: Ensure each variable is on its own line with no extra spaces or comments on the same line.

### 7.3 Update settings.py

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

### 7.4 Security Best Practices

1. Add `.env` to `.gitignore`
2. Set proper file permissions: `chmod 600 .env`
3. Generate a new secret key for production:
   ```python
   from django.core.management.utils import get_random_secret_key
   print(get_random_secret_key())
   ```

## Step 8: Final Configuration

### 8.1 Update Virtual Environment Path

In the **Web** tab, set your virtualenv path:
```
/home/username/your_project/.venv
```

### 8.2 Configure HTTPS (Optional but Recommended)

Enable **Force HTTPS** in the Web tab security settings.

### 8.3 Reload Your Web App

Click the green **Reload** button in the Web tab.

## Common Issues and Solutions

### Issue 1: ModuleNotFoundError
**Error**: `ModuleNotFoundError: No module named 'your-app'`
**Solution**: Python modules can't have hyphens. Rename your directory or create a symlink.

### Issue 2: Static Files Not Loading (MIME Type Error)
**Error**: `The resource was blocked due to MIME type mismatch`
**Solution**: 
- Check static files are collected to the right directory
- Verify static files mapping in Web tab points to correct location
- Ensure you've run `collectstatic`

### Issue 3: ImportError or sys.path Issues
**Error**: `ImportError: No module named mysite.settings`
**Solution**: Check the [debugging import errors](/pages/DebuggingImportError) guide. Common fixes:
- Verify your WSGI file paths
- Ensure project directory is in sys.path
- Check DJANGO_SETTINGS_MODULE value

### Issue 4: Database Connection Errors
**Solution**: 
- Verify database credentials
- Ensure database name follows format `username$dbname`
- Check you've created the database in the Databases tab

### Issue 5: 500 Internal Server Error
**Solution**: 
1. Check the error log (link in Web tab)
2. Ensure `DEBUG=False` for production
3. Verify all dependencies are installed in virtualenv
4. Check for syntax errors in settings.py

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
mysqldump -u username -h username.mysql.pythonanywhere-services.com 'username$project' > backup.sql
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

## Additional Resources

### PythonAnywhere-Specific Help
- [Official deployment guide](https://help.pythonanywhere.com/pages/DeployExistingDjangoProject/)
- [Debugging import errors](https://help.pythonanywhere.com/pages/DebuggingImportError)
- [Static files with Django](https://help.pythonanywhere.com/pages/DjangoStaticFiles)
- [Environment variables for web apps](https://help.pythonanywhere.com/pages/environment-variables-for-web-apps)
- [Debugging web app errors](https://help.pythonanywhere.com/pages/#im-looking-at-an-error-message-in-my-web-app)

### Django Resources
- [Django Deployment Checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/)
- [Django Static Files Documentation](https://docs.djangoproject.com/en/stable/howto/static-files/)

### Quick Links for Your Web App
- Error log: Web tab → Log files → Error log
- WSGI configuration: Web tab → Code → WSGI configuration file
- Static files setup: Web tab → Static files

Remember to always check the error logs first when debugging issues!