# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build/Run Commands
- Activate venv: `source venv/bin/activate` (macOS/Linux) or `venv\Scripts\activate` (Windows)
- Install requirements: `pip install -r requirements.txt`
- Run migrations: `python manage.py migrate`
- Run server: `python manage.py runserver_plus --cert-file=certificates/cert.pem --key-file=certificates/key.pem`
- Run a specific test: `python manage.py test eshop.tests.TestClassName.test_method_name`

## Code Style Guidelines
- **Imports**: Group Django imports first, followed by third-party, then local app imports
- **Formatting**: Use 4 spaces for indentation, 80-character line limit
- **Security**: Always sanitize user inputs with `bleach.clean()`, never raw SQL
- **Forms**: Validate and clean all form inputs, use Django's built-in validators
- **Error Handling**: Use try/except blocks with specific exceptions, log errors
- **Django Best Practices**: 
  - Use Django ORM for database operations
  - Apply CSRF protection to all forms
  - Use secure settings (HTTPS, secure cookies)
  - Implement Argon2 password hashing
  - Apply Content Security Policy headers