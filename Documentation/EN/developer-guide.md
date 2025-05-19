# Developer Guide

This guide provides technical documentation for developers working on the Secure E-Shop project, including code structure, architecture details, and development workflows.

## Project Structure

The Secure E-Shop project follows a standard Django project structure with additional security enhancements:

```
secure-eshop/
├── certificates/        # HTTPS certificates
├── db.sqlite3           # SQLite database
├── eshop/               # Main application
│   ├── migrations/      # Database migrations
│   ├── static/          # Static assets (CSS, JS)
│   │   ├── css/
│   │   ├── img/
│   │   └── js/
│   ├── templates/       # HTML templates
│   ├── admin.py         # Admin site configuration
│   ├── forms.py         # Form definitions
│   ├── models.py        # Database models
│   ├── tests.py         # Test cases
│   ├── urls.py          # URL routing
│   └── views.py         # View functions
├── eshop_project/       # Project configuration
│   ├── settings.py      # Django settings
│   ├── urls.py          # Main URL routing
│   └── wsgi.py          # WSGI configuration
├── media/               # User-uploaded content
├── manage.py            # Django management script
└── requirements.txt     # Package dependencies
```

## Core Architecture

### MTV (Model-Template-View) Pattern

The application follows Django's MTV pattern:

1. **Models (`models.py`)**: Define the database structure
2. **Templates (`templates/`)**: Handle presentation logic
3. **Views (`views.py`)**: Process user requests and return responses

### Key Components

#### Models

The database schema includes:

- **Product**: Store inventory items with name, description, price, and image
- **Cart**: One-to-one relationship with User to track their shopping cart
- **CartItem**: Items in a user's cart with quantity
- **ShippingAddress**: User shipping details (name, address, city, zip code, country)
- **Order**: Records of completed orders with status and total price
- **OrderItem**: Products included in an order with quantity and price at purchase time

Key relationships:
- One user has one cart
- Cart contains multiple cart items
- User can have multiple shipping addresses
- User can place multiple orders
- Orders contain multiple order items

#### Views

Key views implement the application flow:

- **login_view**: Handles user authentication with security against user enumeration
- **catalog_view**: Displays products, processes search queries with XSS protection
- **add_to_cart**: AJAX endpoint for adding products to cart with CSRF protection
- **payment_view**: Two-step checkout process (address entry and order confirmation)

#### Forms

- **LoginForm**: Login form with protection against timing attacks and user enumeration
- **ShippingAddressForm**: Form for collecting shipping information with input sanitization

#### URL Patterns

Main URL patterns:
- `/login/`: User authentication
- `/logout/`: Session termination
- `/`: Product catalog (home page)
- `/add-to-cart/`: AJAX endpoint for cart management
- `/payment/`: Checkout and order processing

## Development Environment Setup

See [INSTALLATION.md](INSTALLATION.md) for detailed setup instructions.

## Development Workflow

### Making Code Changes

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes

3. Run tests to ensure functionality and security:
   ```bash
   python manage.py test
   ```

4. Submit your changes:
   ```bash
   git add .
   git commit -m "Description of changes"
   git push origin feature/your-feature-name
   ```

### Database Changes

When modifying models:

1. Update the model in `models.py`

2. Create migrations:
   ```bash
   python manage.py makemigrations eshop
   ```

3. Apply the migrations:
   ```bash
   python manage.py migrate
   ```

### Static Files

When working with static files:

1. Add/modify files in the app's `static/` directory
2. During development, Django's `runserver` will automatically serve these files
3. For deployment, run `collectstatic`:
   ```bash
   python manage.py collectstatic
   ```

## Application Flow

### User Authentication

1. User navigates to login page
2. Credentials submitted through secure form
3. LoginForm validates with timing attack protection
4. Django authenticates user
5. Session key is cycled for security
6. User redirected to catalog

### Product Browsing and Search

1. Catalog displays all products
2. Search form allows filtering by name/description
3. Search queries sanitized against XSS
4. Results displayed with cart status in footer

### Cart Management

1. User clicks "Add to Cart" on product
2. JavaScript sends AJAX request with CSRF token
3. Server validates request and adds product to cart
4. Cart counter updates without page reload
5. Cart items shown in footer

### Checkout Process

1. User navigates to payment page
2. Shipping address entered through validated form
3. Form data sanitized and stored
4. Order confirmation page shows cart contents and address
5. User confirms order
6. Order saved to database
7. Confirmation email sent to admin
8. Cart emptied
9. User redirected to catalog with success message

## Security Development Guidelines

### Authentication & Authorization

- All views that require authentication should use the `@login_required` decorator
- Additional access controls should be implemented where users can only access their own data
- Always cycle session keys after login using `request.session.cycle_key()`

### Input Validation

- Always sanitize user inputs using bleach:
  ```python
  cleaned_input = bleach.clean(user_input)
  ```
- Validate all form inputs with appropriate validators
- For search queries or other GET parameters, sanitize before use:
  ```python
  search_query = bleach.clean(request.GET.get('q', ''))
  ```

### Database Security

- Always use the Django ORM for database queries
- Never use raw SQL queries directly
- When filtering by user-provided data, sanitize inputs:
  ```python
  products = Product.objects.filter(Q(name__icontains=clean_query))
  ```

### CSRF Protection

- Always include CSRF token in forms:
  ```html
  <form method="post">
      {% csrf_token %}
      <!-- form fields -->
  </form>
  ```
- For AJAX requests, include the CSRF token in headers:
  ```javascript
  const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;
  
  fetch('/api/endpoint/', {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken
      },
      body: JSON.stringify(data)
  })
  ```

### XSS Prevention

- Never use the `|safe` filter or `{% autoescape off %}` without careful consideration
- Use JavaScript's `textContent` instead of `innerHTML` when possible
- Sanitize all user inputs before rendering in templates

### Error Handling

- Use try/except blocks for error-prone operations
- Log errors with proper context
- Return user-friendly error messages without leaking sensitive information

## Testing

### Test Environment Setup

The tests require a special settings file that properly configures the encryption key and test database. A test settings file has been created at `eshop/tests/test_settings.py`.

### Running Tests

Run all tests with the test settings:
```bash
python manage.py test --settings=eshop.tests.test_settings
```

Run a specific test:
```bash
python manage.py test eshop.tests.TestClassName.test_method_name --settings=eshop.tests.test_settings
```

Run tests from a specific module:
```bash
python manage.py test eshop.tests.test_authentication --settings=eshop.tests.test_settings
```

### Alternative Methods

You can also set the DJANGO_SETTINGS_MODULE environment variable:
```bash
export DJANGO_SETTINGS_MODULE=eshop.tests.test_settings
python manage.py test
```

Or create an alias for easier use:
```bash
alias test-eshop="python manage.py test --settings=eshop.tests.test_settings"
test-eshop
```

### Important Notes

**Important**: Always use the test settings when running tests. Without it, tests will fail with encryption key errors:
```
ValueError: FIELD_ENCRYPTION_KEY must be set in production
```

The test settings file (`eshop/tests/test_settings.py`) handles:
- Setting up the encryption key
- Configuring an in-memory test database
- Disabling security features for testing
- Using DEBUG mode for better error messages

### Test Documentation

The test suite includes automatic documentation generation. After each test run, it creates:

1. **Markdown Report** (`test_documentation_YYYYMMDD_HHMMSS.md`):
   - Summary of test results
   - List of successful tests with descriptions
   - Failed tests with error messages
   - Test categorization by type
   - Execution times for each test

2. **JSON Report** (`test_documentation_YYYYMMDD_HHMMSS.json`):
   - Machine-readable test results
   - Complete test metadata
   - Can be used for CI/CD integration

These files are saved in the `eshop/tests/` directory and provide:
- Track record of test runs
- Documentation of what each test verifies
- Performance metrics for test execution
- Test coverage by category

### Writing Tests

The project includes several types of tests:

1. **Model Tests**: Test database models and relationships
2. **View Tests**: Test HTTP responses and view logic
3. **Form Tests**: Test form validation and security
4. **Security Tests**: Test for vulnerabilities like XSS, CSRF, and SQL injection

When adding features, write tests that cover:
- Normal functionality
- Edge cases
- Security concerns

Example test for XSS protection:
```python
def test_search_xss_protection(self):
    self.client.login(username='testuser', password='12345')
    
    # Attempt XSS in search query
    xss_payload = "<script>alert('XSS')</script>"
    response = self.client.get(f'/?q={xss_payload}')
    
    # Verify the response doesn't contain the raw script tag
    self.assertEqual(response.status_code, 200)
    self.assertNotContains(response, xss_payload)
    
    # Verify the search term was sanitized
    self.assertContains(response, "Αποτελέσματα αναζήτησης")
    # Check that it contains the sanitized version
    self.assertContains(response, "&lt;script&gt;")
```

## Useful Commands

```bash
# Run the development server with HTTPS
python manage.py runserver_plus --cert-file=certificates/cert.pem --key-file=certificates/key.pem

# Create migrations
python manage.py makemigrations eshop

# Apply migrations
python manage.py migrate

# Create a superuser
python manage.py createsuperuser

# Set up OTP for admin
python manage.py add_otp_device admin

# Collect static files
python manage.py collectstatic

# Run tests
python manage.py test

# Run specific tests
python manage.py test eshop.tests.TestClassName

# Django shell (with auto-import)
python manage.py shell_plus
```

## Debugging Tips

### Django Debug Toolbar

The project includes Django Debug Toolbar for development. To use it:

1. Ensure `DEBUG = True` in settings.py
2. Access the site and the toolbar will appear on the right side
3. Use it to inspect SQL queries, templates, request data, and more

### Logging

The application uses Python's logging module. View logs in `logs/app.log`:

```bash
tail -f logs/app.log
```

Custom loggers are available for specific components:
- `security`: Logs security-related events
- `orders`: Logs order processing

To use these loggers:
```python
import logging

# Get a logger
logger = logging.getLogger('security')

# Log an event
logger.warning("Suspicious login attempt from IP: %s", ip_address)
```

## Development Best Practices

1. **Follow Security Guidelines**: Always follow the security practices outlined in this document
2. **Code Style**: Adhere to PEP 8 style guidelines
3. **Documentation**: Document security-relevant code with comments
4. **Testing**: Write tests for all new features, especially security features
5. **Dependencies**: Keep dependencies updated to latest secure versions
6. **Secrets Management**: Never commit secrets to version control; use environment variables
7. **Code Reviews**: All security-related changes should undergo peer review

## Troubleshooting Common Issues

### HTTPS Certificate Issues

If you encounter SSL certificate errors:
```bash
# Regenerate the certificates
openssl req -x509 -newkey rsa:4096 -keyout certificates/key.pem -out certificates/cert.pem -days 365 -nodes
```

### Database Migration Conflicts

If you encounter migration conflicts:
```bash
# Reset the database (development only!)
rm db.sqlite3
rm -r eshop/migrations/0*.py
python manage.py makemigrations eshop
python manage.py migrate
```

### Static Files Not Loading

If static files aren't loading properly:
```bash
python manage.py collectstatic --noinput --clear
```

### OTP Setup Issues

If you're having issues with OTP setup:
```bash
# Check if the QR code was generated
ls -la admin_qrcode.png

# Regenerate OTP device
python manage.py add_otp_device admin
```

## Additional Resources

- [Django Documentation](https://docs.djangoproject.com/)
- [Django Security Best Practices](https://docs.djangoproject.com/en/stable/topics/security/)
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- [Django Debug Toolbar](https://django-debug-toolbar.readthedocs.io/)
- [Bleach Documentation](https://bleach.readthedocs.io/)
