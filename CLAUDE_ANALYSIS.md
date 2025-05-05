# Secure E-Shop Project Analysis

This document contains a comprehensive analysis of the Secure E-Shop Django project, intended as a reference for future development and maintenance.

## Project Overview

Secure E-Shop is a Django 5.2 e-commerce application focused on implementing security best practices. The application includes:

- User authentication
- Product catalog with search functionality
- Shopping cart system
- Checkout and order processing
- Shipping address management

## Project Structure

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

## Core Components

### 1. Models (models.py)

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

### 2. Views (views.py)

Key views implement the application flow:

- **login_view**: Handles user authentication with security against user enumeration
- **catalog_view**: Displays products, processes search queries with XSS protection
- **add_to_cart**: AJAX endpoint for adding products to cart with CSRF protection
- **payment_view**: Two-step checkout process (address entry and order confirmation)

### 3. Forms (forms.py)

- **LoginForm**: Login form with protection against timing attacks and user enumeration
- **ShippingAddressForm**: Form for collecting shipping information with input sanitization

### 4. URLs (urls.py)

Main URL patterns:
- `/login/`: User authentication
- `/logout/`: Session termination
- `/`: Product catalog (home page)
- `/add-to-cart/`: AJAX endpoint for cart management
- `/payment/`: Checkout and order processing

### 5. Templates

- **base.html**: Base template with CSP headers and layout structure
- **login.html**: Authentication form with CSRF protection
- **catalog.html**: Product display with search functionality
- **payment.html**: Checkout process with shipping form and confirmation

### 6. Static Files

- **CSS**: Styling for the application
- **JS**: cart.js for AJAX-based cart management
- **Images**: Product images and application assets

## Security Measures

### Authentication Security

- **Argon2 Password Hashing**: Strongest available password hashing algorithm
- **Protection Against Timing Attacks**: Constant-time comparison and deliberate delays
- **User Enumeration Prevention**: Generic error messages and consistent response times
- **Brute Force Protection**: django-axes with 5-attempt limit and 1-hour lockout

### Data Protection

- **Input Sanitization**: All user inputs sanitized with bleach library
- **CSRF Protection**: Django's CSRF middleware with secure token handling in forms and AJAX
- **XSS Prevention**: Template auto-escaping and Content Security Policy
- **SQL Injection Prevention**: Exclusive use of Django ORM with parameterized queries

### Transport Security

- **HTTPS Only**: Enforced SSL/TLS with SECURE_SSL_REDIRECT
- **Secure Cookies**: SESSION_COOKIE_SECURE and CSRF_COOKIE_SECURE enabled
- **HSTS**: HTTP Strict Transport Security implementation
- **Content Security Policy**: Restricts resource loading to trusted sources

### Session Management

- **Session Key Cycling**: Session IDs refreshed after login (request.session.cycle_key())
- **Secure Session Settings**: HttpOnly and SameSite attributes for session cookies
- **Session Data Cleanup**: Proper deletion of session data after order completion

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

## Known Limitations

As noted in the security documentation:

- Development environment uses self-signed certificates
- SQLite database (not ideal for production)
- No rate limiting for API endpoints
- Limited address validation
- Simulated payment system (no actual payment processor)
- Limited logging and monitoring
- No CAPTCHA implementation

## Running the Application

1. Activate virtual environment: 
   - macOS/Linux: `source venv/bin/activate` 
   - Windows: `venv\Scripts\activate`

2. Install dependencies: 
   `pip install -r requirements.txt`

3. Run migrations: 
   `python manage.py migrate`

4. Create superuser (if needed): 
   `python manage.py createsuperuser`

5. Generate certificates (if needed):
   ```
   mkdir -p certificates
   openssl req -x509 -newkey rsa:4096 -keyout certificates/key.pem -out certificates/cert.pem -days 365 -nodes
   ```

6. Run server with HTTPS: 
   `python manage.py runserver_plus --cert-file=certificates/cert.pem --key-file=certificates/key.pem`

## Development Guidelines

- Always sanitize user inputs using bleach
- Follow Django's ORM patterns to prevent SQL injection
- Include CSRF tokens in all forms and AJAX requests
- Maintain secure settings (HTTPS, secure cookies)
- Test thoroughly for security vulnerabilities
- Keep dependencies updated to latest secure versions