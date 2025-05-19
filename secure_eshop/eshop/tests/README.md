# Test Suite Documentation

This directory contains the test suite for the Secure E-Shop application.

## Running Tests

**Important**: Always use the test settings file to run tests:

```bash
python manage.py test --settings=eshop_project.test_settings
```

Without the test settings, tests will fail with encryption key errors.

## Automatic Documentation

The test suite automatically generates documentation after each run:

- **`test_documentation_YYYYMMDD_HHMMSS.md`**: Human-readable test report
- **`test_documentation_YYYYMMDD_HHMMSS.json`**: Machine-readable results

These files include:
- Test summary and success rate
- Detailed results for each test
- Test categorization by type
- Execution times
- Error messages for failed tests

## Test Modules

- `test_authentication.py`: Tests for user authentication, login/logout, and sessions
- `test_data_processing.py`: Tests for encryption/decryption and data processing
- `test_validation.py`: Tests for form validation and input sanitization
- `test_simple.py`: Basic tests to verify test environment setup

## Test Configuration

The test settings file (`eshop_project/test_settings.py`) includes:
- Automatic encryption key generation
- In-memory SQLite database for fast tests
- Debug mode enabled for better error messages
- Security features disabled for testing

## Common Issues

If you see this error:
```
ValueError: FIELD_ENCRYPTION_KEY must be set in production
```

Make sure you're using the test settings:
```bash
python manage.py test --settings=eshop_project.test_settings
```

## Writing New Tests

When adding new tests:
1. Import required test utilities
2. Set up test data in `setUp()` method
3. Write descriptive test names starting with `test_`
4. Clean up resources in `tearDown()` if needed
5. Use assertions to verify expected behavior

Example:
```python
def test_user_can_login(self):
    response = self.client.post(reverse('eshop:login'), {
        'username': 'testuser',
        'password': 'testpass'
    })
    self.assertEqual(response.status_code, 302)
```