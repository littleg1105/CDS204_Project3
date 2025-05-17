# Database Encryption Guide

This guide explains the encryption implementation for the Secure E-Shop application.

## Overview

The application now implements:
1. **Data in Transit**: SSL/TLS encryption for database connections
2. **Data at Rest**: Field-level encryption for sensitive personal data

## SSL/TLS Configuration (Data in Transit)

### MySQL Configuration
```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        # ... other settings ...
        'OPTIONS': {
            'ssl': {
                'ca': os.getenv('DB_SSL_CA'),  # Path to CA certificate
            } if os.getenv('DB_SSL_CA') else None,
        }
    }
}
```

### PostgreSQL Configuration
```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        # ... other settings ...
        'OPTIONS': {
            'sslmode': os.getenv('DB_SSL_MODE', 'require'),
        }
    }
}
```

### Environment Variables for SSL/TLS
Set these in your `.env` file:

#### For MySQL:
```
DB_SSL_CA=/path/to/ca-cert.pem
DB_SSL_CERT=/path/to/client-cert.pem    # Optional if client certificates required
DB_SSL_KEY=/path/to/client-key.pem      # Optional if client certificates required
```

#### For PostgreSQL:
```
DB_SSL_MODE=require                     # Options: disable, allow, prefer, require, verify-ca, verify-full
DB_SSL_CERT=/path/to/client-cert.pem    # Optional
DB_SSL_KEY=/path/to/client-key.pem      # Optional  
DB_SSL_CA=/path/to/ca-cert.pem          # Required for verify-ca or verify-full modes
```

## Field-Level Encryption (Data at Rest)

### Encrypted Fields

#### ShippingAddress Model
The following sensitive fields are encrypted:
- `name` - Customer full name
- `address` - Street address
- `phone` - Phone number
- `email` - Email address

#### CustomUser Model
The following sensitive fields are encrypted:
- `email` - User email address
- `first_name` - User first name
- `last_name` - User last name

Note: The username field is not encrypted as it's used for authentication and needs to be searchable.

### How It Works
1. Data is encrypted using Fernet symmetric encryption before saving to database
2. Data is automatically decrypted when retrieved from database
3. Encryption is transparent to the application logic

### Setting Up Encryption

1. **Generate an encryption key**:
   ```python
   from cryptography.fernet import Fernet
   key = Fernet.generate_key()
   print(key.decode())  # Save this key securely!
   ```

2. **Configure environment variables**:
   
   Add to your `.env` file:
   ```
   # Field-level encryption key (required)
   FIELD_ENCRYPTION_KEY=your-generated-key-here
   
   # SSL/TLS Configuration for MySQL (optional)
   DB_SSL_CA=/path/to/ca-cert.pem
   DB_SSL_CERT=/path/to/client-cert.pem    # Optional if client certificates required
   DB_SSL_KEY=/path/to/client-key.pem      # Optional if client certificates required
   
   # SSL/TLS Configuration for PostgreSQL (optional)
   DB_SSL_MODE=require                     # Options: disable, allow, prefer, require, verify-ca, verify-full
   DB_SSL_CERT=/path/to/client-cert.pem    # Optional
   DB_SSL_KEY=/path/to/client-key.pem      # Optional  
   DB_SSL_CA=/path/to/ca-cert.pem          # Required for verify-ca or verify-full modes
   ```

3. **Apply database migrations**:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

4. **Encrypt existing data** (if you have existing records):
   ```bash
   python manage.py encrypt_existing_data
   ```

## Important Security Notes

1. **Never commit encryption keys to version control**
2. **Store the encryption key securely** (use environment variables, secrets manager, etc.)
3. **Backup your encryption keys** - without them, encrypted data cannot be recovered
4. **Use different keys for different environments** (development, staging, production)

## Migration from Unencrypted to Encrypted

If you have existing data:

1. Make sure you have a backup of your database
2. Set the `FIELD_ENCRYPTION_KEY` environment variable
3. Run database migrations: `python manage.py migrate`
4. Run the encryption command: `python manage.py encrypt_existing_data`

The custom field implementation handles the transition gracefully - if decryption fails, it returns the original value (useful during migration).

## Testing

To verify encryption is working:

1. Create a new shipping address through the application
2. Check the database directly - personal data should appear as encrypted strings
3. View the address in the application - data should appear decrypted

## Performance Considerations

- Field-level encryption adds minimal overhead for individual record operations
- Bulk operations may be slower due to encryption/decryption overhead
- Consider indexing strategies - encrypted fields cannot be used in database indexes

## Example .env Configuration

Here's a complete example of the encryption settings in your `.env` file:

```
# Django settings
SECRET_KEY=your-django-secret-key
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1,yourdomain.com

# Database settings
DB_NAME=secure_eshop_db
DB_USER=eshop_user
DB_PASSWORD=strong_password_here
DB_HOST=localhost
DB_PORT=5432

# Field-level encryption (REQUIRED - generate with Fernet)
FIELD_ENCRYPTION_KEY=gAAAAABhZ8Kj2_N3QzF-your-actual-key-here

# For MySQL with SSL
DB_SSL_CA=/etc/mysql/ssl/ca-cert.pem
# DB_SSL_CERT=/etc/mysql/ssl/client-cert.pem  # Uncomment if needed
# DB_SSL_KEY=/etc/mysql/ssl/client-key.pem    # Uncomment if needed

# For PostgreSQL with SSL
# DB_SSL_MODE=require
# DB_SSL_CA=/etc/postgresql/ssl/ca-cert.pem
```

## Compliance

This implementation helps meet data protection requirements:
- GDPR compliance for personal data protection
- PCI DSS requirements for payment card data (if implemented)
- General security best practices for sensitive data

## Implementation Details

### How We Implemented Field-Level Encryption

1. **Custom Django Model Fields**
   
   We created two custom field classes that inherit from Django's standard fields:
   - `EncryptedCharField`: For short text data (names, emails, phones)
   - `EncryptedTextField`: For longer text data

   ```python
   class EncryptedCharField(models.CharField):
       def get_prep_value(self, value):
           """Encrypt before saving to database"""
           return encrypt_value(str(value))
       
       def from_db_value(self, value, expression, connection):
           """Decrypt when loading from database"""
           return decrypt_value(value)
   ```

2. **Fernet Symmetric Encryption**
   
   We use the `cryptography` library's Fernet implementation because:
   - It's authenticated encryption (provides both confidentiality and integrity)
   - Uses AES 128-bit encryption in CBC mode
   - Includes HMAC for authentication
   - Handles IV generation automatically
   - Is part of the well-maintained `cryptography` package

3. **Key Management**
   
   The encryption key is loaded from environment variables:
   ```python
   def get_encryption_key():
       key = os.getenv('FIELD_ENCRYPTION_KEY')
       if not key and settings.DEBUG:
           # Auto-generate only in development
           key = Fernet.generate_key()
       return key
   ```

4. **Transparent Operation**
   
   The encryption/decryption happens automatically:
   - When saving: Django calls `get_prep_value()` → encrypts data
   - When loading: Django calls `from_db_value()` → decrypts data
   - Application code doesn't need to know about encryption

### How We Implemented SSL/TLS for Database Connections

1. **MySQL SSL Configuration**
   ```python
   'OPTIONS': {
       'ssl': {
           'ca': os.getenv('DB_SSL_CA'),
       } if os.getenv('DB_SSL_CA') else None,
   }
   ```

2. **PostgreSQL SSL Configuration**
   ```python
   'OPTIONS': {
       'sslmode': os.getenv('DB_SSL_MODE', 'require'),
   }
   ```

3. **Environment-Based Configuration**
   - All SSL settings come from environment variables
   - Supports different configurations per environment
   - No hardcoded paths or certificates

### Migration Strategy

We implemented a graceful migration approach:

1. **Fallback Mechanism**: If decryption fails, return original value
2. **Management Command**: `encrypt_existing_data` for bulk encryption
3. **Field Length Adjustment**: Encrypted values are ~3x longer than original

## Potential Improvements

### 1. Advanced Key Management

**Current**: Single key stored in environment variable

**Improvements**:
- **Key Rotation**: Implement key versioning to support periodic key rotation
- **Hardware Security Module (HSM)**: Store keys in dedicated hardware
- **Key Management Service**: Use AWS KMS, Azure Key Vault, or HashiCorp Vault
- **Split Keys**: Use Shamir's Secret Sharing for distributed key storage

```python
# Example: Key rotation support
class EncryptedFieldWithKeyRotation:
    def encrypt_value(self, value):
        current_key = get_current_key()
        return f"{current_key.version}:{current_key.encrypt(value)}"
    
    def decrypt_value(self, encrypted):
        version, data = encrypted.split(':', 1)
        key = get_key_by_version(version)
        return key.decrypt(data)
```

### 2. Performance Optimization

**Current**: Individual field encryption/decryption

**Improvements**:
- **Batch Operations**: Encrypt/decrypt multiple fields in one operation
- **Caching**: Cache decrypted values in memory (with careful security considerations)
- **Async Encryption**: Use async operations for bulk data processing
- **Database-Level Encryption**: Consider Transparent Data Encryption (TDE) for entire database

```python
# Example: Cached decryption
class CachedEncryptedField:
    def from_db_value(self, value, expression, connection):
        cache_key = f"decrypt:{hash(value)}"
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        decrypted = decrypt_value(value)
        cache.set(cache_key, decrypted, timeout=300)  # 5 minutes
        return decrypted
```

### 3. Enhanced Security Features

**Current**: Basic Fernet encryption

**Improvements**:
- **Format Preserving Encryption (FPE)**: Maintain data format while encrypted
- **Searchable Encryption**: Allow queries on encrypted data
- **Homomorphic Encryption**: Perform operations on encrypted data
- **Zero-Knowledge Proofs**: Verify data without decryption

```python
# Example: Searchable encryption with blind indexing
class SearchableEncryptedField:
    def save_with_index(self, value):
        encrypted = encrypt_value(value)
        blind_index = generate_blind_index(value)
        return encrypted, blind_index
```

### 4. Monitoring and Auditing

**Current**: Basic logging

**Improvements**:
- **Encryption Events Logging**: Track all encryption/decryption operations
- **Performance Metrics**: Monitor encryption overhead
- **Compliance Reporting**: Generate GDPR/HIPAA compliance reports
- **Anomaly Detection**: Detect unusual decryption patterns

```python
# Example: Audit logging
class AuditedEncryptedField:
    def from_db_value(self, value, expression, connection):
        audit_log.info(f"Decrypting field {self.name} for user {current_user}")
        return decrypt_value(value)
```

### 5. Database-Specific Features

**Current**: Application-level encryption

**Improvements**:
- **PostgreSQL pgcrypto**: Use native PostgreSQL encryption functions
- **MySQL Encryption Functions**: Leverage AES_ENCRYPT/AES_DECRYPT
- **Column-Level Encryption**: Use database native column encryption
- **Encrypted Connections**: Implement mutual TLS authentication

```sql
-- Example: PostgreSQL pgcrypto
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Encrypt at database level
INSERT INTO users (email) VALUES (
    pgp_sym_encrypt('user@example.com', 'encryption_key')
);
```

### 6. Testing Improvements

**Current**: Basic field testing

**Improvements**:
- **Encryption Compliance Tests**: Verify all sensitive fields are encrypted
- **Performance Benchmarks**: Measure encryption overhead
- **Key Rotation Tests**: Test upgrade paths
- **Security Penetration Tests**: Attempt to bypass encryption

```python
# Example: Compliance test
class EncryptionComplianceTest(TestCase):
    def test_all_pii_fields_encrypted(self):
        """Ensure all PII fields use encryption"""
        pii_fields = ['email', 'first_name', 'last_name', 'phone']
        for field_name in pii_fields:
            field = User._meta.get_field(field_name)
            self.assertIsInstance(field, (EncryptedCharField, EncryptedTextField))
```

### 7. User Experience Improvements

**Current**: Transparent encryption

**Improvements**:
- **Partial Decryption**: Show masked values (e.g., "****1234")
- **Client-Side Encryption**: End-to-end encryption for sensitive data
- **Field-Level Access Control**: Decrypt only for authorized users
- **Progressive Disclosure**: Decrypt on-demand for performance

```python
# Example: Masked display
class MaskedEncryptedField:
    def get_masked_value(self):
        decrypted = self.decrypt_value()
        if self.field_type == 'email':
            user, domain = decrypted.split('@')
            return f"{user[:2]}***@{domain}"
        return decrypted[:3] + "***"
```

### 8. Backup and Recovery

**Current**: Standard database backups

**Improvements**:
- **Encrypted Backups**: Ensure backups are also encrypted
- **Key Escrow**: Secure key backup mechanism
- **Disaster Recovery**: Test encryption in DR scenarios
- **Point-in-Time Recovery**: Handle encrypted data during PITR

### Implementation Roadmap

1. **Phase 1**: Current implementation (COMPLETE)
   - Basic field encryption
   - SSL/TLS for connections

2. **Phase 2**: Key Management (RECOMMENDED NEXT)
   - Implement key rotation
   - Add key versioning
   - Set up monitoring

3. **Phase 3**: Performance & Security
   - Add caching layer
   - Implement audit logging
   - Enhanced key storage

4. **Phase 4**: Advanced Features
   - Searchable encryption
   - Format-preserving encryption
   - Database-native features

By implementing these improvements incrementally, you can enhance the security posture while maintaining system stability and performance.