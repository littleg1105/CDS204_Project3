#!/usr/bin/env python
"""
Encryption and Data Protection Test Script

This script tests the application's encryption and data protection measures by
analyzing the database, checking for exposed encryption keys, and inspecting
encrypted fields.

The script checks:
1. If sensitive data is properly encrypted in the database
2. If encryption keys are properly protected and not hardcoded
3. If proper encryption algorithms are used
4. If data is decrypted securely

Usage:
    python encryption_test.py [db_path] [app_path]

Example:
    python encryption_test.py /path/to/db.sqlite3 /path/to/app
"""

import sys
import os
import re
import sqlite3
import json
import logging
import binascii
import django
import base64
import subprocess
from tabulate import tabulate
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('encryption_test.log')
    ]
)
logger = logging.getLogger(__name__)

class EncryptionTest:
    def __init__(self, db_path, app_path):
        self.db_path = db_path
        self.app_path = app_path
        self.conn = None
        self.encryption_files = []
        self.encryption_patterns = [
            r'encr[iy]pt',
            r'decr[iy]pt',
            r'cipher',
            r'aes',
            r'rsa',
            r'crypt(?!python)',
            r'secret',
            r'key',
            r'salt',
            r'iv',
            r'nonce',
            r'pbkdf2',
            r'bcrypt',
            r'argon2',
            r'hash'
        ]
        
        # Key detection patterns
        self.key_patterns = [
            # Generic patterns
            r'key\s*=\s*[\'"]([^\'"]*)[\'""]',
            r'SECRET_KEY\s*=\s*[\'"]([^\'"]*)[\'""]',
            r'api[-_]key\s*=\s*[\'"]([^\'"]*)[\'""]',
            r'secret\s*=\s*[\'"]([^\'"]*)[\'""]',
            
            # Base64 pattern (possible encoded keys)
            r'[\'"][A-Za-z0-9+/]{32,}={0,2}[\'""]',
            
            # Hex patterns (possible encoded keys or hashes)
            r'[\'"][0-9a-fA-F]{32,}[\'""]',
            r'bytes\.fromhex\([\'"]([0-9a-fA-F]+)[\'"]\)',
            
            # Environment variable keys
            r'os\.environ\.get\([\'"]([^\'"]*)[\'"]\)',
            r'os\.getenv\([\'"]([^\'"]*)[\'"]\)'
        ]
        
        # Initialize results
        self.results = {
            'encrypted_fields': [],
            'encryption_implementation': [],
            'secret_keys': [],
            'database_analysis': {},
            'security_assessment': {}
        }

    def connect_to_db(self):
        """Connect to the database"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            logger.info(f"Connected to database: {self.db_path}")
            return True
        except Exception as e:
            logger.error(f"Error connecting to database: {e}")
            return False

    def find_encryption_files(self):
        """Find files related to encryption in the application"""
        logger.info("\n[*] Searching for encryption-related files...")
        
        encryption_files = []
        pattern = '|'.join(self.encryption_patterns)
        
        # Use grep to find encryption-related files
        try:
            grep_command = ['grep', '-r', '-l', '-i', '-E', pattern, self.app_path, 
                          '--include=*.py', '--exclude-dir=__pycache__']
            
            result = subprocess.run(grep_command, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout:
                encryption_files = result.stdout.strip().split('\n')
                logger.info(f"Found {len(encryption_files)} encryption-related files")
                
                self.encryption_files = encryption_files
                return encryption_files
            else:
                logger.warning("No encryption-related files found using grep")
        except Exception as e:
            logger.error(f"Error using grep to find encryption files: {e}")
        
        # Fallback: manual search
        try:
            for root, _, files in os.walk(self.app_path):
                for file in files:
                    if not file.endswith('.py'):
                        continue
                    
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            
                            if re.search(pattern, content, re.IGNORECASE):
                                encryption_files.append(file_path)
                    except Exception:
                        # Skip files that can't be read
                        continue
            
            logger.info(f"Found {len(encryption_files)} encryption-related files")
            self.encryption_files = encryption_files
            return encryption_files
            
        except Exception as e:
            logger.error(f"Error manually searching for encryption files: {e}")
            return []

    def analyze_encryption_implementation(self):
        """Analyze encryption implementation in the code"""
        logger.info("\n[*] Analyzing encryption implementation...")
        
        if not self.encryption_files:
            logger.warning("No encryption files found. Skipping analysis.")
            return
        
        for file_path in self.encryption_files:
            logger.info(f"Analyzing file: {file_path}")
            
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Check for encryption algorithm
                algorithms = []
                
                if re.search(r'aes', content, re.IGNORECASE):
                    algorithms.append('AES')
                    
                    # Check for AES mode
                    if re.search(r'cbc', content, re.IGNORECASE):
                        algorithms[-1] += '-CBC'
                    elif re.search(r'gcm', content, re.IGNORECASE):
                        algorithms[-1] += '-GCM'
                    elif re.search(r'ctr', content, re.IGNORECASE):
                        algorithms[-1] += '-CTR'
                    elif re.search(r'ecb', content, re.IGNORECASE):
                        algorithms[-1] += '-ECB (INSECURE)'
                
                if re.search(r'rsa', content, re.IGNORECASE):
                    algorithms.append('RSA')
                
                if re.search(r'fernet', content, re.IGNORECASE):
                    algorithms.append('Fernet (AES-128-CBC)')
                
                # Check for key derivation
                key_derivation = []
                
                if re.search(r'pbkdf2', content, re.IGNORECASE):
                    key_derivation.append('PBKDF2')
                    
                    # Check for iterations
                    iterations_match = re.search(r'iterations\s*=\s*(\d+)', content)
                    if iterations_match:
                        iterations = int(iterations_match.group(1))
                        key_derivation[-1] += f" (iterations: {iterations})"
                        
                        if iterations < 100000:
                            key_derivation[-1] += " - WEAK"
                
                if re.search(r'bcrypt', content, re.IGNORECASE):
                    key_derivation.append('bcrypt')
                
                if re.search(r'argon2', content, re.IGNORECASE):
                    key_derivation.append('Argon2')
                
                # Check for hardcoded secrets
                secrets = []
                
                for pattern in self.key_patterns:
                    matches = re.findall(pattern, content)
                    
                    for match in matches:
                        # Skip empty matches and common placeholders
                        if (not match or match == 'None' or match == 'None-None' or 
                           'PLACEHOLDER' in match or match == 'SECRET_KEY'):
                            continue
                        
                        # Check if it's a potential key
                        if len(match) >= 16:
                            secrets.append(match)
                            self.results['secret_keys'].append({
                                'file': file_path,
                                'type': 'Potential hardcoded key/secret',
                                'value': match,
                                'secure': False
                            })
                
                # Record results
                self.results['encryption_implementation'].append({
                    'file': file_path,
                    'algorithms': algorithms,
                    'key_derivation': key_derivation,
                    'hardcoded_secrets': len(secrets) > 0,
                    'secrets_count': len(secrets)
                })
                
                # Log findings
                if algorithms:
                    logger.info(f"  Encryption algorithms found: {', '.join(algorithms)}")
                else:
                    logger.warning(f"  No encryption algorithms positively identified")
                
                if key_derivation:
                    logger.info(f"  Key derivation methods found: {', '.join(key_derivation)}")
                else:
                    logger.warning(f"  No key derivation methods found")
                
                if secrets:
                    logger.warning(f"  Found {len(secrets)} potential hardcoded secrets!")
                    for i, secret in enumerate(secrets[:3]):  # Only show first 3
                        masked = secret[:3] + '*' * (len(secret) - 6) + secret[-3:] if len(secret) > 10 else '***'
                        logger.warning(f"    Secret {i+1}: {masked}")
                    
                    if len(secrets) > 3:
                        logger.warning(f"    ...and {len(secrets) - 3} more")
                else:
                    logger.info(f"  No hardcoded secrets found (good practice)")
                
            except Exception as e:
                logger.error(f"Error analyzing file {file_path}: {e}")

    def analyze_environment_variables(self):
        """Check if encryption keys are stored in environment variables"""
        logger.info("\n[*] Checking for encryption keys in environment variables...")
        
        # Look for environment variables in the code
        env_vars = set()
        
        for file_path in self.encryption_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Find references to environment variables
                env_var_patterns = [
                    r'os\.environ\.get\([\'"]([^\'"]+)[\'"]',
                    r'os\.getenv\([\'"]([^\'"]+)[\'"]',
                    r'os\.environ\[[\'"]([^\'"]+)[\'"]'
                ]
                
                for pattern in env_var_patterns:
                    matches = re.findall(pattern, content)
                    env_vars.update(matches)
            
            except Exception as e:
                logger.error(f"Error checking environment variables in {file_path}: {e}")
        
        # Filter for potential encryption-related env vars
        encryption_env_vars = []
        
        encryption_keywords = ['key', 'secret', 'token', 'password', 'crypt', 'salt', 'encrypt', 'cert']
        
        for var in env_vars:
            if any(keyword in var.lower() for keyword in encryption_keywords):
                encryption_env_vars.append(var)
                
                # Record in results
                self.results['secret_keys'].append({
                    'type': 'Environment variable',
                    'name': var,
                    'secure': True  # Environment variables are generally secure
                })
        
        if encryption_env_vars:
            logger.info(f"Found {len(encryption_env_vars)} encryption-related environment variables:")
            for var in encryption_env_vars:
                logger.info(f"  {var}")
        else:
            logger.warning("No encryption-related environment variables found")

    def analyze_database_encryption(self):
        """Analyze database to check for encrypted fields"""
        logger.info("\n[*] Analyzing database for encrypted fields...")
        
        if not self.conn:
            if not self.connect_to_db():
                logger.error("Could not connect to database. Skipping database analysis.")
                return
        
        # Get the list of tables
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        # Store potential encrypted data
        encrypted_fields = []
        
        # Analyze each table
        for table in tables:
            table_name = table[0]
            
            # Skip SQLite internal tables
            if table_name.startswith('sqlite_'):
                continue
            
            logger.info(f"Analyzing table: {table_name}")
            
            # Get table schema
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()
            column_names = [col[1] for col in columns]
            
            # Calculate column width
            max_col_width = max(len(col) for col in column_names) + 2
            
            # Get sample data
            cursor.execute(f"SELECT * FROM {table_name} LIMIT 5;")
            rows = cursor.fetchall()
            
            if not rows:
                logger.info(f"  Table {table_name} is empty")
                continue
            
            # Analyze each column for potentially encrypted data
            for i, column in enumerate(column_names):
                # Skip obvious non-encrypted fields
                if column in ['id', 'created_at', 'updated_at', 'date_joined', 'last_login']:
                    continue
                
                values = [row[i] for row in rows if row[i] is not None]
                
                if not values:
                    continue
                
                # Check if values are string type
                if not all(isinstance(val, str) for val in values):
                    continue
                
                # Check for base64-like patterns
                if all(self._is_potential_encrypted(val) for val in values):
                    encrypted_fields.append({
                        'table': table_name,
                        'column': column,
                        'sample': values[0],
                        'format': self._guess_encryption_format(values[0])
                    })
                    
                    logger.info(f"  Potential encrypted field: {column}")
                    logger.info(f"  Sample: {values[0][:20]}..." if len(values[0]) > 20 else f"  Sample: {values[0]}")
                    logger.info(f"  Format: {self._guess_encryption_format(values[0])}")
        
        # Record results
        self.results['encrypted_fields'] = encrypted_fields
        
        # Summary
        self.results['database_analysis'] = {
            'tables_analyzed': len(tables),
            'encrypted_fields_found': len(encrypted_fields)
        }
        
        if encrypted_fields:
            logger.info(f"\nFound {len(encrypted_fields)} potentially encrypted fields across all tables")
        else:
            logger.warning("\nNo potentially encrypted fields found in the database")

    def _is_potential_encrypted(self, value):
        """Check if a value appears to be encrypted"""
        # Skip short values
        if len(value) < 16:
            return False
        
        # Check if value looks like Base64
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', value):
            return True
        
        # Check for hex data
        if re.match(r'^[0-9a-fA-F]+$', value) and len(value) % 2 == 0:
            return True
        
        # Check for binary-like data encoded as text
        binary_chars = set([c for c in value if ord(c) < 32 or ord(c) > 126])
        if binary_chars:
            return True
        
        # Check for Django's encoded data format
        if value.startswith('gAAAAAB') and len(value) > 60:
            return True
        
        return False

    def _guess_encryption_format(self, value):
        """Guess the format of encrypted data"""
        # Django Fernet
        if value.startswith('gAAAAAB') and len(value) > 60:
            return "Django Fernet (AES-CBC)"
        
        # Generic Base64
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', value):
            try:
                # Try to decode and check if it's valid UTF-8
                decoded = base64.b64decode(value)
                if self._is_binary(decoded):
                    return "Base64-encoded binary (likely encrypted)"
                else:
                    return "Base64-encoded (not encrypted)"
            except:
                return "Base64-like data"
        
        # Hex data
        if re.match(r'^[0-9a-fA-F]+$', value) and len(value) % 2 == 0:
            return "Hex-encoded data"
        
        # Encoded binary
        binary_chars = sum(1 for c in value if ord(c) < 32 or ord(c) > 126)
        if binary_chars > len(value) * 0.1:
            return "Binary data (likely encrypted)"
        
        return "Unknown format"

    def _is_binary(self, data):
        """Check if data appears to be binary"""
        # Count control characters
        control_chars = sum(1 for b in data if b < 32 and b not in (9, 10, 13))
        return control_chars > len(data) * 0.1

    def analyze_security_settings(self):
        """Analyze Django security settings"""
        logger.info("\n[*] Analyzing Django security settings...")
        
        settings_file = os.path.join(self.app_path, 'eshop_project', 'settings.py')
        
        if not os.path.exists(settings_file):
            # Try to find the settings file
            for root, dirs, files in os.walk(self.app_path):
                for file in files:
                    if file == 'settings.py':
                        settings_file = os.path.join(root, file)
                        break
        
        if not os.path.exists(settings_file):
            logger.warning("Could not find Django settings.py file")
            return
        
        logger.info(f"Analyzing settings file: {settings_file}")
        
        security_settings = {
            'SECRET_KEY': {'present': False, 'value': None, 'secure': False},
            'DEBUG': {'present': False, 'value': None, 'secure': False},
            'ALLOWED_HOSTS': {'present': False, 'value': None, 'secure': False},
            'PASSWORD_HASHERS': {'present': False, 'value': None, 'secure': False},
            'SESSION_COOKIE_SECURE': {'present': False, 'value': None, 'secure': False},
            'CSRF_COOKIE_SECURE': {'present': False, 'value': None, 'secure': False},
            'SECURE_SSL_REDIRECT': {'present': False, 'value': None, 'secure': False},
            'SECURE_HSTS_SECONDS': {'present': False, 'value': None, 'secure': False},
            'SECURE_BROWSER_XSS_FILTER': {'present': False, 'value': None, 'secure': False},
            'SECURE_CONTENT_TYPE_NOSNIFF': {'present': False, 'value': None, 'secure': False}
        }
        
        try:
            with open(settings_file, 'r') as f:
                content = f.read()
            
            # Check for SECRET_KEY
            secret_key_match = re.search(r'SECRET_KEY\s*=\s*[\'"]([^\'"]*)[\'"]', content)
            if secret_key_match:
                security_settings['SECRET_KEY']['present'] = True
                security_settings['SECRET_KEY']['value'] = secret_key_match.group(1)[:5] + '...'
                
                # Check if it's from environment variable
                if re.search(r'SECRET_KEY\s*=\s*os\.environ', content):
                    security_settings['SECRET_KEY']['secure'] = True
            
            # Check for DEBUG
            debug_match = re.search(r'DEBUG\s*=\s*(\w+)', content)
            if debug_match:
                security_settings['DEBUG']['present'] = True
                security_settings['DEBUG']['value'] = debug_match.group(1)
                security_settings['DEBUG']['secure'] = debug_match.group(1).lower() == 'false'
            
            # Check for ALLOWED_HOSTS
            if 'ALLOWED_HOSTS' in content:
                security_settings['ALLOWED_HOSTS']['present'] = True
                
                # Try to extract the list
                allowed_hosts_match = re.search(r'ALLOWED_HOSTS\s*=\s*\[(.*?)\]', content, re.DOTALL)
                if allowed_hosts_match:
                    hosts_text = allowed_hosts_match.group(1)
                    security_settings['ALLOWED_HOSTS']['value'] = hosts_text.strip()
                    
                    # Check if it's secure (not empty, not '*')
                    security_settings['ALLOWED_HOSTS']['secure'] = (
                        hosts_text.strip() and not re.search(r'[\'"]\*[\'"]', hosts_text)
                    )
            
            # Check for PASSWORD_HASHERS
            if 'PASSWORD_HASHERS' in content:
                security_settings['PASSWORD_HASHERS']['present'] = True
                
                # Check for secure hashers
                secure_hashers = ['argon2', 'pbkdf2', 'bcrypt']
                security_settings['PASSWORD_HASHERS']['secure'] = any(
                    hasher in content for hasher in secure_hashers
                )
                
                # Try to extract first hasher
                password_hashers_match = re.search(r'PASSWORD_HASHERS\s*=\s*\[(.*?)[,\]]', content, re.DOTALL)
                if password_hashers_match:
                    security_settings['PASSWORD_HASHERS']['value'] = password_hashers_match.group(1).strip()
            
            # Check for other security settings
            for setting in ['SESSION_COOKIE_SECURE', 'CSRF_COOKIE_SECURE', 'SECURE_SSL_REDIRECT',
                           'SECURE_HSTS_SECONDS', 'SECURE_BROWSER_XSS_FILTER', 'SECURE_CONTENT_TYPE_NOSNIFF']:
                setting_match = re.search(rf'{setting}\s*=\s*(\w+)', content)
                if setting_match:
                    security_settings[setting]['present'] = True
                    security_settings[setting]['value'] = setting_match.group(1)
                    security_settings[setting]['secure'] = setting_match.group(1).lower() == 'true'
            
        except Exception as e:
            logger.error(f"Error analyzing settings file: {e}")
        
        # Record results
        self.results['security_assessment'] = security_settings
        
        # Display results
        table_data = []
        for setting, data in security_settings.items():
            if data['present']:
                table_data.append([
                    setting,
                    data['value'] if data['value'] is not None else 'N/A',
                    'Yes' if data['secure'] else 'No'
                ])
            else:
                table_data.append([setting, 'Not set', 'No'])
        
        headers = ["Setting", "Value", "Secure"]
        logger.info("\nSecurity Settings Analysis:")
        logger.info(tabulate(table_data, headers=headers, tablefmt="grid"))

    def analyze_results(self):
        """Analyze the test results and generate report"""
        logger.info("\n[ANALYSIS]")
        
        # Analyze database encryption
        logger.info("\n[DATABASE ENCRYPTION]")
        if self.results['encrypted_fields']:
            logger.info(f"Found {len(self.results['encrypted_fields'])} potentially encrypted fields")
            
            # Display encrypted fields
            table_data = []
            for field in self.results['encrypted_fields']:
                sample = field['sample']
                if len(sample) > 30:
                    sample = f"{sample[:15]}...{sample[-10:]}"
                
                table_data.append([
                    field['table'],
                    field['column'],
                    sample,
                    field['format']
                ])
            
            headers = ["Table", "Column", "Sample", "Format"]
            logger.info(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            logger.warning("No encrypted fields found in the database")
        
        # Analyze encryption implementation
        logger.info("\n[ENCRYPTION IMPLEMENTATION]")
        if self.results['encryption_implementation']:
            secure_algs = 0
            insecure_algs = 0
            secure_kdf = 0
            insecure_kdf = 0
            hardcoded_secrets_count = 0
            
            for impl in self.results['encryption_implementation']:
                # Check algorithms
                for alg in impl.get('algorithms', []):
                    if 'ECB' in alg or alg == 'INSECURE':
                        insecure_algs += 1
                    else:
                        secure_algs += 1
                
                # Check key derivation
                for kdf in impl.get('key_derivation', []):
                    if 'WEAK' in kdf:
                        insecure_kdf += 1
                    else:
                        secure_kdf += 1
                
                # Check hardcoded secrets
                if impl.get('hardcoded_secrets', False):
                    hardcoded_secrets_count += impl.get('secrets_count', 0)
            
            logger.info(f"Found {secure_algs + insecure_algs} encryption algorithm references")
            logger.info(f"  Secure algorithms: {secure_algs}")
            logger.info(f"  Insecure algorithms: {insecure_algs}")
            
            logger.info(f"Found {secure_kdf + insecure_kdf} key derivation references")
            logger.info(f"  Secure key derivation: {secure_kdf}")
            logger.info(f"  Insecure key derivation: {insecure_kdf}")
            
            if hardcoded_secrets_count > 0:
                logger.warning(f"Found {hardcoded_secrets_count} hardcoded secrets/keys")
        else:
            logger.warning("No encryption implementation found")
        
        # Analyze security settings
        logger.info("\n[SECURITY SETTINGS]")
        secure_settings = 0
        insecure_settings = 0
        missing_settings = 0
        
        for setting, data in self.results['security_assessment'].items():
            if not data['present']:
                missing_settings += 1
            elif data['secure']:
                secure_settings += 1
            else:
                insecure_settings += 1
        
        logger.info(f"Security settings analysis:")
        logger.info(f"  Secure settings: {secure_settings}")
        logger.info(f"  Insecure settings: {insecure_settings}")
        logger.info(f"  Missing settings: {missing_settings}")
        
        # Overall security assessment
        logger.info("\n[OVERALL SECURITY ASSESSMENT]")
        
        vulnerabilities = []
        
        # Check for hardcoded secrets
        if self.results['secret_keys']:
            insecure_keys = [k for k in self.results['secret_keys'] if not k.get('secure', False)]
            if insecure_keys:
                vulnerabilities.append(f"Found {len(insecure_keys)} hardcoded/insecure keys or secrets")
        
        # Check for insecure encryption
        if insecure_algs > 0:
            vulnerabilities.append(f"Found {insecure_algs} references to insecure encryption algorithms")
        
        # Check for weak key derivation
        if insecure_kdf > 0:
            vulnerabilities.append(f"Found {insecure_kdf} references to weak key derivation functions")
        
        # Check for insecure settings
        if insecure_settings > 0:
            vulnerabilities.append(f"Found {insecure_settings} insecure security settings")
        
        # Check for missing settings
        if missing_settings > 0:
            vulnerabilities.append(f"Found {missing_settings} missing security settings")
        
        # Display vulnerabilities
        if vulnerabilities:
            logger.warning("Vulnerabilities found:")
            for vulnerability in vulnerabilities:
                logger.warning(f"  - {vulnerability}")
            
            logger.warning("\nRecommendations:")
            logger.warning("  - Use environment variables for all secrets and keys")
            logger.warning("  - Use secure encryption algorithms (AES-GCM, AES-CBC with HMAC)")
            logger.warning("  - Use strong key derivation (PBKDF2 with 100,000+ iterations or Argon2)")
            logger.warning("  - Turn on all Django security settings in production")
            logger.warning("  - Use Django's built-in encryption tools like Fernet")
        else:
            logger.info("No major encryption vulnerabilities found")
            logger.info("\nGood practices to maintain:")
            logger.info("  - Continue storing secrets in environment variables")
            logger.info("  - Continue using secure encryption algorithms")
            logger.info("  - Continue encrypting sensitive data in the database")
            logger.info("  - Regularly rotate encryption keys")

    def run_test(self):
        """Run the full encryption test suite"""
        logger.info(f"[*] Starting encryption test on {self.app_path}")
        
        # Find encryption files
        self.find_encryption_files()
        
        # Analyze encryption implementation
        self.analyze_encryption_implementation()
        
        # Check environment variables
        self.analyze_environment_variables()
        
        # Analyze database encryption
        self.analyze_database_encryption()
        
        # Analyze security settings
        self.analyze_security_settings()
        
        # Analyze results
        self.analyze_results()
        
        # Close database connection
        if self.conn:
            self.conn.close()

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} [db_path] [app_path]")
        print(f"Example: {sys.argv[0]} /path/to/db.sqlite3 /path/to/app")
        sys.exit(1)
    
    db_path = sys.argv[1]
    app_path = sys.argv[2]
    
    # Check if paths exist
    if not os.path.exists(db_path):
        print(f"Database path does not exist: {db_path}")
        sys.exit(1)
    
    if not os.path.exists(app_path):
        print(f"Application path does not exist: {app_path}")
        sys.exit(1)
    
    try:
        # Verify that required packages are installed
        import tabulate
        import cryptography
    except ImportError as e:
        missing_package = str(e).split("'")[1]
        print(f"[!] Required package '{missing_package}' is missing. Please install it with:")
        print(f"    pip install {missing_package}")
        print("[!] You may also need to install: tabulate, cryptography")
        sys.exit(1)
    
    tester = EncryptionTest(db_path, app_path)
    tester.run_test()

if __name__ == "__main__":
    main()