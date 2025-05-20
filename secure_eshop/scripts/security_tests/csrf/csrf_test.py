#!/usr/bin/env python
"""
Cross-Site Request Forgery (CSRF) Test Script

This script tests the application's resistance to CSRF attacks by
attempting to submit forms without valid CSRF tokens or with manipulated tokens.

The script checks:
1. If forms require valid CSRF tokens
2. If the application enforces CSRF protection on all state-changing operations
3. If SameSite cookie attributes are properly set
4. If applications rejects requests with wrong or missing CSRF tokens

Usage:
    python csrf_test.py [target_url] [username] [password]

Example:
    python csrf_test.py https://localhost:8000/ admin password123
"""

import requests
import sys
import time
import re
import json
import logging
import uuid
import os
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
from tabulate import tabulate
import http.server
import socketserver
import threading
import webbrowser
from urllib.parse import urlparse

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('csrf_test.log')
    ]
)
logger = logging.getLogger(__name__)

class CSRFTest:
    def __init__(self, target_url, username=None, password=None):
        self.target_url = target_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.authenticated = False
        self.timeout = 15  # Request timeout in seconds
        self.test_id = str(uuid.uuid4().hex)[:8]  # Unique identifier for this test run
        
        # Initialize results
        self.results = {
            'form_protection': [],
            'cookie_settings': {},
            'http_methods': []
        }
        
        # Test server for CSRF POC
        self.http_server = None
        self.server_thread = None
        self.server_port = 8099  # Default port for test server

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

    def test_forms_csrf_protection(self):
        """Test if forms have CSRF protection"""
        logger.info("\n[*] Testing forms for CSRF protection...")
        
        # Login if credentials are provided
        if not self.authenticated and self.username and self.password:
            self.login()
        
        # Find forms in the application
        forms = self._find_forms()
        
        if not forms:
            logger.warning("No forms found for testing.")
            return
        
        for form_url, method, form_fields in forms:
            logger.info(f"Testing form: {form_url} ({method} method)")
            
            # First, check if the form has a CSRF token field
            has_csrf_field = any(field.get('name') == 'csrfmiddlewaretoken' for field in form_fields)
            
            if not has_csrf_field:
                logger.warning(f"Form at {form_url} does not have a visible CSRF token field")
            else:
                logger.info(f"Form at {form_url} has a CSRF token field")
            
            # Test submitting the form without a CSRF token
            no_token_result = self._test_form_without_token(form_url, method, form_fields)
            
            # Test submitting the form with an invalid CSRF token
            invalid_token_result = self._test_form_with_invalid_token(form_url, method, form_fields)
            
            # Record the results
            csrf_enforced = no_token_result['error'] and invalid_token_result['error']
            
            result = {
                'url': form_url,
                'method': method,
                'has_csrf_field': has_csrf_field,
                'rejects_missing_token': no_token_result['error'],
                'rejects_invalid_token': invalid_token_result['error'],
                'csrf_enforced': csrf_enforced,
                'details': {
                    'no_token': no_token_result,
                    'invalid_token': invalid_token_result
                }
            }
            
            self.results['form_protection'].append(result)
            
            if not csrf_enforced:
                logger.warning(f"Form at {form_url} does not properly enforce CSRF protection")
                
                # Generate a proof of concept CSRF HTML payload
                if not has_csrf_field or not no_token_result['error']:
                    self._generate_csrf_poc(form_url, method, form_fields)
            else:
                logger.info(f"Form at {form_url} correctly enforces CSRF protection")

    def _test_form_without_token(self, form_url, method, form_fields):
        """Test submitting a form without a CSRF token"""
        try:
            # Prepare form data without CSRF token
            form_data = {}
            
            # Fill required fields with dummy values
            for field in form_fields:
                field_name = field.get('name', '')
                field_type = field.get('type', 'text')
                
                if field_name and field_name != 'csrfmiddlewaretoken':
                    form_data[field_name] = self._get_dummy_value(field_name, field_type)
            
            # Create a new session to avoid using existing CSRF cookies
            test_session = requests.Session()
            
            # Get the form page first (to establish cookies)
            test_session.get(form_url, verify=False, timeout=self.timeout)
            
            # Submit the form
            if method.upper() == 'GET':
                response = test_session.get(
                    form_url,
                    params=form_data,
                    verify=False,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:  # POST
                response = test_session.post(
                    form_url,
                    data=form_data,
                    headers={'Referer': form_url},
                    verify=False,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            
            # Check if the submission was rejected
            rejection_indicators = [
                'csrf',
                'token',
                'forbidden',
                'not allowed',
                'permission denied',
                'unauthorized',
                'error',
                'invalid',
                'required'
            ]
            
            error_msg = None
            
            # Check for error messages in response
            if any(indicator in response.text.lower() for indicator in rejection_indicators):
                for indicator in rejection_indicators:
                    if indicator in response.text.lower():
                        # Try to extract the error message
                        soup = BeautifulSoup(response.text, 'html.parser')
                        error_elements = soup.find_all(['div', 'p', 'span'], 
                                                    class_=lambda c: c and ('error' in c.lower() or 'alert' in c.lower()))
                        
                        if error_elements:
                            error_msg = error_elements[0].get_text().strip()
                            break
            
            # Check if we got a 403 Forbidden response
            is_error = response.status_code in [403, 400, 401] or error_msg is not None
            
            return {
                'error': is_error,
                'status_code': response.status_code,
                'error_message': error_msg,
                'response_length': len(response.text)
            }
            
        except Exception as e:
            logger.error(f"Error testing form without token: {e}")
            return {'error': True, 'status_code': None, 'error_message': str(e)}

    def _test_form_with_invalid_token(self, form_url, method, form_fields):
        """Test submitting a form with an invalid CSRF token"""
        try:
            # Prepare form data with invalid CSRF token
            form_data = {
                'csrfmiddlewaretoken': 'invalid_token_' + self.test_id
            }
            
            # Fill required fields with dummy values
            for field in form_fields:
                field_name = field.get('name', '')
                field_type = field.get('type', 'text')
                
                if field_name and field_name != 'csrfmiddlewaretoken':
                    form_data[field_name] = self._get_dummy_value(field_name, field_type)
            
            # Create a new session to avoid using existing CSRF cookies
            test_session = requests.Session()
            
            # Get the form page first (to establish cookies)
            test_session.get(form_url, verify=False, timeout=self.timeout)
            
            # Submit the form
            if method.upper() == 'GET':
                response = test_session.get(
                    form_url,
                    params=form_data,
                    verify=False,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:  # POST
                response = test_session.post(
                    form_url,
                    data=form_data,
                    headers={'Referer': form_url},
                    verify=False,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            
            # Check if the submission was rejected
            rejection_indicators = [
                'csrf',
                'token',
                'forbidden',
                'not allowed',
                'permission denied',
                'unauthorized',
                'error',
                'invalid',
                'verification failed'
            ]
            
            error_msg = None
            
            # Check for error messages in response
            if any(indicator in response.text.lower() for indicator in rejection_indicators):
                for indicator in rejection_indicators:
                    if indicator in response.text.lower():
                        # Try to extract the error message
                        soup = BeautifulSoup(response.text, 'html.parser')
                        error_elements = soup.find_all(['div', 'p', 'span'], 
                                                    class_=lambda c: c and ('error' in c.lower() or 'alert' in c.lower()))
                        
                        if error_elements:
                            error_msg = error_elements[0].get_text().strip()
                            break
            
            # Check if we got a 403 Forbidden response
            is_error = response.status_code in [403, 400, 401] or error_msg is not None
            
            return {
                'error': is_error,
                'status_code': response.status_code,
                'error_message': error_msg,
                'response_length': len(response.text)
            }
            
        except Exception as e:
            logger.error(f"Error testing form with invalid token: {e}")
            return {'error': True, 'status_code': None, 'error_message': str(e)}

    def _get_dummy_value(self, field_name, field_type):
        """Generate a dummy value for a form field based on its name and type"""
        if field_type == 'email' or 'email' in field_name.lower():
            return f"test_{self.test_id}@example.com"
        elif field_type == 'password' or 'password' in field_name.lower():
            return f"Password123_{self.test_id}"
        elif field_type == 'tel' or 'phone' in field_name.lower():
            return f"1234567890"
        elif 'name' in field_name.lower():
            return f"Test User {self.test_id}"
        elif 'address' in field_name.lower():
            return f"123 Test St, {self.test_id}"
        elif 'city' in field_name.lower():
            return f"Test City {self.test_id}"
        elif 'country' in field_name.lower():
            return "Test Country"
        elif 'zip' in field_name.lower() or 'postal' in field_name.lower():
            return "12345"
        elif field_type == 'hidden':
            return "1"  # Default value for hidden fields
        else:
            return f"test_value_{self.test_id}"

    def _find_forms(self):
        """Find forms in the application"""
        forms = []
        visited = set()
        
        try:
            # Pages to check for forms
            pages_to_check = [
                self.target_url,
                f"{self.target_url}/profile/",
                f"{self.target_url}/account/",
                f"{self.target_url}/login/",
                f"{self.target_url}/register/",
                f"{self.target_url}/password/reset/",
                f"{self.target_url}/contact/",
                f"{self.target_url}/catalog/",
                f"{self.target_url}/cart/",
                f"{self.target_url}/payment/",
                f"{self.target_url}/settings/",
                f"{self.target_url}/orders/"
            ]
            
            # Also crawl the site for links
            for url in pages_to_check:
                if url in visited:
                    continue
                
                visited.add(url)
                
                try:
                    response = self.session.get(url, verify=False, timeout=self.timeout)
                    
                    if response.status_code != 200:
                        continue
                    
                    # Parse the HTML
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find forms
                    page_forms = soup.find_all('form')
                    
                    for form in page_forms:
                        # Get form action and method
                        action = form.get('action', '')
                        method = form.get('method', 'POST').upper()
                        
                        # Skip forms that likely don't change state
                        if method == 'GET' and ('search' in action.lower() or 'find' in action.lower()):
                            continue
                        
                        # Build the full URL
                        if not action:
                            form_url = url
                        elif action.startswith('/'):
                            form_url = f"{self.target_url}{action}"
                        elif action.startswith('http'):
                            form_url = action
                        else:
                            form_url = f"{url.rstrip('/')}/{action.lstrip('/')}"
                        
                        # Get form fields
                        fields = []
                        
                        for input_tag in form.find_all('input'):
                            field = {
                                'name': input_tag.get('name'),
                                'type': input_tag.get('type', 'text'),
                                'value': input_tag.get('value', '')
                            }
                            fields.append(field)
                        
                        for textarea in form.find_all('textarea'):
                            field = {
                                'name': textarea.get('name'),
                                'type': 'textarea',
                                'value': textarea.get_text()
                            }
                            fields.append(field)
                        
                        for select in form.find_all('select'):
                            options = []
                            for option in select.find_all('option'):
                                if option.get('value'):
                                    options.append(option.get('value'))
                            
                            field = {
                                'name': select.get('name'),
                                'type': 'select',
                                'options': options
                            }
                            fields.append(field)
                        
                        # Filter out fields without names
                        fields = [f for f in fields if f.get('name')]
                        
                        if fields and form_url not in [f[0] for f in forms]:
                            forms.append((form_url, method, fields))
                    
                    # Find links to add to the crawl
                    links = soup.find_all('a', href=True)
                    
                    for link in links:
                        href = link['href']
                        
                        if href.startswith('#') or href.startswith('javascript:'):
                            continue
                        
                        # Build the full URL
                        if href.startswith('/'):
                            full_url = f"{self.target_url}{href}"
                        elif href.startswith('http') and urlparse(href).netloc == urlparse(self.target_url).netloc:
                            full_url = href
                        elif not href.startswith('http'):
                            full_url = f"{url.rstrip('/')}/{href.lstrip('/')}"
                        else:
                            continue  # Skip external links
                        
                        if full_url not in visited and full_url.startswith(self.target_url):
                            pages_to_check.append(full_url)
                    
                except Exception as e:
                    logger.error(f"Error processing page {url}: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Error finding forms: {e}")
        
        return forms

    def _generate_csrf_poc(self, form_url, method, form_fields):
        """Generate a CSRF proof of concept HTML page"""
        try:
            # Get form fields, excluding CSRF token
            poc_fields = []
            
            for field in form_fields:
                field_name = field.get('name', '')
                field_type = field.get('type', 'text')
                
                if field_name and field_name != 'csrfmiddlewaretoken':
                    poc_fields.append({
                        'name': field_name,
                        'type': field_type,
                        'value': self._get_dummy_value(field_name, field_type)
                    })
            
            # Create the HTML POC
            form_id = f"csrf_form_{self.test_id}"
            
            if method.upper() == 'GET':
                # For GET, create a link with query parameters
                query_params = "&".join([f"{field['name']}={field['value']}" for field in poc_fields])
                poc_url = f"{form_url}?{query_params}"
                
                html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>CSRF Test (GET Method)</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; }}
                        h1 {{ color: #d9534f; }}
                        .warning {{ background-color: #f8d7da; padding: 15px; border-radius: 5px; }}
                        .button {{ background-color: #d9534f; color: white; padding: 10px 15px; border: none; border-radius: 5px; cursor: pointer; }}
                    </style>
                </head>
                <body>
                    <h1>CSRF Vulnerability Proof of Concept (GET Method)</h1>
                    <div class="warning">
                        <p><strong>Warning:</strong> This is a demonstration of a CSRF vulnerability. In a real attack, this page would be hosted on a malicious site.</p>
                    </div>
                    <p>Target URL: {form_url}</p>
                    <p>Click the link below to trigger the CSRF attack:</p>
                    <a href="{poc_url}" target="_blank" class="button">Click Me (CSRF Attack)</a>
                    <p>Or the attack could happen automatically:</p>
                    <img src="{poc_url}" style="display:none" alt="CSRF Attack">
                </body>
                </html>
                """
            else:  # POST
                # For POST, create an auto-submitting form
                form_fields_html = ""
                
                for field in poc_fields:
                    form_fields_html += f'<input type="hidden" name="{field["name"]}" value="{field["value"]}">\n    '
                
                html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>CSRF Test (POST Method)</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; }}
                        h1 {{ color: #d9534f; }}
                        .warning {{ background-color: #f8d7da; padding: 15px; border-radius: 5px; }}
                        .button {{ background-color: #d9534f; color: white; padding: 10px 15px; border: none; border-radius: 5px; cursor: pointer; }}
                    </style>
                </head>
                <body>
                    <h1>CSRF Vulnerability Proof of Concept (POST Method)</h1>
                    <div class="warning">
                        <p><strong>Warning:</strong> This is a demonstration of a CSRF vulnerability. In a real attack, this page would be hosted on a malicious site.</p>
                    </div>
                    <p>Target URL: {form_url}</p>
                    <p>This form will be submitted automatically when the page loads:</p>
                    <form id="{form_id}" action="{form_url}" method="POST">
                    {form_fields_html}
                    </form>
                    <button type="button" onclick="document.getElementById('{form_id}').submit();" class="button">
                        Submit Form Manually
                    </button>
                    <script>
                        // Auto-submit the form when the page loads
                        window.onload = function() {{
                            // Uncomment the line below to enable auto-submission
                            // document.getElementById('{form_id}').submit();
                            console.log("CSRF form ready to submit");
                        }};
                    </script>
                </body>
                </html>
                """
            
            # Save the POC to a file
            filename = f"csrf_poc_{urlparse(form_url).path.replace('/', '_')}_{method}.html"
            poc_path = os.path.join(os.getcwd(), filename)
            
            with open(poc_path, 'w') as f:
                f.write(html)
            
            logger.info(f"CSRF POC saved to: {poc_path}")
            
            # Start a simple HTTP server to serve the POC
            self._start_poc_server(filename)
            
            return poc_path
            
        except Exception as e:
            logger.error(f"Error generating CSRF POC: {e}")
            return None

    def _start_poc_server(self, filename):
        """Start a simple HTTP server to serve the CSRF POC"""
        try:
            # Define handler class
            class CSRFPocHandler(http.server.SimpleHTTPRequestHandler):
                def log_message(self, format, *args):
                    # Suppress log messages
                    pass
            
            # Find an available port
            for port in range(8099, 8199):
                try:
                    self.http_server = socketserver.TCPServer(("localhost", port), CSRFPocHandler)
                    self.server_port = port
                    break
                except OSError:
                    continue
            
            if not self.http_server:
                logger.error("Could not find an available port for the POC server")
                return
            
            # Start the server in a background thread
            self.server_thread = threading.Thread(target=self.http_server.serve_forever)
            self.server_thread.daemon = True  # Allow the thread to be terminated when the main program exits
            self.server_thread.start()
            
            logger.info(f"POC server started at http://localhost:{self.server_port}/{filename}")
            logger.info(f"Visit the URL above in your browser to see the CSRF POC")
            
            # Open the POC in the default browser (commented out for security)
            # webbrowser.open(f"http://localhost:{self.server_port}/{filename}")
            
        except Exception as e:
            logger.error(f"Error starting POC server: {e}")

    def test_cookie_settings(self):
        """Test cookie security settings (SameSite, Secure, HttpOnly)"""
        logger.info("\n[*] Testing cookie security settings...")
        
        # Login if credentials are provided
        if not self.authenticated and self.username and self.password:
            self.login()
        
        # Get cookies from the session
        cookies = self.session.cookies
        
        if not cookies:
            logger.warning("No cookies found in the session.")
            return
        
        # Check each cookie
        for cookie in cookies:
            logger.info(f"Analyzing cookie: {cookie.name}")
            
            # Check SameSite attribute
            samesite = cookie.get_nonstandard_attr('samesite')
            
            if not samesite:
                samesite_status = "Not set (default to Lax in modern browsers)"
                samesite_secure = False
            elif samesite.lower() == 'none':
                samesite_status = "None (cross-site cookies allowed)"
                samesite_secure = False
            elif samesite.lower() == 'lax':
                samesite_status = "Lax (some cross-site requests allowed)"
                samesite_secure = True
            elif samesite.lower() == 'strict':
                samesite_status = "Strict (no cross-site requests allowed)"
                samesite_secure = True
            else:
                samesite_status = f"Unknown value: {samesite}"
                samesite_secure = False
            
            # Check Secure flag
            secure = cookie.secure
            secure_status = "Yes" if secure else "No (cookie sent over HTTP)"
            
            # Check HttpOnly flag
            httponly = cookie.has_nonstandard_attr('httponly')
            httponly_status = "Yes" if httponly else "No (accessible via JavaScript)"
            
            # Record results
            self.results['cookie_settings'][cookie.name] = {
                'samesite': samesite,
                'samesite_status': samesite_status,
                'samesite_secure': samesite_secure,
                'secure': secure,
                'secure_status': secure_status,
                'httponly': httponly,
                'httponly_status': httponly_status,
                'domain': cookie.domain,
                'path': cookie.path,
                'is_session_cookie': not cookie.expires
            }
            
            # Log security issues
            if not samesite_secure:
                logger.warning(f"Cookie '{cookie.name}' has insecure SameSite attribute: {samesite}")
            
            if not secure and cookie.name.lower() in ['sessionid', 'csrftoken', 'auth', 'token']:
                logger.warning(f"Security cookie '{cookie.name}' missing Secure flag")
            
            if not httponly and cookie.name.lower() in ['sessionid', 'auth', 'token']:
                logger.warning(f"Security cookie '{cookie.name}' missing HttpOnly flag")

    def test_http_methods(self):
        """Test if the application enforces CSRF protection for different HTTP methods"""
        logger.info("\n[*] Testing CSRF protection for different HTTP methods...")
        
        # Login if credentials are provided
        if not self.authenticated and self.username and self.password:
            self.login()
        
        # Targets to test
        targets = [
            (self.target_url, "Main site"),
            (f"{self.target_url}/login/", "Login page"),
            (f"{self.target_url}/profile/", "Profile page"),
            (f"{self.target_url}/cart/", "Cart page")
        ]
        
        # Methods to test
        methods = ['GET', 'POST', 'PUT', 'DELETE']
        
        # Test each target with each method
        for url, description in targets:
            logger.info(f"Testing methods for {description} ({url})")
            
            for method in methods:
                result = self._test_http_method(url, method)
                self.results['http_methods'].append(result)

    def _test_http_method(self, url, method):
        """Test if a specific HTTP method requires CSRF protection"""
        try:
            # Create a new session to avoid using authenticated session cookies
            test_session = requests.Session()
            
            # Make a request with the specified method
            response = test_session.request(
                method=method,
                url=url,
                verify=False,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Check if the request was rejected
            is_rejected = response.status_code in [403, 405]
            
            # Check for CSRF related headers
            csrf_header = None
            for header in response.headers:
                if 'csrf' in header.lower():
                    csrf_header = f"{header}: {response.headers[header]}"
                    break
            
            # Check if CSRF is mentioned in the response body
            csrf_in_body = 'csrf' in response.text.lower()
            
            return {
                'url': url,
                'method': method,
                'status_code': response.status_code,
                'is_rejected': is_rejected,
                'csrf_header': csrf_header,
                'csrf_in_body': csrf_in_body,
                'response_length': len(response.text)
            }
            
        except Exception as e:
            logger.error(f"Error testing HTTP method {method} for {url}: {e}")
            return {
                'url': url,
                'method': method,
                'status_code': None,
                'is_rejected': True,
                'csrf_header': None,
                'csrf_in_body': False,
                'error': str(e)
            }

    def analyze_results(self):
        """Analyze the test results and generate report"""
        logger.info("\n[ANALYSIS]")
        
        vulnerable_count = 0
        
        # Check form protection results
        unprotected_forms = [r for r in self.results['form_protection'] if not r['csrf_enforced']]
        
        logger.info("\n[FORM PROTECTION]")
        if unprotected_forms:
            vulnerable_count += 1
            logger.warning(f"Found {len(unprotected_forms)} forms without proper CSRF protection")
            
            # Show vulnerable forms
            table_data = []
            for form in unprotected_forms:
                table_data.append([
                    form['url'],
                    form['method'],
                    "Yes" if form['has_csrf_field'] else "No",
                    "Yes" if form['rejects_missing_token'] else "No",
                    "Yes" if form['rejects_invalid_token'] else "No"
                ])
            
            if table_data:
                headers = ["URL", "Method", "Has CSRF Field", "Rejects Missing Token", "Rejects Invalid Token"]
                logger.warning(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            logger.info("All tested forms have proper CSRF protection")
        
        # Check cookie settings
        logger.info("\n[COOKIE SETTINGS]")
        cookie_issues = []
        
        for cookie_name, settings in self.results['cookie_settings'].items():
            issues = []
            
            if cookie_name.lower() in ['sessionid', 'csrftoken', 'auth', 'token']:
                if not settings.get('samesite_secure', False):
                    issues.append("Insecure SameSite")
                
                if not settings.get('secure', False):
                    issues.append("Missing Secure flag")
                
                if not settings.get('httponly', False):
                    issues.append("Missing HttpOnly flag")
            
            if issues:
                cookie_issues.append((cookie_name, issues))
        
        if cookie_issues:
            vulnerable_count += 1
            logger.warning(f"Found {len(cookie_issues)} cookies with security issues")
            
            # Show cookie issues
            for cookie_name, issues in cookie_issues:
                logger.warning(f"Cookie '{cookie_name}' has issues: {', '.join(issues)}")
                
            # Display cookie settings table
            table_data = []
            for cookie_name, settings in self.results['cookie_settings'].items():
                table_data.append([
                    cookie_name,
                    settings.get('samesite', 'Not set'),
                    "Yes" if settings.get('secure', False) else "No",
                    "Yes" if settings.get('httponly', False) else "No"
                ])
            
            if table_data:
                headers = ["Cookie Name", "SameSite", "Secure", "HttpOnly"]
                logger.info(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            logger.info("All cookies have secure settings")
        
        # Check HTTP methods
        logger.info("\n[HTTP METHODS]")
        unsafe_methods = [r for r in self.results['http_methods'] 
                        if r['method'] not in ['GET', 'HEAD'] and not r['is_rejected']]
        
        if unsafe_methods:
            vulnerable_count += 1
            logger.warning(f"Found {len(unsafe_methods)} endpoints allowing unsafe HTTP methods without proper protection")
            
            # Show unsafe methods
            table_data = []
            for method in unsafe_methods:
                table_data.append([
                    method['url'],
                    method['method'],
                    method['status_code']
                ])
            
            if table_data:
                headers = ["URL", "Method", "Status Code"]
                logger.warning(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            logger.info("All unsafe HTTP methods are properly protected or rejected")
        
        # Overall summary
        logger.info("\n[SUMMARY]")
        if vulnerable_count > 0:
            logger.warning(f"The application appears to be vulnerable to CSRF attacks in {vulnerable_count} area(s)")
            logger.warning("Recommendations:")
            logger.warning("1. Ensure all forms have proper CSRF token protection")
            logger.warning("2. Set SameSite=Strict or SameSite=Lax for session cookies")
            logger.warning("3. Enable the Secure flag for all sensitive cookies")
            logger.warning("4. Enable the HttpOnly flag for session cookies")
            logger.warning("5. Reject unsafe HTTP methods or ensure they require CSRF tokens")
            logger.warning("6. Use custom request headers for AJAX requests")
        else:
            logger.info("The application appears to be resistant to CSRF attacks")
            logger.info("Good security practices to maintain:")
            logger.info("1. Continue using Django's CSRF protection middleware")
            logger.info("2. Keep cookies with SameSite, Secure, and HttpOnly flags")
            logger.info("3. Regularly update Django to get the latest security features")

    def run_test(self):
        """Run the full CSRF test suite"""
        logger.info(f"[*] Starting CSRF test on {self.target_url}")
        logger.info(f"[*] Test ID: {self.test_id}")
        
        # Test forms for CSRF protection
        self.test_forms_csrf_protection()
        
        # Test cookie settings
        self.test_cookie_settings()
        
        # Test HTTP methods
        self.test_http_methods()
        
        # Analyze results
        self.analyze_results()
        
        # Stop POC server if running
        if self.http_server:
            logger.info("Stopping POC server...")
            self.http_server.shutdown()
            self.http_server.server_close()

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
    
    tester = CSRFTest(target_url, username, password)
    tester.run_test()

if __name__ == "__main__":
    main()