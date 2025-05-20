#!/usr/bin/env python
"""
OTP Brute Force Test Script

This script tests the application's resistance to brute force attacks against
One-Time Password (OTP) mechanisms like 2FA/MFA. OTP codes are typically 
6-digit numbers, making them potentially vulnerable to brute force attacks
if rate limiting or account lockout mechanisms are not implemented.

The script checks:
1. If the application implements rate limiting for OTP attempts
2. If the application implements account lockout after multiple failed attempts
3. If the application enforces proper OTP security measures

Usage:
    python otp_brute_force_test.py [target_url] [username] [password]

Example:
    python otp_brute_force_test.py https://localhost:8000/two_factor/ admin password123
"""

import requests
import sys
import time
import re
import random
import logging
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('otp_brute_force_test.log')
    ]
)
logger = logging.getLogger(__name__)

class OTPBruteForceTest:
    def __init__(self, target_url, username, password):
        self.target_url = target_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.authenticated = False
        self.otp_url = None
        self.total_attempts = 0
        self.start_time = None
        self.blocked = False
        self.timeout = 20  # Request timeout in seconds
        self.csrf_token = None
        self.error_patterns = [
            r'incorrect code',
            r'invalid token',
            r'invalid otp',
            r'wrong code',
            r'verification failed',
            r'code expired',
            r'invalid verification',
            r'failed attempt',
            r'otp failed',
            r'invalid authentication',
            r'locked',
            r'too many attempts'
        ]
        self.success_patterns = [
            r'authenticated',
            r'verified',
            r'welcome',
            r'dashboard',
            r'logged in',
            r'success'
        ]
        self.lockout_patterns = [
            r'locked',
            r'too many attempts',
            r'temporarily blocked',
            r'try again later',
            r'account disabled',
            r'exceeded maximum',
            r'suspended'
        ]

    def login(self):
        """Attempt to log in with the provided username and password"""
        logger.info(f"Attempting to log in as {self.username}")
        
        try:
            # Get the login page to extract CSRF token
            response = self.session.get(self.target_url, verify=False, timeout=self.timeout)
            
            if response.status_code != 200:
                logger.error(f"Error accessing login page. Status code: {response.status_code}")
                return False

            # Extract CSRF token
            self.csrf_token = self._get_csrf_token(response)
            if not self.csrf_token:
                logger.error("Could not extract CSRF token. Site may be protected.")
                return False

            # Prepare login data
            login_data = {
                'csrfmiddlewaretoken': self.csrf_token,
                'username': self.username,
                'password': self.password
            }
            
            # Add captcha if needed (we'll use a dummy value)
            if 'captcha' in response.text.lower():
                logger.warning("CAPTCHA detected. Testing will likely fail.")
                login_data['captcha'] = '12345'  # Dummy value

            # Submit login form
            login_response = self.session.post(
                self.target_url,
                data=login_data,
                headers={'Referer': self.target_url},
                verify=False,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Check if we're redirected to OTP verification page
            self.otp_url = login_response.url
            
            # Check if we need to extract the OTP URL from the response
            if "otp" in login_response.text.lower() or "verification" in login_response.text.lower() or "two-factor" in login_response.text.lower():
                # Look for OTP form action URL
                otp_form_match = re.search(r'<form[^>]*action="([^"]*)"[^>]*id="[^"]*otp[^"]*"', login_response.text, re.IGNORECASE)
                if otp_form_match:
                    otp_action = otp_form_match.group(1)
                    # Handle relative URLs
                    if otp_action.startswith('/'):
                        base_url = '/'.join(self.target_url.split('/')[:3])  # http(s)://domain.com
                        self.otp_url = base_url + otp_action
                    elif not otp_action.startswith('http'):
                        self.otp_url = self.target_url.rstrip('/') + '/' + otp_action.lstrip('/')
                    else:
                        self.otp_url = otp_action
            
            # Re-extract CSRF token from current page
            self.csrf_token = self._get_csrf_token(login_response)
            
            logger.info(f"Logged in successfully. OTP URL: {self.otp_url}")
            self.authenticated = True
            return True
            
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

    def _generate_otp_code(self, length=6):
        """Generate a random OTP code of specified length"""
        return ''.join(random.choices('0123456789', k=length))

    def _detect_otp_length(self, response_text):
        """Try to detect the OTP code length from the response"""
        # Look for input fields with maxlength attribute
        maxlength_match = re.search(r'<input[^>]*name="otp"[^>]*maxlength="(\d+)"', response_text, re.IGNORECASE)
        if maxlength_match:
            return int(maxlength_match.group(1))
        
        # Look for other common OTP input field patterns
        for pattern in [
            r'<input[^>]*name="token"[^>]*maxlength="(\d+)"',
            r'<input[^>]*name="code"[^>]*maxlength="(\d+)"',
            r'<input[^>]*name="verification_code"[^>]*maxlength="(\d+)"'
        ]:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return int(match.group(1))
        
        # Default to 6 digits (most common)
        return 6

    def _detect_otp_field_name(self, response_text):
        """Try to detect the OTP field name from the response"""
        # Look for common OTP field names
        for field_name in ['otp', 'token', 'code', 'verification_code', 'auth_code', 'totp', 'otp_token']:
            if re.search(f'name="{field_name}"', response_text, re.IGNORECASE):
                return field_name
        
        # Default to 'otp'
        return 'otp'

    def attempt_otp(self, otp_code, attempt_num):
        """Try to authenticate with the given OTP code"""
        if self.blocked:
            logger.warning("Testing blocked due to rate limiting or account lockout")
            return False
        
        try:
            # Get current OTP page to extract latest CSRF token if needed
            if not self.csrf_token:
                response = self.session.get(self.otp_url, verify=False, timeout=self.timeout)
                self.csrf_token = self._get_csrf_token(response)
                
                # Detect OTP field name and length
                otp_field_name = self._detect_otp_field_name(response.text)
                otp_length = self._detect_otp_length(response.text)
                logger.info(f"Detected OTP field: {otp_field_name}, length: {otp_length}")
                
                # If OTP code length doesn't match, regenerate it
                if len(otp_code) != otp_length:
                    otp_code = self._generate_otp_code(otp_length)
            else:
                # Use default field name if we didn't get a chance to detect it
                otp_field_name = 'otp'
            
            # Prepare OTP verification data
            otp_data = {
                'csrfmiddlewaretoken': self.csrf_token,
                otp_field_name: otp_code
            }
            
            logger.info(f"Attempt {attempt_num}: Trying OTP code: {otp_code}")
            
            # Submit OTP form
            otp_response = self.session.post(
                self.otp_url,
                data=otp_data,
                headers={'Referer': self.otp_url},
                verify=False,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Update CSRF token for next attempt
            self.csrf_token = self._get_csrf_token(otp_response)
            
            # Increment attempt counter
            self.total_attempts += 1
            
            # Check for rate limiting (429 Too Many Requests)
            if otp_response.status_code == 429:
                logger.warning(f"Rate limit detected after {self.total_attempts} attempts!")
                self.blocked = True
                return False
            
            # Check for account lockout message
            response_text_lower = otp_response.text.lower()
            for pattern in self.lockout_patterns:
                if re.search(pattern, response_text_lower):
                    logger.warning(f"Account lockout detected after {self.total_attempts} attempts!")
                    self.blocked = True
                    return False
            
            # Check for successful authentication
            for pattern in self.success_patterns:
                if re.search(pattern, response_text_lower):
                    logger.info(f"OTP verification successful with code: {otp_code}")
                    return True
            
            # Check for specific error messages
            for pattern in self.error_patterns:
                if re.search(pattern, response_text_lower):
                    logger.info(f"OTP verification failed with code: {otp_code}")
                    return False
            
            # If we got a redirect to a new page, it might be a success
            if otp_response.url != self.otp_url:
                logger.info(f"Redirected to {otp_response.url} after OTP submission. Possible success.")
                # Check for logout link which would indicate successful login
                if "logout" in otp_response.text.lower():
                    logger.info(f"OTP verification successful with code: {otp_code}")
                    return True
            
            logger.info(f"OTP verification result unclear for code: {otp_code}")
            return False
            
        except Exception as e:
            logger.error(f"Error during OTP attempt: {e}")
            return False

    def run_sequential_test(self, max_attempts=100, otp_length=6):
        """Run a sequential OTP brute force test"""
        if not self.authenticated or not self.otp_url:
            logger.error("Not authenticated or OTP URL not found. Login first.")
            return
        
        logger.info(f"\n[*] Starting sequential OTP brute force test")
        logger.info(f"[*] Target URL: {self.otp_url}")
        logger.info(f"[*] Username: {self.username}")
        logger.info(f"[*] Maximum attempts: {max_attempts}")
        logger.info(f"[*] OTP length: {otp_length}")
        
        self.start_time = datetime.now()
        self.blocked = False
        self.total_attempts = 0
        
        # Random starting point to avoid always testing from 000000
        start = random.randint(0, 10**otp_length - 1)
        
        for i in range(max_attempts):
            # Generate OTP code
            otp_code = str(start % (10**otp_length)).zfill(otp_length)
            start += 1
            
            # Add a small delay between requests to avoid overwhelming the server
            time.sleep(0.5)
            
            if self.attempt_otp(otp_code, i+1):
                logger.info(f"\n[SUCCESS] Found valid OTP code after {i+1} attempts: {otp_code}")
                break
                
            if self.blocked:
                logger.warning(f"\n[BLOCKED] Testing stopped after {i+1} attempts due to blocking/rate limiting")
                break
            
            # Every 10 attempts, report progress
            if (i+1) % 10 == 0:
                elapsed = datetime.now() - self.start_time
                rate = (i+1) / elapsed.total_seconds()
                logger.info(f"Progress: {i+1}/{max_attempts} attempts ({rate:.2f} attempts/second)")
        
        test_duration = datetime.now() - self.start_time
        
        logger.info(f"\n[SUMMARY] Sequential Test Complete")
        logger.info(f"Total attempts: {self.total_attempts}")
        logger.info(f"Test duration: {test_duration}")
        
        if self.blocked:
            logger.info("Result: PASS - Application implemented rate limiting or account lockout")
        elif self.total_attempts >= max_attempts:
            logger.info(f"Result: INCONCLUSIVE - Reached maximum attempts ({max_attempts}) without success or blocking")
        else:
            logger.info("Result: FAIL - Found valid OTP code through brute force")

    def run_parallel_test(self, max_attempts=100, max_workers=5, otp_length=6):
        """Run a parallel OTP brute force test with multiple threads"""
        if not self.authenticated or not self.otp_url:
            logger.error("Not authenticated or OTP URL not found. Login first.")
            return
        
        logger.info(f"\n[*] Starting parallel OTP brute force test")
        logger.info(f"[*] Target URL: {self.otp_url}")
        logger.info(f"[*] Username: {self.username}")
        logger.info(f"[*] Maximum attempts: {max_attempts}")
        logger.info(f"[*] Parallel workers: {max_workers}")
        logger.info(f"[*] OTP length: {otp_length}")
        
        self.start_time = datetime.now()
        self.blocked = False
        self.total_attempts = 0
        
        # Generate a list of OTP codes to try
        # Start from a random point to avoid always testing from 000000
        start = random.randint(0, 10**otp_length - 1)
        otp_codes = [str((start + i) % (10**otp_length)).zfill(otp_length) for i in range(max_attempts)]
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            
            for i, otp_code in enumerate(otp_codes):
                # Create a new session for each thread to avoid session conflicts
                self.session = requests.Session()
                
                # Re-login for each thread to ensure proper session
                if not self.login():
                    logger.error("Failed to log in again for parallel test")
                    break
                
                # Submit the OTP attempt task
                futures.append(executor.submit(self.attempt_otp, otp_code, i+1))
                
                # Add a small delay between thread starts to avoid overwhelming the server
                time.sleep(0.1)
                
                # Check if we're already blocked or found a valid code
                if self.blocked:
                    break
                
                if any(f.result() for f in futures if f.done()):
                    break
        
        test_duration = datetime.now() - self.start_time
        
        logger.info(f"\n[SUMMARY] Parallel Test Complete")
        logger.info(f"Total attempts: {self.total_attempts}")
        logger.info(f"Test duration: {test_duration}")
        
        if self.blocked:
            logger.info("Result: PASS - Application implemented rate limiting or account lockout")
        elif self.total_attempts >= max_attempts:
            logger.info(f"Result: INCONCLUSIVE - Reached maximum attempts ({max_attempts}) without success or blocking")
        else:
            logger.info("Result: FAIL - Found valid OTP code through brute force")

    def run_test(self, max_sequential=50, max_parallel=50, max_workers=5):
        """Run both sequential and parallel OTP brute force tests"""
        # First, login to get to the OTP page
        if not self.login():
            logger.error("Failed to log in. OTP testing cannot proceed.")
            return
        
        # Run sequential test
        self.run_sequential_test(max_attempts=max_sequential)
        
        # Reset session for parallel test
        self.session = requests.Session()
        self.authenticated = False
        self.otp_url = None
        self.csrf_token = None
        
        # Login again for parallel test
        if not self.login():
            logger.error("Failed to log in again for parallel test")
            return
        
        # Run parallel test
        self.run_parallel_test(max_attempts=max_parallel, max_workers=max_workers)
        
        # Provide recommendations
        logger.info("\n[RECOMMENDATIONS]")
        logger.info("To properly secure OTP/2FA:")
        logger.info("1. Implement strict rate limiting (e.g., 3-5 attempts per minute)")
        logger.info("2. Lock accounts after 5-10 failed attempts")
        logger.info("3. Require re-authentication after failed OTP attempts")
        logger.info("4. Use TOTP with secure seed generation")
        logger.info("5. Implement OTP expiration (30-60 seconds)")
        logger.info("6. Use longer OTP codes (8+ digits) or alphanumeric codes")
        logger.info("7. Notify users of failed OTP attempts")
        logger.info("8. Add delays between attempts that increase with each failure")

def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} [target_url] [username] [password]")
        print(f"Example: {sys.argv[0]} https://localhost:8000/two_factor/ admin password123")
        sys.exit(1)
    
    target_url = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    
    tester = OTPBruteForceTest(target_url, username, password)
    tester.run_test()

if __name__ == "__main__":
    main()