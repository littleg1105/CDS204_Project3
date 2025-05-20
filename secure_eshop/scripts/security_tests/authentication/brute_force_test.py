#!/usr/bin/env python
"""
Brute Force Attack Test Script

This script tests the application's resistance to brute force attacks by
attempting to login with a known username and multiple password combinations.

The script checks:
1. If the application implements rate limiting
2. If login attempts are properly tracked
3. If account lockout is implemented

Usage:
    python brute_force_test.py [username] [target_url]

Example:
    python brute_force_test.py admin https://localhost:8000/login/
"""

import requests
import sys
import time
import re
import random
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class BruteForceTest:
    def __init__(self, username, target_url):
        self.username = username
        self.target_url = target_url
        self.session = requests.Session()
        self.passwords = self._generate_passwords()
        self.total_attempts = 0
        self.blocked = False
        self.start_time = None
        self.last_status_code = None
        self.last_response_time = None

    def _generate_passwords(self):
        """Generate a list of passwords for testing"""
        common_passwords = [
            "password", "123456", "admin", "welcome", "password123",
            "12345678", "qwerty", "111111", "1234567890", "admin123",
            "letmein", "welcome1", "monkey", "1234", "sunshine", "654321",
            "trustno1", "dragon", "baseball", "football", "superman"
        ]
        # Add some random passwords
        random_passwords = [f"test{random.randint(1000, 9999)}" for _ in range(10)]
        return common_passwords + random_passwords

    def _get_csrf_token(self, response):
        """Extract CSRF token from the response"""
        try:
            csrf = re.search('name="csrfmiddlewaretoken" value="(.+?)"', response.text)
            if csrf:
                return csrf.group(1)
            return None
        except Exception as e:
            print(f"Error extracting CSRF token: {e}")
            return None

    def _get_captcha_answer(self, response):
        """
        This would need to be implemented with OCR or manual entry in a real test.
        For this demo, we'll just return None to simulate a failed CAPTCHA.
        """
        return None

    def attempt_login(self, password, attempt_num):
        """Attempt to login with the given password"""
        if self.blocked:
            return False

        try:
            # Get the login page to extract CSRF token
            start_time = time.time()
            response = self.session.get(self.target_url, verify=False, timeout=10)
            self.last_status_code = response.status_code
            
            if response.status_code != 200:
                print(f"Error accessing login page. Status code: {response.status_code}")
                return False

            # Extract CSRF token
            csrf_token = self._get_csrf_token(response)
            if not csrf_token:
                print("Could not extract CSRF token. Site may be protected.")
                return False

            # Extract CAPTCHA (would need implementation for real testing)
            captcha_answer = self._get_captcha_answer(response)

            # Prepare login data
            login_data = {
                'csrfmiddlewaretoken': csrf_token,
                'username': self.username,
                'password': password,
            }
            
            # Add captcha if needed
            if 'captcha' in response.text.lower():
                if captcha_answer:
                    login_data['captcha'] = captcha_answer
                else:
                    print("CAPTCHA detected but could not solve it.")
                    return False

            # Submit login form
            login_response = self.session.post(
                self.target_url,
                data=login_data,
                headers={'Referer': self.target_url},
                verify=False,
                timeout=10
            )
            
            end_time = time.time()
            self.last_response_time = end_time - start_time
            self.last_status_code = login_response.status_code
            self.total_attempts += 1

            # Check for rate limiting (429 Too Many Requests)
            if login_response.status_code == 429:
                print(f"[{attempt_num}] Rate limit detected after {self.total_attempts} attempts!")
                self.blocked = True
                return False

            # Check for account lockout message
            if "locked" in login_response.text.lower() or "too many" in login_response.text.lower():
                print(f"[{attempt_num}] Account lockout detected after {self.total_attempts} attempts!")
                self.blocked = True
                return False

            # Check for successful login (redirect to dashboard, etc.)
            if "logout" in login_response.text.lower() or "dashboard" in login_response.text.lower():
                print(f"[{attempt_num}] Login successful with password: {password}")
                return True
                
            print(f"[{attempt_num}] Failed login with password: {password}")
            return False
            
        except Exception as e:
            print(f"Error during login attempt: {e}")
            return False

    def run_sequential_test(self):
        """Run a sequential brute force test"""
        print(f"\n[*] Starting sequential brute force test at {self.target_url}")
        print(f"[*] Target username: {self.username}")
        print(f"[*] Testing {len(self.passwords)} passwords...\n")
        
        self.start_time = datetime.now()
        self.blocked = False
        self.total_attempts = 0
        
        for i, password in enumerate(self.passwords, 1):
            # Add a small delay between requests to avoid overwhelming the server
            time.sleep(0.5)
            
            if self.attempt_login(password, i):
                print(f"\n[SUCCESS] Found valid password after {i} attempts: {password}")
                break
                
            if self.blocked:
                print(f"\n[BLOCKED] Testing stopped after {i} attempts due to blocking/rate limiting")
                break
        
        test_duration = datetime.now() - self.start_time
        print(f"\n[SUMMARY] Sequential Test Complete")
        print(f"Total attempts: {self.total_attempts}")
        print(f"Test duration: {test_duration}")
        print(f"Last response time: {self.last_response_time:.2f} seconds")
        print(f"Last status code: {self.last_status_code}")
        
        if self.blocked:
            print("Result: PASS - Site implemented rate limiting or account lockout")
        else:
            print("Result: FAIL - Site allowed unlimited login attempts")

    def run_parallel_test(self, max_workers=5):
        """Run a parallel brute force test with multiple threads"""
        print(f"\n[*] Starting parallel brute force test at {self.target_url}")
        print(f"[*] Target username: {self.username}")
        print(f"[*] Testing {len(self.passwords)} passwords with {max_workers} parallel threads...\n")
        
        self.start_time = datetime.now()
        self.blocked = False
        self.total_attempts = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.attempt_login, password, i+1): password 
                      for i, password in enumerate(self.passwords)}
            
            for future in futures:
                if future.result():
                    print(f"\n[SUCCESS] Found valid password: {futures[future]}")
                    break
                
                if self.blocked:
                    break
        
        test_duration = datetime.now() - self.start_time
        print(f"\n[SUMMARY] Parallel Test Complete")
        print(f"Total attempts: {self.total_attempts}")
        print(f"Test duration: {test_duration}")
        print(f"Last response time: {self.last_response_time:.2f} seconds")
        print(f"Last status code: {self.last_status_code}")
        
        if self.blocked:
            print("Result: PASS - Site implemented rate limiting or account lockout")
        else:
            print("Result: FAIL - Site allowed unlimited login attempts")

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} [username] [target_url]")
        print(f"Example: {sys.argv[0]} admin https://localhost:8000/login/")
        sys.exit(1)
    
    username = sys.argv[1]
    target_url = sys.argv[2]
    
    tester = BruteForceTest(username, target_url)
    
    # Run sequential test
    tester.run_sequential_test()
    
    # Reset session for parallel test
    tester.session = requests.Session()
    
    # Run parallel test
    tester.run_parallel_test()

if __name__ == "__main__":
    main()