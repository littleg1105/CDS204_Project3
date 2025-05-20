#!/usr/bin/env python
"""
User Enumeration Test Script

This script tests if an application allows user enumeration, which is the ability
to determine whether a username exists in the system based on different responses
or behaviors from the application.

The script checks:
1. Different response texts for existing vs non-existing users
2. Different status codes
3. Different response times
4. Different redirects or behaviors

Usage:
    python user_enumeration_test.py [target_url] [known_username]

Example:
    python user_enumeration_test.py https://localhost:8000/login/ admin
"""

import requests
import sys
import time
import re
import statistics
import json
from urllib3.exceptions import InsecureRequestWarning
from tabulate import tabulate

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class UserEnumerationTest:
    def __init__(self, target_url, known_username):
        self.target_url = target_url
        self.known_username = known_username
        self.session = requests.Session()
        self.test_usernames = self._generate_test_usernames()
        self.results = {}

    def _generate_test_usernames(self):
        """Generate test usernames including the known one and some fake ones"""
        return [
            self.known_username,
            "nonexistent_user",
            "fake_user123",
            "test_user_789",
            "admin123",
            "administrator",
            "root",
            "system",
            "guest",
            "user"
        ]

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

    def test_username(self, username):
        """Test a single username and record results"""
        try:
            # Get the login page to extract CSRF token
            response = self.session.get(self.target_url, verify=False, timeout=10)
            
            if response.status_code != 200:
                print(f"Error accessing login page. Status code: {response.status_code}")
                return None

            # Extract CSRF token
            csrf_token = self._get_csrf_token(response)
            if not csrf_token:
                print("Could not extract CSRF token. Site may be protected.")
                return None

            # Prepare login data with an intentionally wrong password
            login_data = {
                'csrfmiddlewaretoken': csrf_token,
                'username': username,
                'password': 'wrong_password'  # Intentionally wrong password
            }
            
            # Add captcha if needed (we'll skip actual solving)
            if 'captcha' in response.text.lower():
                login_data['captcha'] = '12345'  # Dummy value

            # Submit login form and measure time
            start_time = time.time()
            login_response = self.session.post(
                self.target_url,
                data=login_data,
                headers={'Referer': self.target_url},
                verify=False,
                timeout=10
            )
            response_time = time.time() - start_time
            
            # Record results
            result = {
                'username': username,
                'status_code': login_response.status_code,
                'response_time': response_time,
                'response_length': len(login_response.text),
                'redirect_url': login_response.url,
                'error_message': self._extract_error_message(login_response.text),
                'is_known_user': username == self.known_username
            }
            
            return result
            
        except Exception as e:
            print(f"Error testing username '{username}': {e}")
            return None

    def _extract_error_message(self, html_content):
        """Extract error message from HTML response"""
        # Look for common error message patterns
        error_patterns = [
            r'<div[^>]*class="[^"]*error[^"]*"[^>]*>(.*?)</div>',
            r'<div[^>]*class="[^"]*alert[^"]*"[^>]*>(.*?)</div>',
            r'<p[^>]*class="[^"]*error[^"]*"[^>]*>(.*?)</p>',
            r'<span[^>]*class="[^"]*error[^"]*"[^>]*>(.*?)</span>'
        ]
        
        for pattern in error_patterns:
            matches = re.findall(pattern, html_content, re.DOTALL)
            if matches:
                # Clean up the error message
                error = re.sub(r'<[^>]*>', '', matches[0])
                return error.strip()
        
        return None

    def run_test(self, iterations=3):
        """Run the user enumeration test"""
        print(f"\n[*] Starting user enumeration test at {self.target_url}")
        print(f"[*] Known username: {self.known_username}")
        print(f"[*] Testing {len(self.test_usernames)} usernames with {iterations} iterations each...\n")
        
        all_results = []
        
        # Test each username multiple times
        for username in self.test_usernames:
            username_results = []
            for i in range(iterations):
                print(f"Testing '{username}' (iteration {i+1}/{iterations})...")
                result = self.test_username(username)
                if result:
                    username_results.append(result)
                # Reset session between tests
                self.session = requests.Session()
                # Small delay to avoid rate limiting
                time.sleep(1)
            
            if username_results:
                # Calculate average response time
                avg_response_time = statistics.mean([r['response_time'] for r in username_results])
                # Calculate average response length
                avg_response_length = statistics.mean([r['response_length'] for r in username_results])
                
                # Store aggregated result
                aggregated_result = username_results[0].copy()
                aggregated_result['response_time'] = avg_response_time
                aggregated_result['response_length'] = avg_response_length
                all_results.append(aggregated_result)
        
        self.results = all_results
        self.analyze_results()

    def analyze_results(self):
        """Analyze test results and determine if user enumeration is possible"""
        if not self.results:
            print("\n[!] No results to analyze.")
            return
        
        # Filter results for known and unknown users
        known_results = [r for r in self.results if r['is_known_user']]
        unknown_results = [r for r in self.results if not r['is_known_user']]
        
        if not known_results or not unknown_results:
            print("\n[!] Insufficient data for analysis.")
            return
        
        # Prepare data for reporting
        table_data = []
        for result in self.results:
            table_data.append([
                result['username'],
                "Yes" if result['is_known_user'] else "No",
                result['status_code'],
                f"{result['response_time']:.4f}s",
                result['response_length'],
                result['error_message'][:50] + "..." if result['error_message'] and len(result['error_message']) > 50 else result['error_message']
            ])
        
        # Display results table
        headers = ["Username", "Known User", "Status Code", "Response Time", "Response Length", "Error Message"]
        print("\n[RESULTS]")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # Analyze for differences that could allow enumeration
        differences = {}
        
        # Check status codes
        known_status = set(r['status_code'] for r in known_results)
        unknown_status = set(r['status_code'] for r in unknown_results)
        if known_status != unknown_status:
            differences['status_code'] = f"Different status codes: Known users {known_status}, Unknown users {unknown_status}"
        
        # Check response times
        known_times = [r['response_time'] for r in known_results]
        unknown_times = [r['response_time'] for r in unknown_results]
        avg_known_time = statistics.mean(known_times)
        avg_unknown_time = statistics.mean(unknown_times)
        time_diff_pct = abs(avg_known_time - avg_unknown_time) / max(avg_known_time, avg_unknown_time) * 100
        
        if time_diff_pct > 10:  # If time difference is more than 10%
            differences['response_time'] = f"Response time difference: {time_diff_pct:.2f}% (Known: {avg_known_time:.4f}s, Unknown: {avg_unknown_time:.4f}s)"
        
        # Check error messages
        known_errors = set(r['error_message'] for r in known_results if r['error_message'])
        unknown_errors = set(r['error_message'] for r in unknown_results if r['error_message'])
        if known_errors != unknown_errors:
            differences['error_message'] = f"Different error messages for known vs unknown users"
        
        # Check response lengths
        known_lengths = [r['response_length'] for r in known_results]
        unknown_lengths = [r['response_length'] for r in unknown_results]
        avg_known_length = statistics.mean(known_lengths)
        avg_unknown_length = statistics.mean(unknown_lengths)
        length_diff_pct = abs(avg_known_length - avg_unknown_length) / max(avg_known_length, avg_unknown_length) * 100
        
        if length_diff_pct > 5:  # If length difference is more than 5%
            differences['response_length'] = f"Response length difference: {length_diff_pct:.2f}% (Known: {avg_known_length:.0f}, Unknown: {avg_unknown_length:.0f})"
        
        # Report findings
        print("\n[ANALYSIS]")
        if differences:
            print("User enumeration may be possible based on the following differences:")
            for key, value in differences.items():
                print(f"- {value}")
                
            print("\n[RECOMMENDATION]")
            print("The application should be updated to ensure consistent responses for both valid and invalid usernames:")
            print("- Use generic error messages for all login failures")
            print("- Ensure consistent response times between valid and invalid usernames")
            print("- Return the same HTTP status codes regardless of username validity")
            print("- Make response size consistent for all login attempts")
        else:
            print("No significant differences detected between known and unknown users.")
            print("The application appears to be resistant to user enumeration attacks.")

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} [target_url] [known_username]")
        print(f"Example: {sys.argv[0]} https://localhost:8000/login/ admin")
        sys.exit(1)
    
    target_url = sys.argv[1]
    known_username = sys.argv[2]
    
    try:
        # Verify that tabulate is installed
        import tabulate
    except ImportError:
        print("[!] The 'tabulate' package is required. Install it with 'pip install tabulate'.")
        sys.exit(1)
    
    tester = UserEnumerationTest(target_url, known_username)
    tester.run_test()

if __name__ == "__main__":
    main()