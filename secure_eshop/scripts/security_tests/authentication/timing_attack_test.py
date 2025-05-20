#!/usr/bin/env python
"""
Timing Attack Test Script

This script tests if an application is vulnerable to timing attacks. Timing attacks
can be used to determine whether a username exists or to incrementally guess a
password by measuring response times.

The script checks:
1. Response time differences between valid and invalid usernames
2. Response time differences based on password length
3. Response time patterns that could leak information

Usage:
    python timing_attack_test.py [target_url] [known_username] [optional_known_password]

Example:
    python timing_attack_test.py https://localhost:8000/login/ admin password123
"""

import requests
import sys
import time
import re
import statistics
import numpy as np
import matplotlib.pyplot as plt
from urllib3.exceptions import InsecureRequestWarning
from tabulate import tabulate

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class TimingAttackTest:
    def __init__(self, target_url, known_username, known_password=None):
        self.target_url = target_url
        self.known_username = known_username
        self.known_password = known_password
        self.session = requests.Session()
        self.results = {
            'username_tests': [],
            'password_tests': []
        }

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

    def _measure_login_time(self, username, password):
        """Measure the time it takes to try a login"""
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

            # Prepare login data
            login_data = {
                'csrfmiddlewaretoken': csrf_token,
                'username': username,
                'password': password
            }
            
            # Add captcha if needed (we'll use a dummy value)
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
            
            # Result
            result = {
                'username': username,
                'password': password,
                'response_time': response_time,
                'status_code': login_response.status_code,
                'response_length': len(login_response.text),
            }
            
            return result
            
        except Exception as e:
            print(f"Error measuring login time: {e}")
            return None

    def test_username_timing(self, iterations=10):
        """Test timing differences based on username validity"""
        print(f"\n[*] Testing username timing differences ({iterations} iterations each)...")
        
        # Define test usernames
        test_usernames = [
            self.known_username,  # Known username
            "nonexistent_user",   # Non-existent username
            "another_fake_user",  # Another non-existent username
            "test_user_123",      # Another non-existent username
            "admin123"            # Similar to common admin username
        ]
        
        # Use a random password for all tests
        test_password = "incorrect_password"
        
        # Test each username
        username_results = {}
        
        for username in test_usernames:
            print(f"Testing username: {username}")
            results = []
            
            for i in range(iterations):
                print(f"  Iteration {i+1}/{iterations}", end="\r")
                result = self._measure_login_time(username, test_password)
                if result:
                    results.append(result)
                # Reset session between tests
                self.session = requests.Session()
                # Small delay to avoid rate limiting
                time.sleep(1)
            
            print(f"Completed testing username: {username}                ")
            
            if results:
                # Calculate statistics
                response_times = [r['response_time'] for r in results]
                username_results[username] = {
                    'mean': statistics.mean(response_times),
                    'median': statistics.median(response_times),
                    'min': min(response_times),
                    'max': max(response_times),
                    'std_dev': statistics.stdev(response_times) if len(response_times) > 1 else 0,
                    'is_known': username == self.known_username,
                    'raw_times': response_times
                }
        
        self.results['username_tests'] = username_results
        return username_results

    def test_password_timing(self, iterations=10):
        """Test timing differences based on password characteristics"""
        print(f"\n[*] Testing password timing differences ({iterations} iterations each)...")
        
        # Only run this test if we have a known username
        if not self.known_username:
            print("Skipping password timing test - no known username provided")
            return {}
        
        # Define test passwords with varying lengths and correctness
        test_passwords = [
            "",                     # Empty password
            "a",                    # Very short password
            "password",             # Common password
            "a" * 10,               # 10 character password
            "a" * 20,               # 20 character password
            "a" * 50,               # 50 character password
        ]
        
        # Add the known password if provided
        if self.known_password:
            test_passwords.append(self.known_password)
        
        # Test each password
        password_results = {}
        
        for password in test_passwords:
            display_pwd = password if len(password) <= 10 else f"{password[:10]}... ({len(password)} chars)"
            print(f"Testing password: {display_pwd}")
            results = []
            
            for i in range(iterations):
                print(f"  Iteration {i+1}/{iterations}", end="\r")
                result = self._measure_login_time(self.known_username, password)
                if result:
                    results.append(result)
                # Reset session between tests
                self.session = requests.Session()
                # Small delay to avoid rate limiting
                time.sleep(1)
            
            print(f"Completed testing password: {display_pwd}                ")
            
            if results:
                # Calculate statistics
                response_times = [r['response_time'] for r in results]
                password_results[password] = {
                    'length': len(password),
                    'mean': statistics.mean(response_times),
                    'median': statistics.median(response_times),
                    'min': min(response_times),
                    'max': max(response_times),
                    'std_dev': statistics.stdev(response_times) if len(response_times) > 1 else 0,
                    'is_correct': password == self.known_password if self.known_password else False,
                    'raw_times': response_times
                }
        
        self.results['password_tests'] = password_results
        return password_results

    def analyze_results(self):
        """Analyze the test results and determine if timing attacks are possible"""
        print("\n[ANALYSIS]")
        
        # Analyze username timing differences
        if self.results['username_tests']:
            self._analyze_username_results()
        
        # Analyze password timing differences
        if self.results['password_tests']:
            self._analyze_password_results()
        
        # Generate visualizations
        self._generate_visualizations()

    def _analyze_username_results(self):
        """Analyze the username timing test results"""
        username_results = self.results['username_tests']
        
        print("\n[USERNAME TIMING ANALYSIS]")
        
        # Prepare data for the table
        table_data = []
        for username, data in username_results.items():
            table_data.append([
                username,
                "Yes" if data['is_known'] else "No",
                f"{data['mean']:.6f}s",
                f"{data['median']:.6f}s",
                f"{data['min']:.6f}s",
                f"{data['max']:.6f}s",
                f"{data['std_dev']:.6f}s"
            ])
        
        # Display results table
        headers = ["Username", "Known", "Mean Time", "Median Time", "Min Time", "Max Time", "Std Dev"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # Extract known and unknown user data
        known_users = {u: data for u, data in username_results.items() if data['is_known']}
        unknown_users = {u: data for u, data in username_results.items() if not data['is_known']}
        
        if not known_users or not unknown_users:
            print("Insufficient data for username timing analysis.")
            return
        
        # Calculate average times
        known_avg = statistics.mean([data['mean'] for data in known_users.values()])
        unknown_avg = statistics.mean([data['mean'] for data in unknown_users.values()])
        
        # Calculate time difference percentage
        time_diff_pct = abs(known_avg - unknown_avg) / max(known_avg, unknown_avg) * 100
        
        print(f"\nAverage response time for known usernames: {known_avg:.6f}s")
        print(f"Average response time for unknown usernames: {unknown_avg:.6f}s")
        print(f"Percentage difference: {time_diff_pct:.2f}%")
        
        # T-test to determine statistical significance
        try:
            from scipy import stats
            
            # Collect all response times for known and unknown users
            known_times = []
            for data in known_users.values():
                known_times.extend(data['raw_times'])
            
            unknown_times = []
            for data in unknown_users.values():
                unknown_times.extend(data['raw_times'])
            
            # Perform t-test
            t_stat, p_value = stats.ttest_ind(known_times, unknown_times, equal_var=False)
            
            print(f"T-test p-value: {p_value:.6f}")
            print(f"Statistical significance: {'Yes (p < 0.05)' if p_value < 0.05 else 'No (p >= 0.05)'}")
            
            # Vulnerability assessment
            if p_value < 0.05 and time_diff_pct > 5:
                print("\n[VULNERABILITY] The application may be vulnerable to username timing attacks.")
                print("There is a statistically significant difference in response times between known and unknown usernames.")
            else:
                print("\n[SECURE] The application appears to be resistant to username timing attacks.")
        
        except ImportError:
            print("\n[WARNING] SciPy not installed. Install with 'pip install scipy' for statistical analysis.")
            
            # Simple assessment without t-test
            if time_diff_pct > 10:
                print("\n[POSSIBLE VULNERABILITY] There may be a timing difference between known and unknown usernames.")
                print(f"The percentage difference ({time_diff_pct:.2f}%) is above the 10% threshold.")
            else:
                print("\n[LIKELY SECURE] No significant timing difference detected between known and unknown usernames.")

    def _analyze_password_results(self):
        """Analyze the password timing test results"""
        password_results = self.results['password_tests']
        
        print("\n[PASSWORD TIMING ANALYSIS]")
        
        # Prepare data for the table
        table_data = []
        for password, data in password_results.items():
            display_pwd = password if len(password) <= 10 else f"{password[:10]}... ({len(password)} chars)"
            table_data.append([
                display_pwd,
                data['length'],
                "Yes" if data['is_correct'] else "No",
                f"{data['mean']:.6f}s",
                f"{data['median']:.6f}s",
                f"{data['min']:.6f}s",
                f"{data['max']:.6f}s",
                f"{data['std_dev']:.6f}s"
            ])
        
        # Display results table
        headers = ["Password", "Length", "Correct", "Mean Time", "Median Time", "Min Time", "Max Time", "Std Dev"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # Check correlation between password length and response time
        lengths = [data['length'] for data in password_results.values()]
        times = [data['mean'] for data in password_results.values()]
        
        try:
            from scipy.stats import pearsonr
            
            # Calculate correlation coefficient
            corr, p_value = pearsonr(lengths, times)
            
            print(f"\nCorrelation between password length and response time: {corr:.4f}")
            print(f"Correlation p-value: {p_value:.6f}")
            
            # Check if correlation is statistically significant
            if p_value < 0.05 and abs(corr) > 0.5:
                print("\n[VULNERABILITY] There appears to be a significant correlation between password length and response time.")
                print("This could potentially be exploited in a timing attack.")
            else:
                print("\n[SECURE] No significant correlation between password length and response time was detected.")
        
        except ImportError:
            print("\n[WARNING] SciPy not installed. Install with 'pip install scipy' for correlation analysis.")
            
            # Simple linear regression without scipy
            if len(lengths) > 2:
                # Calculate correlation coefficient manually
                mean_x = sum(lengths) / len(lengths)
                mean_y = sum(times) / len(times)
                
                numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(lengths, times))
                denominator = (sum((x - mean_x) ** 2 for x in lengths) * sum((y - mean_y) ** 2 for y in times)) ** 0.5
                
                if denominator != 0:
                    corr = numerator / denominator
                    print(f"\nEstimated correlation between password length and response time: {corr:.4f}")
                    
                    if abs(corr) > 0.7:
                        print("\n[POSSIBLE VULNERABILITY] There may be a correlation between password length and response time.")
                    else:
                        print("\n[LIKELY SECURE] No strong correlation between password length and response time was detected.")
                else:
                    print("\n[ERROR] Could not calculate correlation (division by zero).")
            else:
                print("\n[ERROR] Insufficient data for correlation analysis.")
        
        # Check if correct password has a different timing
        if self.known_password and self.known_password in password_results:
            correct = password_results[self.known_password]
            incorrect = [data for pwd, data in password_results.items() if pwd != self.known_password]
            
            if incorrect:
                avg_incorrect_time = statistics.mean([data['mean'] for data in incorrect])
                time_diff_pct = abs(correct['mean'] - avg_incorrect_time) / max(correct['mean'], avg_incorrect_time) * 100
                
                print(f"\nCorrect password response time: {correct['mean']:.6f}s")
                print(f"Average incorrect password response time: {avg_incorrect_time:.6f}s")
                print(f"Percentage difference: {time_diff_pct:.2f}%")
                
                if time_diff_pct > 10:
                    print("\n[VULNERABILITY] There is a noticeable timing difference between correct and incorrect passwords.")
                    print("This could potentially be exploited in a timing attack.")
                else:
                    print("\n[SECURE] No significant timing difference between correct and incorrect passwords was detected.")

    def _generate_visualizations(self):
        """Generate visualizations of the timing test results"""
        try:
            # Generate username timing plot
            if self.results['username_tests']:
                plt.figure(figsize=(10, 6))
                
                usernames = []
                times = []
                colors = []
                
                for username, data in self.results['username_tests'].items():
                    usernames.append(username)
                    times.append(data['mean'])
                    colors.append('blue' if data['is_known'] else 'grey')
                
                plt.bar(usernames, times, color=colors)
                plt.xlabel('Username')
                plt.ylabel('Average Response Time (s)')
                plt.title('Username Timing Analysis')
                plt.grid(axis='y', linestyle='--', alpha=0.7)
                plt.xticks(rotation=45)
                
                # Add horizontal line at the average
                plt.axhline(y=sum(times)/len(times), color='red', linestyle='--', alpha=0.7)
                
                plt.tight_layout()
                output_file = 'username_timing_analysis.png'
                plt.savefig(output_file)
                print(f"\nSaved username timing visualization to {output_file}")
                plt.close()
            
            # Generate password timing plot
            if self.results['password_tests']:
                plt.figure(figsize=(10, 6))
                
                passwords = []
                times = []
                colors = []
                
                for password, data in self.results['password_tests'].items():
                    display_pwd = password if len(password) <= 10 else f"{password[:5]}...({len(password)})"
                    passwords.append(display_pwd)
                    times.append(data['mean'])
                    colors.append('green' if data['is_correct'] else 'grey')
                
                plt.bar(passwords, times, color=colors)
                plt.xlabel('Password')
                plt.ylabel('Average Response Time (s)')
                plt.title('Password Timing Analysis')
                plt.grid(axis='y', linestyle='--', alpha=0.7)
                plt.xticks(rotation=45)
                
                # Add horizontal line at the average
                plt.axhline(y=sum(times)/len(times), color='red', linestyle='--', alpha=0.7)
                
                plt.tight_layout()
                output_file = 'password_timing_analysis.png'
                plt.savefig(output_file)
                print(f"Saved password timing visualization to {output_file}")
                plt.close()
                
                # Generate password length correlation plot
                plt.figure(figsize=(10, 6))
                
                lengths = [data['length'] for data in self.results['password_tests'].values()]
                times = [data['mean'] for data in self.results['password_tests'].values()]
                
                plt.scatter(lengths, times)
                plt.xlabel('Password Length')
                plt.ylabel('Average Response Time (s)')
                plt.title('Password Length vs. Response Time')
                plt.grid(True, linestyle='--', alpha=0.7)
                
                # Add trend line
                if len(lengths) > 1:
                    z = np.polyfit(lengths, times, 1)
                    p = np.poly1d(z)
                    plt.plot(lengths, p(lengths), "r--")
                    
                    # Add correlation text
                    correlation = np.corrcoef(lengths, times)[0, 1]
                    plt.text(0.05, 0.95, f'Correlation: {correlation:.4f}', 
                             transform=plt.gca().transAxes, fontsize=10,
                             verticalalignment='top')
                
                plt.tight_layout()
                output_file = 'password_length_correlation.png'
                plt.savefig(output_file)
                print(f"Saved password length correlation visualization to {output_file}")
                plt.close()
        
        except Exception as e:
            print(f"\n[ERROR] Failed to generate visualizations: {e}")
            print("Make sure matplotlib and numpy are installed: 'pip install matplotlib numpy'")

    def run_test(self, username_iterations=10, password_iterations=10):
        """Run the full timing attack test suite"""
        print(f"\n[*] Starting timing attack test at {self.target_url}")
        print(f"[*] Target username: {self.known_username}")
        if self.known_password:
            print(f"[*] Target password provided (will be included in tests)")
        
        # Test username timing
        self.test_username_timing(iterations=username_iterations)
        
        # Test password timing
        self.test_password_timing(iterations=password_iterations)
        
        # Analyze results
        self.analyze_results()
        
        print("\n[RECOMMENDATIONS]")
        print("To prevent timing attacks, the application should:")
        print("1. Implement constant-time comparison for credentials (using secure functions like hmac.compare_digest)")
        print("2. Add random delays to response times")
        print("3. Ensure all authentication flows take approximately the same time")
        print("4. Implement rate limiting and account lockout")

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} [target_url] [known_username] [optional_known_password]")
        print(f"Example: {sys.argv[0]} https://localhost:8000/login/ admin password123")
        sys.exit(1)
    
    target_url = sys.argv[1]
    known_username = sys.argv[2]
    known_password = sys.argv[3] if len(sys.argv) > 3 else None
    
    try:
        # Verify that required packages are installed
        import tabulate
        import numpy
        import matplotlib.pyplot as plt
    except ImportError as e:
        missing_package = str(e).split("'")[1]
        print(f"[!] Required package '{missing_package}' is missing. Please install it with:")
        print(f"    pip install {missing_package}")
        print("[!] You may also need to install other packages: numpy, matplotlib, scipy, tabulate")
        sys.exit(1)
    
    tester = TimingAttackTest(target_url, known_username, known_password)
    tester.run_test()

if __name__ == "__main__":
    main()