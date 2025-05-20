#!/usr/bin/env python
"""
Security Headers Checker

This script checks a website for important security headers including
Content-Security-Policy, X-XSS-Protection, and others.

Usage: python check_security_headers.py [url]
If no URL is provided, it defaults to https://localhost:8000
"""

import sys
import requests
import argparse
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress SSL verification warnings for local testing with self-signed certs
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def check_security_headers(url):
    """
    Check security headers for the given URL
    """
    try:
        # Make request without verifying SSL for local development
        response = requests.get(url, verify=False, timeout=10)
        headers = response.headers
        
        # Important security headers to check
        security_headers = {
            'Content-Security-Policy': 'Sets allowed sources for content',
            'X-XSS-Protection': 'Helps prevent cross-site scripting attacks',
            'X-Content-Type-Options': 'Prevents MIME-type sniffing',
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'Strict-Transport-Security': 'Forces HTTPS connections',
            'Referrer-Policy': 'Controls how much referrer information is included',
            'Permissions-Policy': 'Controls browser features available to the site',
            'Cache-Control': 'Controls browser caching behavior'
        }
        
        print(f"\n🔐 Security Headers Check for {url}")
        print("="*60)
        print(f"Status Code: {response.status_code}")
        print("="*60)
        
        missing_headers = []
        
        for header, description in security_headers.items():
            if header.lower() in [h.lower() for h in headers.keys()]:
                # Get the actual header name with correct case
                actual_header = next(h for h in headers.keys() if h.lower() == header.lower())
                print(f"✅ {header}: {headers[actual_header]}")
                print(f"   📝 {description}")
            else:
                print(f"❌ {header} is missing!")
                print(f"   📝 {description}")
                missing_headers.append(header)
        
        # Print summary
        print("\n"+"="*60)
        if missing_headers:
            print(f"⚠️  Missing {len(missing_headers)} security headers:")
            for header in missing_headers:
                print(f"   - {header}")
        else:
            print("🎉 All security headers are present! Well done!")
        
        # Additional CSP analysis if present
        if 'Content-Security-Policy' in headers or 'content-security-policy' in [h.lower() for h in headers.keys()]:
            header_name = next((h for h in headers.keys() if h.lower() == 'content-security-policy'), 'Content-Security-Policy')
            csp = headers[header_name]
            print("\nContent Security Policy Analysis:")
            print("-"*60)
            
            for directive in csp.split(';'):
                if directive.strip():
                    print(f"   {directive.strip()}")
        
        return not missing_headers
        
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to {url}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Check security headers on a website')
    parser.add_argument('url', nargs='?', default='https://localhost:8000', 
                        help='URL to check (default: https://localhost:8000)')
    args = parser.parse_args()
    
    # Ensure URL has a scheme
    url = args.url
    if not urlparse(url).scheme:
        url = 'https://' + url
    
    check_security_headers(url)

if __name__ == "__main__":
    main()