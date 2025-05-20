#!/usr/bin/env python
"""
Security Test Runner

This script runs all security tests and compiles the results into a single report.

Usage:
    python run_all_tests.py [target_url] [username] [password] [db_path]

Example:
    python run_all_tests.py https://localhost:8000/ admin password123 db.sqlite3
"""

import sys
import os
import subprocess
import time
import datetime
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('security_test_report.log')
    ]
)
logger = logging.getLogger(__name__)

def run_test(test_script, args, description):
    """Run a specific security test"""
    logger.info(f"\n{'=' * 80}")
    logger.info(f"Running {description}")
    logger.info(f"{'=' * 80}")
    
    try:
        # Construct command arguments
        cmd = [sys.executable, test_script] + args
        
        # Run the test with output piped to both console and log
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Print output in real-time
        for line in process.stdout:
            print(line, end='')
            
        process.wait()
        
        if process.returncode == 0:
            logger.info(f"{description} completed successfully")
            return True
        else:
            logger.error(f"{description} failed with exit code {process.returncode}")
            return False
    
    except Exception as e:
        logger.error(f"Error running {description}: {e}")
        return False

def run_all_tests(target_url, username, password, db_path):
    """Run all security tests"""
    start_time = time.time()
    logger.info(f"Starting security tests at {datetime.datetime.now()}")
    logger.info(f"Target URL: {target_url}")
    
    # Check if paths exist
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define tests to run
    tests = [
        {
            "script": os.path.join(scripts_dir, "authentication", "brute_force_test.py"),
            "args": [target_url] + ([username] if username else []),
            "description": "Brute Force Attack Test"
        },
        {
            "script": os.path.join(scripts_dir, "authentication", "user_enumeration_test.py"),
            "args": [target_url] + ([username] if username else []),
            "description": "User Enumeration Test"
        },
        {
            "script": os.path.join(scripts_dir, "authentication", "timing_attack_test.py"),
            "args": [target_url] + ([username] if username else []) + ([password] if password else []),
            "description": "Timing Attack Test"
        },
        {
            "script": os.path.join(scripts_dir, "authentication", "otp_brute_force_test.py"),
            "args": [target_url] + ([username] if username else []) + ([password] if password else []),
            "description": "OTP Brute Force Test"
        },
        {
            "script": os.path.join(scripts_dir, "injection", "sql_injection_test.py"),
            "args": [target_url] + ([username] if username else []) + ([password] if password else []),
            "description": "SQL Injection Test"
        },
        {
            "script": os.path.join(scripts_dir, "xss", "xss_test.py"),
            "args": [target_url] + ([username] if username else []) + ([password] if password else []),
            "description": "XSS Test"
        },
        {
            "script": os.path.join(scripts_dir, "csrf", "csrf_test.py"),
            "args": [target_url] + ([username] if username else []) + ([password] if password else []),
            "description": "CSRF Test"
        }
    ]
    
    # Add encryption test if db_path is provided
    if db_path:
        # Find the actual database path
        if not os.path.isabs(db_path):
            db_full_path = os.path.abspath(os.path.join(os.getcwd(), db_path))
        else:
            db_full_path = db_path
            
        # Make sure the path exists
        if not os.path.exists(db_full_path):
            logger.warning(f"Database path not found: {db_full_path}. Using default db.sqlite3")
            # Try to find a default SQLite database
            default_db_path = os.path.abspath(os.path.join(scripts_dir, "..", "..", "db.sqlite3"))
            if os.path.exists(default_db_path):
                db_full_path = default_db_path
            else:
                logger.warning("Default database not found. Skipping encryption test.")
                db_full_path = None
                
        if db_full_path:
            app_path = os.path.abspath(os.path.join(scripts_dir, "..", ".."))
            tests.append({
                "script": os.path.join(scripts_dir, "encryption", "encryption_test.py"),
                "args": [db_full_path, app_path],
                "description": "Encryption Test"
            })
    
    # Track results
    results = {}
    
    # Run each test
    for test in tests:
        script = test["script"]
        args = test["args"]
        description = test["description"]
        
        # Check if script exists
        if not os.path.exists(script):
            logger.error(f"Test script not found: {script}")
            results[description] = "SCRIPT NOT FOUND"
            continue
        
        # Run the test
        success = run_test(script, args, description)
        results[description] = "PASSED" if success else "FAILED"
    
    # Print summary
    end_time = time.time()
    duration = end_time - start_time
    
    logger.info(f"\n{'=' * 80}")
    logger.info(f"Security Test Summary")
    logger.info(f"{'=' * 80}")
    logger.info(f"Tests completed in {duration:.2f} seconds")
    
    for test, result in results.items():
        logger.info(f"{test}: {result}")
    
    logger.info(f"\nDetailed logs saved to security_test_report.log and individual test logs")
    logger.info(f"{'=' * 80}")

def main():
    parser = argparse.ArgumentParser(description='Run all security tests')
    parser.add_argument('target_url', help='Target URL (e.g., https://localhost:8000/)')
    parser.add_argument('username', nargs='?', default=None, help='Username for authenticated tests')
    parser.add_argument('password', nargs='?', default=None, help='Password for authenticated tests')
    parser.add_argument('db_path', nargs='?', default=None, help='Path to database file for encryption tests')
    
    args = parser.parse_args()
    
    run_all_tests(args.target_url, args.username, args.password, args.db_path)

if __name__ == "__main__":
    main()