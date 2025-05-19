#!/usr/bin/env python3
"""
Utility to view test results and statistics.
"""

import os
import json
import sys
from datetime import datetime
from pathlib import Path

def find_test_reports():
    """Find all test documentation files."""
    test_dir = Path(__file__).parent.parent / 'eshop' / 'tests'
    json_files = list(test_dir.glob('test_documentation_*.json'))
    return sorted(json_files, key=lambda x: x.stat().st_mtime, reverse=True)

def display_report(json_path):
    """Display a test report."""
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    print(f"\n📊 Test Report: {json_path.name}")
    print("="*50)
    
    print(f"\n📅 Date: {data['start_time']}")
    print(f"⏱️  Duration: {data['duration']}")
    
    summary = data['summary']
    print(f"\n✅ Total Tests: {summary['total']}")
    print(f"✅ Successful: {summary['successful']}")
    print(f"❌ Failed: {summary['failed']}")
    print(f"💥 Errors: {summary['errors']}")
    print(f"📈 Success Rate: {summary['success_rate']*100:.1f}%")
    
    # Group tests by module
    modules = {}
    for test in data['tests']:
        module = test['module']
        if module not in modules:
            modules[module] = {'success': 0, 'fail': 0, 'error': 0}
        modules[module][test['status']] += 1
    
    print("\n📦 Test Results by Module:")
    for module, counts in sorted(modules.items()):
        total = sum(counts.values())
        success_rate = (counts['success'] / total * 100) if total > 0 else 0
        print(f"  {module}: {counts['success']}/{total} ({success_rate:.0f}%)")
    
    # Show failed tests if any
    failed_tests = [t for t in data['tests'] if t['status'] != 'success']
    if failed_tests:
        print("\n❌ Failed Tests:")
        for test in failed_tests:
            print(f"  - {test['module']}.{test['class']}.{test['method']}")
            print(f"    Status: {test['status']}")
            if test['error']:
                print(f"    Error: {test['error'][:100]}...")

def main():
    reports = find_test_reports()
    
    if not reports:
        print("❌ No test reports found")
        sys.exit(1)
    
    if len(sys.argv) > 1 and sys.argv[1] == '--all':
        # Show all reports
        for report in reports:
            display_report(report)
    else:
        # Show latest report
        display_report(reports[0])
        
        if len(reports) > 1:
            print(f"\n📂 Found {len(reports)} test reports. Use --all to see all.")

if __name__ == "__main__":
    main()