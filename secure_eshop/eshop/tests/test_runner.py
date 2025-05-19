"""
Custom test runner that logs successful tests to a file.
"""

import os
import datetime
from django.test.runner import DiscoverRunner
from unittest import TestResult
import json


class DocumentingTestResult(TestResult):
    """Custom test result that tracks all test outcomes."""
    
    def __init__(self, stream=None, descriptions=None, verbosity=None):
        super().__init__(stream, descriptions, verbosity)
        self.test_results = []
        self.start_time = {}
        
    def startTest(self, test):
        super().startTest(test)
        self.start_time[test] = datetime.datetime.now()
    
    def stopTest(self, test):
        super().stopTest(test)
        
    def addSuccess(self, test):
        super().addSuccess(test)
        self._add_result(test, 'success')
        
    def addError(self, test, err):
        super().addError(test, err)
        self._add_result(test, 'error', err)
        
    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._add_result(test, 'fail', err)
        
    def _add_result(self, test, status, err=None):
        duration = (datetime.datetime.now() - self.start_time.get(test, datetime.datetime.now())).total_seconds()
        
        # Extract test information
        test_module = test.__class__.__module__
        test_class = test.__class__.__name__
        test_method = test._testMethodName
        test_doc = test._testMethodDoc or ""
        
        result = {
            'module': test_module,
            'class': test_class,
            'method': test_method,
            'description': test_doc.strip(),
            'status': status,
            'duration': duration,
            'error': str(err[1]) if err else None,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        self.test_results.append(result)


class DocumentingTestRunner(DiscoverRunner):
    """Test runner that documents successful tests."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.test_results = []
        self.start_time = None
        self.total_tests = 0
        self.successful_tests = 0
        self.failed_tests = 0
        self.errors = 0
        
    def setup_test_environment(self, **kwargs):
        super().setup_test_environment(**kwargs)
        self.start_time = datetime.datetime.now()
        
    def teardown_test_environment(self, **kwargs):
        super().teardown_test_environment(**kwargs)
        self._write_test_report()
    
    def get_resultclass(self):
        """Return the custom test result class."""
        return DocumentingTestResult
        
    def run_suite(self, suite, **kwargs):
        """Run the test suite with our custom result class."""
        resultclass = self.get_resultclass()
        result = resultclass(stream=None, descriptions=True, verbosity=self.verbosity)
        
        # Run tests
        suite.run(result)
        
        # Collect statistics from our custom result
        self.test_results = result.test_results
        for test_result in self.test_results:
            self.total_tests += 1
            if test_result['status'] == 'success':
                self.successful_tests += 1
            elif test_result['status'] == 'fail':
                self.failed_tests += 1
            elif test_result['status'] == 'error':
                self.errors += 1
                
        return result
    
    def _write_test_report(self):
        """Write test results to a documentation file."""
        report_path = os.path.join(
            os.path.dirname(__file__), 
            f'test_documentation_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.md'
        )
        
        with open(report_path, 'w') as f:
            f.write("# Test Run Documentation\n\n")
            f.write(f"**Date**: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Duration**: {datetime.datetime.now() - self.start_time}\n\n")
            
            f.write("## Summary\n\n")
            f.write(f"- **Total Tests**: {self.total_tests}\n")
            f.write(f"- **Successful**: {self.successful_tests}\n")
            f.write(f"- **Failed**: {self.failed_tests}\n")
            f.write(f"- **Errors**: {self.errors}\n")
            f.write(f"- **Success Rate**: {(self.successful_tests/self.total_tests*100):.1f}%\n\n")
            
            # Group tests by module
            tests_by_module = {}
            for test in self.test_results:
                module = test['module']
                if module not in tests_by_module:
                    tests_by_module[module] = []
                tests_by_module[module].append(test)
            
            # Write successful tests
            f.write("## Successful Tests\n\n")
            for module, tests in sorted(tests_by_module.items()):
                successful = [t for t in tests if t['status'] == 'success']
                if successful:
                    f.write(f"### {module}\n\n")
                    for test in successful:
                        f.write(f"✅ **{test['class']}.{test['method']}**\n")
                        if test['description']:
                            f.write(f"   - Description: {test['description']}\n")
                        f.write(f"   - Duration: {test['duration']:.3f}s\n")
                        f.write("\n")
            
            # Write failed tests
            failed_tests = [t for t in self.test_results if t['status'] in ['fail', 'error']]
            if failed_tests:
                f.write("## Failed Tests\n\n")
                for test in failed_tests:
                    status_emoji = "❌" if test['status'] == 'fail' else "💥"
                    f.write(f"{status_emoji} **{test['module']}.{test['class']}.{test['method']}**\n")
                    if test['description']:
                        f.write(f"   - Description: {test['description']}\n")
                    f.write(f"   - Status: {test['status']}\n")
                    if test['error']:
                        f.write(f"   - Error: {test['error']}\n")
                    f.write(f"   - Duration: {test['duration']:.3f}s\n")
                    f.write("\n")
            
            # Write test categories
            f.write("## Test Categories\n\n")
            categories = {}
            for test in self.test_results:
                if test['status'] == 'success':
                    category = self._categorize_test(test)
                    if category not in categories:
                        categories[category] = []
                    categories[category].append(test)
            
            for category, tests in sorted(categories.items()):
                f.write(f"### {category}\n")
                f.write(f"- **Count**: {len(tests)}\n")
                test_names = [f"{t['class']}.{t['method']}" for t in tests]
                f.write(f"- **Tests**: {', '.join(test_names)}\n")
                f.write("\n")
        
        # Also create a JSON file for programmatic access
        json_path = report_path.replace('.md', '.json')
        with open(json_path, 'w') as f:
            json.dump({
                'start_time': self.start_time.isoformat(),
                'duration': str(datetime.datetime.now() - self.start_time),
                'summary': {
                    'total': self.total_tests,
                    'successful': self.successful_tests,
                    'failed': self.failed_tests,
                    'errors': self.errors,
                    'success_rate': self.successful_tests/self.total_tests if self.total_tests > 0 else 0
                },
                'tests': self.test_results
            }, f, indent=2)
        
        print(f"\n📝 Test documentation written to:")
        print(f"   - {report_path}")
        print(f"   - {json_path}")
    
    def _categorize_test(self, test):
        """Categorize test based on its name and module."""
        method = test['method'].lower()
        module = test['module'].lower()
        
        if 'auth' in module or 'login' in method or 'logout' in method:
            return "Authentication"
        elif 'encrypt' in method or 'decrypt' in method:
            return "Encryption"
        elif 'validation' in module or 'validate' in method or 'form' in method:
            return "Validation"
        elif 'security' in module or 'xss' in method or 'csrf' in method:
            return "Security"
        elif 'model' in module or 'db' in method:
            return "Database/Models"
        elif 'view' in module or 'response' in method:
            return "Views/HTTP"
        else:
            return "General"