#!/usr/bin/env python3
"""
Test Runner for Web Application Security Testing Tool
Provides automated testing scenarios and validation
"""

import subprocess
import json
import time
import sys
from pathlib import Path

class TestRunner:
    def __init__(self):
        self.test_results = []
        self.passed = 0
        self.failed = 0
    
    def run_test(self, name, command, expected_exit_code=0, timeout=60):
        """Run a single test case"""
        print(f"🧪 Running test: {name}")
        print(f"   Command: {command}")
        
        try:
            start_time = time.time()
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            end_time = time.time()
            
            success = result.returncode == expected_exit_code
            
            test_result = {
                'name': name,
                'command': command,
                'exit_code': result.returncode,
                'expected_exit_code': expected_exit_code,
                'success': success,
                'duration': end_time - start_time,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            
            self.test_results.append(test_result)
            
            if success:
                print(f"   ✅ PASSED ({test_result['duration']:.2f}s)")
                self.passed += 1
            else:
                print(f"   ❌ FAILED ({test_result['duration']:.2f}s)")
                print(f"      Expected exit code: {expected_exit_code}")
                print(f"      Actual exit code: {result.returncode}")
                if result.stderr:
                    print(f"      Error: {result.stderr[:200]}...")
                self.failed += 1
            
        except subprocess.TimeoutExpired:
            print(f"   ⏰ TIMEOUT after {timeout}s")
            self.failed += 1
            self.test_results.append({
                'name': name,
                'command': command,
                'success': False,
                'error': 'Timeout'
            })
        except Exception as e:
            print(f"   💥 ERROR: {e}")
            self.failed += 1
            self.test_results.append({
                'name': name,
                'command': command,
                'success': False,
                'error': str(e)
            })
    
    def run_basic_tests(self):
        """Run basic functionality tests"""
        print("\n📋 Running Basic Functionality Tests")
        print("="*50)
        
        # Test help output
        self.run_test(
            "Help Output",
            "python3 enhanced_main.py --help",
            expected_exit_code=0
        )
        
        # Test invalid URL
        self.run_test(
            "Invalid URL Handling",
            "python3 enhanced_main.py --all invalid-url",
            expected_exit_code=1
        )
        
        # Test missing test type
        self.run_test(
            "Missing Test Type",
            "python3 enhanced_main.py http://example.com",
            expected_exit_code=2  # argparse error
        )
        
        # Test configuration loading
        self.run_test(
            "Configuration Loading",
            "python3 enhanced_main.py --config config/default_config.yml --all http://httpbin.org",
            expected_exit_code=0
        )
    
    def run_authentication_tests(self):
        """Run authentication-related tests"""
        print("\n🔐 Running Authentication Tests")
        print("="*50)
        
        # Test form authentication (simulated)
        auth_config = {
            "type": "form",
            "login_url": "http://httpbin.org/post",
            "username": "testuser",
            "password": "testpass"
        }
        
        self.run_test(
            "Form Authentication",
            f"python3 enhanced_main.py --auth '{json.dumps(auth_config)}' --xss http://httpbin.org",
            expected_exit_code=0
        )
        
        # Test cookie authentication
        self.run_test(
            "Cookie Authentication",
            "python3 enhanced_main.py --cookies 'session=test123;user=admin' --xss http://httpbin.org",
            expected_exit_code=0
        )
        
        # Test header authentication
        self.run_test(
            "Header Authentication",
            "python3 enhanced_main.py --headers 'Authorization:Bearer token123' --xss http://httpbin.org",
            expected_exit_code=0
        )
    
    def run_scanning_tests(self):
        """Run vulnerability scanning tests"""
        print("\n🔍 Running Vulnerability Scanning Tests")
        print("="*50)
        
        # Test XSS scanning
        self.run_test(
            "XSS Scanning",
            "python3 enhanced_main.py --xss --output test_xss http://httpbin.org",
            expected_exit_code=0
        )
        
        # Test CSRF scanning
        self.run_test(
            "CSRF Scanning",
            "python3 enhanced_main.py --csrf --output test_csrf http://httpbin.org",
            expected_exit_code=0
        )
        
        # Test all vulnerabilities
        self.run_test(
            "All Vulnerability Tests",
            "python3 enhanced_main.py --all --output test_all http://httpbin.org",
            expected_exit_code=0
        )
        
        # Test with custom depth
        self.run_test(
            "Custom Crawl Depth",
            "python3 enhanced_main.py --all --depth 1 --output test_depth http://httpbin.org",
            expected_exit_code=0
        )
        
        # Test with delay
        self.run_test(
            "Request Delay",
            "python3 enhanced_main.py --xss --delay 0.5 --output test_delay http://httpbin.org",
            expected_exit_code=0
        )
    
    def run_output_tests(self):
        """Run output format tests"""
        print("\n📊 Running Output Format Tests")
        print("="*50)
        
        # Test JSON output
        self.run_test(
            "JSON Output Format",
            "python3 enhanced_main.py --all --format json --output test_json http://httpbin.org",
            expected_exit_code=0
        )
        
        # Test HTML output
        self.run_test(
            "HTML Output Format",
            "python3 enhanced_main.py --all --format html --output test_html http://httpbin.org",
            expected_exit_code=0
        )
        
        # Test CSV output
        self.run_test(
            "CSV Output Format",
            "python3 enhanced_main.py --all --format csv --output test_csv http://httpbin.org",
            expected_exit_code=0
        )
        
        # Test multiple formats
        self.run_test(
            "Multiple Output Formats",
            "python3 enhanced_main.py --all --format json,html,csv --output test_multi http://httpbin.org",
            expected_exit_code=0
        )
        
        # Test quiet mode
        self.run_test(
            "Quiet Mode",
            "python3 enhanced_main.py --all --quiet --output test_quiet http://httpbin.org",
            expected_exit_code=0
        )
        
        # Test verbose mode
        self.run_test(
            "Verbose Mode",
            "python3 enhanced_main.py --all --verbose --output test_verbose http://httpbin.org",
            expected_exit_code=0
        )
    
    def run_session_tests(self):
        """Run session management tests"""
        print("\n🔑 Running Session Management Tests")
        print("="*50)
        
        # Create a test session file
        test_session = {
            "cookies": {"PHPSESSID": "test123", "user": "admin"},
            "headers": {"Authorization": "Bearer token123"},
            "logged_in": True,
            "login_url": "http://httpbin.org/post"
        }
        
        with open("test_session.json", "w") as f:
            json.dump(test_session, f)
        
        # Test session import
        self.run_test(
            "Session Import",
            "python3 enhanced_main.py --import-session test_session.json --xss http://httpbin.org",
            expected_exit_code=0
        )
        
        # Test session export
        auth_config = {
            "type": "cookies",
            "cookies": "session=test123;user=admin"
        }
        
        self.run_test(
            "Session Export",
            f"python3 enhanced_main.py --auth '{json.dumps(auth_config)}' --export-session exported_session --xss http://httpbin.org",
            expected_exit_code=0
        )
    
    def run_error_handling_tests(self):
        """Run error handling tests"""
        print("\n⚠️  Running Error Handling Tests")
        print("="*50)
        
        # Test unreachable host
        self.run_test(
            "Unreachable Host",
            "python3 enhanced_main.py --all --timeout 5 http://unreachable.invalid",
            expected_exit_code=1
        )
        
        # Test invalid authentication config
        self.run_test(
            "Invalid Auth Config",
            "python3 enhanced_main.py --auth 'invalid-json' --xss http://httpbin.org",
            expected_exit_code=1
        )
        
        # Test missing session file
        self.run_test(
            "Missing Session File",
            "python3 enhanced_main.py --import-session nonexistent.json --xss http://httpbin.org",
            expected_exit_code=1
        )
        
        # Test invalid config file
        self.run_test(
            "Invalid Config File",
            "python3 enhanced_main.py --config nonexistent.yml --all http://httpbin.org",
            expected_exit_code=0  # Should use defaults and warn
        )
    
    def validate_output_files(self):
        """Validate that output files were created correctly"""
        print("\n📁 Validating Output Files")
        print("="*50)
        
        expected_files = [
            "test_xss.md",
            "test_csrf.md", 
            "test_all.md",
            "test_json.json",
            "test_html.html",
            "test_csv.csv",
            "test_multi.json",
            "test_multi.html",
            "test_multi.csv",
            "exported_session.json"
        ]
        
        for filename in expected_files:
            if Path(filename).exists():
                print(f"   ✅ {filename} exists")
                
                # Basic validation of file content
                try:
                    with open(filename, 'r') as f:
                        content = f.read()
                    
                    if filename.endswith('.json'):
                        json.loads(content)  # Validate JSON
                        print(f"      Valid JSON format")
                    elif filename.endswith('.html'):
                        if '<html>' in content and '</html>' in content:
                            print(f"      Valid HTML structure")
                        else:
                            print(f"      ⚠️  HTML structure may be incomplete")
                    elif filename.endswith('.csv'):
                        lines = content.split('\n')
                        if len(lines) > 1:  # Header + at least one row
                            print(f"      CSV has {len(lines)-1} data rows")
                        else:
                            print(f"      ⚠️  CSV appears empty")
                    elif filename.endswith('.md'):
                        if '# Web Application Security Test Report' in content:
                            print(f"      Valid Markdown report")
                        else:
                            print(f"      ⚠️  Markdown format may be incorrect")
                
                except Exception as e:
                    print(f"      ❌ File validation failed: {e}")
            else:
                print(f"   ❌ {filename} missing")
    
    def cleanup_test_files(self):
        """Clean up test files"""
        print("\n🧹 Cleaning up test files...")
        
        test_files = [
            "test_xss.md", "test_csrf.md", "test_all.md", "test_depth.md", "test_delay.md",
            "test_json.json", "test_html.html", "test_csv.csv", "test_quiet.md", "test_verbose.md",
            "test_multi.json", "test_multi.html", "test_multi.csv", "test_multi.md",
            "test_session.json", "exported_session.json"
        ]
        
        for filename in test_files:
            try:
                Path(filename).unlink(missing_ok=True)
                print(f"   🗑️  Removed {filename}")
            except Exception as e:
                print(f"   ⚠️  Could not remove {filename}: {e}")
    
    def generate_test_report(self):
        """Generate test execution report"""
        print("\n📋 Test Execution Report")
        print("="*50)
        
        total_tests = len(self.test_results)
        print(f"Total tests run: {total_tests}")
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        print(f"Success rate: {(self.passed/total_tests*100):.1f}%")
        
        if self.failed > 0:
            print(f"\n❌ Failed tests:")
            for result in self.test_results:
                if not result['success']:
                    print(f"   - {result['name']}")
                    if 'error' in result:
                        print(f"     Error: {result['error']}")
                    elif 'stderr' in result and result['stderr']:
                        print(f"     Error: {result['stderr'][:100]}...")
        
        # Save detailed report
        report_file = f"test_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump({
                'summary': {
                    'total': total_tests,
                    'passed': self.passed,
                    'failed': self.failed,
                    'success_rate': self.passed/total_tests*100
                },
                'results': self.test_results
            }, f, indent=2)
        
        print(f"\nDetailed report saved to: {report_file}")
        
        return self.failed == 0

def main():
    """Main test runner function"""
    print("🚀 Starting Web Security Tool Test Suite")
    print("="*60)
    
    runner = TestRunner()
    
    try:
        # Run all test suites
        runner.run_basic_tests()
        runner.run_authentication_tests()
        runner.run_scanning_tests()
        runner.run_output_tests()
        runner.run_session_tests()
        runner.run_error_handling_tests()
        
        # Validate outputs
        runner.validate_output_files()
        
        # Generate report
        success = runner.generate_test_report()
        
        # Cleanup
        cleanup_input = input("\n🧹 Clean up test files? (y/N): ").strip().lower()
        if cleanup_input == 'y':
            runner.cleanup_test_files()
        
        # Exit with appropriate code
        if success:
            print("\n🎉 All tests passed!")
            sys.exit(0)
        else:
            print(f"\n💥 {runner.failed} test(s) failed!")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n❌ Test suite interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error in test suite: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()