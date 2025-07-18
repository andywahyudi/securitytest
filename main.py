#!/usr/bin/env python3
"""
Enhanced Web Application Security Testing Tool with Authentication Support
"""

import argparse
import sys
import json
import logging
from modules.xss_scanner import XSSScanner
from modules.csrf_scanner import CSRFScanner
from modules.crawler import WebCrawler
from modules.reporter import Reporter
from modules.auth_handler import AuthHandler
from modules.authenticated_scanner import AuthenticatedScanner

def setup_logging(verbose=False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

def parse_auth_config(auth_string):
    """Parse authentication configuration string"""
    if not auth_string:
        return None
    
    try:
        # Try to parse as JSON first
        return json.loads(auth_string)
    except json.JSONDecodeError:
        # Parse as simple key=value format
        config = {}
        for pair in auth_string.split(','):
            if '=' in pair:
                key, value = pair.strip().split('=', 1)
                config[key.strip()] = value.strip()
        return config

def main():
    parser = argparse.ArgumentParser(
        description='Web Application Security Testing Tool with Authentication Support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Authentication Examples:
  Form-based login:
    --auth '{"type":"form","login_url":"http://example.com/login","username":"admin","password":"password"}'
  
  Basic authentication:
    --auth '{"type":"basic","url":"http://example.com","username":"admin","password":"password"}'
  
  Cookie-based:
    --auth '{"type":"cookies","cookies":"PHPSESSID=abc123;user_token=xyz789"}'
  
  Header-based:
    --auth '{"type":"headers","headers":"Authorization:Bearer token123,X-API-Key:key456"}'
  
  Simple format:
    --auth 'type=form,login_url=http://example.com/login,username=admin,password=password'
        """
    )
    
    parser.add_argument('target', help='Target URL to test')
    parser.add_argument('--xss', action='store_true', help='Test for XSS vulnerabilities')
    parser.add_argument('--csrf', action='store_true', help='Test for CSRF vulnerabilities')
    parser.add_argument('--all', action='store_true', help='Run all available tests')
    parser.add_argument('--session', action='store_true', help='Test session management (requires auth)')
    parser.add_argument('--privilege', action='store_true', help='Test privilege escalation (requires auth)')
    
    # Authentication options
    parser.add_argument('--auth', help='Authentication configuration (JSON or key=value format)')
    parser.add_argument('--login-url', help='Login page URL for form-based authentication')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')
    parser.add_argument('--cookies', help='Authentication cookies (name1=value1;name2=value2)')
    parser.add_argument('--headers', help='Authentication headers (Header1:Value1,Header2:Value2)')
    
    # Output options
    parser.add_argument('--output', '-o', help='Output file for report')
    parser.add_argument('--format', choices=['markdown', 'json', 'html', 'csv'], 
                       default='markdown', help='Report format')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    # Scanning options
    parser.add_argument('--depth', type=int, default=2, help='Crawling depth (default: 2)')
    parser.add_argument('--delay', type=float, default=0.1, help='Delay between requests (default: 0.1)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Validate arguments
    if not any([args.xss, args.csrf, args.all, args.session, args.privilege]):
        parser.error("At least one test type must be specified")
    
    # Parse authentication configuration
    auth_config = None
    if args.auth:
        auth_config = parse_auth_config(args.auth)
    elif args.login_url and args.username and args.password:
        auth_config = {
            'type': 'form',
            'login_url': args.login_url,
            'username': args.username,
            'password': args.password
        }
    elif args.cookies:
        auth_config = {
            'type': 'cookies',
            'cookies': args.cookies
        }
    elif args.headers:
        auth_config = {
            'type': 'headers',
            'headers': args.headers
        }
    
    # Check if authentication is required for certain tests
    if (args.session or args.privilege) and not auth_config:
        parser.error("Session and privilege escalation tests require authentication")
    
    print(f"🔍 Starting security scan of {args.target}")
    
    # Initialize components
    auth_handler = AuthHandler()
    authenticated_scanner = AuthenticatedScanner(auth_handler)
    results = {}
    
    # Setup authentication if provided
    if auth_config:
        print("🔐 Setting up authentication...")
        if authenticated_scanner.setup_authentication(auth_config):
            print("✅ Authentication successful")
            auth_info = auth_handler.get_auth_info()
            print(f"   - Login URL: {auth_info.get('login_url', 'N/A')}")
            print(f"   - Cookies: {len(auth_info.get('cookies', []))}")
            print(f"   - Headers: {len(auth_info.get('headers', []))}")
        else:
            print("❌ Authentication failed")
            if args.session or args.privilege:
                print("Cannot proceed with session/privilege tests without authentication")
                sys.exit(1)
    
    # Initialize crawler with authenticated session if available
    session = auth_handler.get_authenticated_session()
    crawler = WebCrawler(session=session)
    
    # Discover endpoints
    print("🕷️  Crawling application...")
    endpoints = crawler.crawl(args.target, max_depth=args.depth)
    print(f"   Found {len(endpoints)} endpoints")
    
    # If authenticated, also scan protected endpoints
    if auth_handler.logged_in:
        print("🔒 Scanning authenticated endpoints...")
        auth_endpoints = authenticated_scanner.scan_authenticated_endpoints(args.target, args.depth)
        endpoints.extend(auth_endpoints)
        print(f"   Found {len(auth_endpoints)} additional authenticated endpoints")
    
    # Run XSS tests
    if args.xss or args.all:
        print("🚨 Testing for XSS vulnerabilities...")
        xss_scanner = XSSScanner(session=session)
        xss_results = xss_scanner.scan_endpoints(endpoints)
        results['xss'] = xss_results
        print(f"   Found {len(xss_results)} XSS vulnerabilities")
    
    # Run CSRF tests
    if args.csrf or args.all:
        print("🛡️  Testing for CSRF vulnerabilities...")
        csrf_scanner = CSRFScanner(session=session)
        csrf_results = csrf_scanner.scan_endpoints(endpoints)
        results['csrf'] = csrf_results
        print(f"   Found {len(csrf_results)} CSRF vulnerabilities")
    
    # Run session management tests
    if args.session and auth_handler.logged_in:
        print("🔑 Testing session management...")
        session_results = authenticated_scanner.test_session_management(args.target)
        results['session'] = session_results
        print(f"   Found {len(session_results)} session management issues")
    
    # Run privilege escalation tests
    if args.privilege and auth_handler.logged_in:
        print("⬆️  Testing for privilege escalation...")
        privilege_results = authenticated_scanner.test_privilege_escalation(endpoints)
        results['privilege_escalation'] = privilege_results
        print(f"   Found {len(privilege_results)} privilege escalation issues")
    
    # Generate report
    print("📊 Generating report...")
    reporter = Reporter()
    
    if args.format == 'json':
        report_content = reporter.generate_json_report(results, args.target)
    elif args.format == 'html':
        report_content = reporter.generate_html_report(results, args.target)
    elif args.format == 'csv':
        report_content = reporter.generate_csv_report(results, args.target)
    else:  # markdown
        report_content = reporter.generate_report(results, args.target)
    
    # Output report
    if args.output:
        output_path = args.output
        if not output_path.startswith("output/"):
            output_path = f"output/{output_path}"
        try:
            filename = reporter.save_report(report_content, output_path)
            print(f"📄 Report saved to: {filename}")
        except Exception as e:
            print(f"❌ Failed to save report: {e}")
            sys.exit(1)
    else:
        print("\n" + "="*80)
        print(report_content)
    
    # Summary
    total_vulns = sum(len(vulns) for vulns in results.values())
    high_vulns = sum(1 for vulns in results.values() for vuln in vulns if vuln.get('severity') == 'High')
    
    print(f"\n🎯 Scan completed!")
    print(f"   Total vulnerabilities: {total_vulns}")
    print(f"   High severity: {high_vulns}")
    
    if auth_handler.logged_in:
        print(f"   Authenticated scan: ✅")
        session_info = authenticated_scanner.get_session_info()
        print(f"   Active cookies: {len(session_info['cookies'])}")
    
    # Exit with appropriate code
    sys.exit(1 if high_vulns > 0 else 0)

if __name__ == "__main__":
    main()