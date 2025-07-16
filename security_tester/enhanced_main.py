#!/usr/bin/env python3
"""
Enhanced Web Application Security Testing Tool with Advanced Authentication Support
"""

import argparse
import sys
import json
import logging
import time
from pathlib import Path
from modules.xss_scanner import XSSScanner
from modules.csrf_scanner import CSRFScanner
from modules.crawler import WebCrawler
from modules.enhanced_reporter import EnhancedReporter
from modules.advanced_auth import AdvancedAuthHandler
from modules.authenticated_scanner import AuthenticatedScanner
from modules.test_config import TestConfig

def setup_logging(config):
    """Setup logging configuration"""
    log_level = getattr(logging, config.get('output', 'log_level', 'INFO').upper())
    log_file = config.get('output', 'log_file')
    
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

def print_banner():
    """Print application banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    Enhanced Web Security Testing Tool                        ║
║                           Version 2.0 - Advanced                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Features:                                                                   ║
║  • Advanced Authentication Support (Form, Basic, OAuth, Multi-step)         ║
║  • Session Management Testing                                               ║
║  • Privilege Escalation Detection                                           ║
║  • Authentication Bypass Testing                                            ║
║  • Enhanced XSS & CSRF Detection                                            ║
║  • Multiple Report Formats (MD, JSON, HTML, CSV)                           ║
║  • Configurable Testing Parameters                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)

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

def validate_target_url(url):
    """Validate target URL format"""
    from urllib.parse import urlparse
    
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid URL format. Please include protocol (http:// or https://)")
    
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("Only HTTP and HTTPS protocols are supported")
    
    return url

def create_output_directory(config):
    """Create output directory for reports and sessions"""
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    
    session_dir = Path(config.get('authentication', 'session_export_path', 'sessions'))
    session_dir.mkdir(exist_ok=True)
    
    return output_dir

def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Web Application Security Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    python3 enhanced_main.py --all http://example.com
  
  Authenticated scan with form login:
    python3 enhanced_main.py --auth '{"type":"form","login_url":"http://example.com/login","username":"admin","password":"password"}' --all http://example.com
  
  Session testing with exported session:
    python3 enhanced_main.py --import-session session.json --session --privilege http://example.com
  
  Custom configuration:
    python3 enhanced_main.py --config custom_config.yml --all http://example.com
  
  Multiple output formats:
    python3 enhanced_main.py --all --format json,html,csv --output report http://example.com

Authentication Examples:
  Form-based: --auth '{"type":"form","login_url":"http://example.com/login","username":"admin","password":"password"}'
  Basic Auth: --auth '{"type":"basic","url":"http://example.com","username":"admin","password":"password"}'
  Cookies:    --auth '{"type":"cookies","cookies":"PHPSESSID=abc123;user_token=xyz789"}'
  Headers:    --auth '{"type":"headers","headers":"Authorization:Bearer token123"}'
  Multi-step: --auth '{"type":"multi_step","steps":[{"url":"http://example.com/login","data":{"user":"admin","pass":"password"}}]}'
        """
    )
    
    # Target and basic options
    parser.add_argument('target', help='Target URL to test')
    parser.add_argument('--config', '-c', help='Configuration file (YAML or JSON)')
    
    # Test selection
    parser.add_argument('--xss', action='store_true', help='Test for XSS vulnerabilities')
    parser.add_argument('--csrf', action='store_true', help='Test for CSRF vulnerabilities')
    parser.add_argument('--session', action='store_true', help='Test session management')
    parser.add_argument('--privilege', action='store_true', help='Test privilege escalation')
    parser.add_argument('--auth-bypass', action='store_true', help='Test authentication bypass')
    parser.add_argument('--all', action='store_true', help='Run all available tests')
    
    # Authentication options
    auth_group = parser.add_argument_group('Authentication Options')
    auth_group.add_argument('--auth', help='Authentication configuration (JSON or key=value)')
    auth_group.add_argument('--login-url', help='Login page URL')
    auth_group.add_argument('--username', help='Username for authentication')
    auth_group.add_argument('--password', help='Password for authentication')
    auth_group.add_argument('--cookies', help='Authentication cookies')
    auth_group.add_argument('--headers', help='Authentication headers')
    auth_group.add_argument('--export-session', help='Export session to file')
    auth_group.add_argument('--import-session', help='Import session from file')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--output', '-o', help='Output file prefix for reports')
    output_group.add_argument('--format', default='markdown', 
                             help='Report formats (comma-separated): markdown,json,html,csv')
    output_group.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    output_group.add_argument('--quiet', '-q', action='store_true', help='Quiet mode')
    output_group.add_argument('--no-banner', action='store_true', help='Disable banner')
    
    # Scanning options
    scan_group = parser.add_argument_group('Scanning Options')
    scan_group.add_argument('--depth', type=int, help='Crawling depth')
    scan_group.add_argument('--delay', type=float, help='Delay between requests')
    scan_group.add_argument('--timeout', type=int, help='Request timeout')
    scan_group.add_argument('--threads', type=int, help='Number of concurrent threads')
    scan_group.add_argument('--user-agent', help='Custom User-Agent string')
    
    args = parser.parse_args()
    
    # Print banner unless disabled
    if not args.no_banner and not args.quiet:
        print_banner()
    
    # Load configuration
    config = TestConfig(args.config)
    
    # Override config with command line arguments
    if args.depth:
        config.set('scanning', 'max_depth', args.depth)
    if args.delay:
        config.set('scanning', 'delay_between_requests', args.delay)
    if args.timeout:
        config.set('scanning', 'request_timeout', args.timeout)
    if args.threads:
        config.set('scanning', 'max_concurrent_requests', args.threads)
    if args.user_agent:
        config.set('scanning', 'user_agent', args.user_agent)
    if args.verbose:
        config.set('output', 'log_level', 'DEBUG')
    if args.quiet:
        config.set('output', 'log_level', 'ERROR')
    
    # Setup logging
    setup_logging(config)
    
    # Validate target URL
    try:
        target_url = validate_target_url(args.target)
    except ValueError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    
    # Validate test selection
    if not any([args.xss, args.csrf, args.session, args.privilege, args.auth_bypass, args.all]):
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
    
    # Check authentication requirements
    auth_required_tests = [args.session, args.privilege, args.auth_bypass]
    if any(auth_required_tests) and not auth_config and not args.import_session:
        parser.error("Authentication is required for session, privilege, and auth-bypass tests")
    
    # Create output directory
    output_dir = create_output_directory(config)
    
    # Initialize components
    if not args.quiet:
        print(f"🔍 Starting enhanced security scan of {target_url}")
    
    auth_handler = AdvancedAuthHandler()
    authenticated_scanner = AuthenticatedScanner(auth_handler)
    results = {}
    
    # Setup authentication
    if args.import_session:
        if not args.quiet:
            print("📥 Importing session...")
        if auth_handler.import_session(args.import_session):
            if not args.quiet:
                print("✅ Session imported successfully")
        else:
            print("❌ Failed to import session")
            sys.exit(1)
    elif auth_config:
        if not args.quiet:
            print("🔐 Setting up authentication...")
        
        if authenticated_scanner.setup_authentication(auth_config):
            if not args.quiet:
                print("✅ Authentication successful")
                auth_info = auth_handler.get_auth_info()
                print(f"   - Login URL: {auth_info.get('login_url', 'N/A')}")
                print(f"   - Active cookies: {len(auth_info.get('cookies', []))}")
                print(f"   - Auth headers: {len(auth_info.get('headers', []))}")
        else:
            print("❌ Authentication failed")
            if any(auth_required_tests):
                print("Cannot proceed with authenticated tests without valid authentication")
                sys.exit(1)
    
    # Export session if requested
    if args.export_session and auth_handler.logged_in:
        session_file = args.export_session
        if not session_file.endswith('.json'):
            session_file += '.json'
        
        if auth_handler.export_session(session_file):
            if not args.quiet:
                print(f"💾 Session exported to {session_file}")
    
    # Initialize crawler with authenticated session
    session = auth_handler.get_authenticated_session()
    crawler = WebCrawler(session=session)
    
    # Configure crawler from config
    crawler_config = config.get('scanning', {})
    max_depth = crawler_config.get('max_depth', 2)
    delay = crawler_config.get('delay_between_requests', 0.1)
    
    # Discover endpoints
    if not args.quiet:
        print("🕷️  Crawling application...")
    
    start_time = time.time()
    endpoints = crawler.crawl(target_url, max_depth=max_depth)
    crawl_time = time.time() - start_time
    
    if not args.quiet:
        print(f"   Found {len(endpoints)} endpoints in {crawl_time:.2f}s")
    
    # Scan authenticated endpoints if logged in
    if auth_handler.logged_in:
        if not args.quiet:
            print("🔒 Scanning authenticated endpoints...")
        
        auth_endpoints = authenticated_scanner.scan_authenticated_endpoints(target_url, max_depth)
        endpoints.extend(auth_endpoints)
        
        if not args.quiet:
            print(f"   Found {len(auth_endpoints)} additional authenticated endpoints")
    
    # Run tests based on configuration and arguments
    test_start_time = time.time()
    
    # XSS Testing
    if (args.xss or args.all) and config.get('xss_testing', 'enabled', True):
        if not args.quiet:
            print("🚨 Testing for XSS vulnerabilities...")
        
        xss_scanner = XSSScanner(session=session)
        
        # Configure XSS scanner from config
        xss_config = config.get('xss_testing', {})
        if xss_config.get('custom_payloads'):
            xss_scanner.payloads.extend(xss_config['custom_payloads'])
        
        xss_results = xss_scanner.scan_endpoints(endpoints)
        results['xss'] = xss_results
        
        if not args.quiet:
            print(f"   Found {len(xss_results)} XSS vulnerabilities")
        
        time.sleep(delay)
    
    # CSRF Testing
    if (args.csrf or args.all) and config.get('csrf_testing', 'enabled', True):
        if not args.quiet:
            print("🛡️  Testing for CSRF vulnerabilities...")
        
        csrf_scanner = CSRFScanner(session=session)
        csrf_results = csrf_scanner.scan_endpoints(endpoints)
        results['csrf'] = csrf_results
        
        if not args.quiet:
            print(f"   Found {len(csrf_results)} CSRF vulnerabilities")
        
        time.sleep(delay)
    
    # Session Management Testing
    if (args.session or args.all) and auth_handler.logged_in and config.get('session_testing', 'enabled', True):
        if not args.quiet:
            print("🔑 Testing session management...")
        
        session_results = authenticated_scanner.test_session_management(target_url)
        results['session'] = session_results
        
        if not args.quiet:
            print(f"   Found {len(session_results)} session management issues")
        
        time.sleep(delay)
    
    # Privilege Escalation Testing
    if (args.privilege or args.all) and auth_handler.logged_in and config.get('privilege_testing', 'enabled', True):
        if not args.quiet:
            print("⬆️  Testing for privilege escalation...")
        
        privilege_results = authenticated_scanner.test_privilege_escalation(endpoints)
        results['privilege_escalation'] = privilege_results
        
        if not args.quiet:
            print(f"   Found {len(privilege_results)} privilege escalation issues")
        
        time.sleep(delay)
    
    # Authentication Bypass Testing
    if (args.auth_bypass or args.all) and config.get('auth_bypass_testing', 'enabled', True):
        if not args.quiet:
            print("🚪 Testing authentication bypass...")
        
        bypass_results = []
        
        # Test protected endpoints for bypass
        protected_endpoints = [ep for ep in endpoints if auth_handler.logged_in]
        
        for endpoint in protected_endpoints[:10]:  # Limit to first 10 for performance
            bypass_tests = auth_handler.test_authentication_bypass(endpoint['url'])
            bypass_results.extend(bypass_tests)
        
        results['auth_bypass'] = bypass_results
        
        if not args.quiet:
            print(f"   Found {len(bypass_results)} authentication bypass issues")
    
    test_time = time.time() - test_start_time
    
    # Generate reports
    if not args.quiet:
        print("📊 Generating reports...")
    
    reporter = EnhancedReporter()
    auth_info = auth_handler.get_auth_info() if auth_handler.logged_in else None
    
    # Parse output formats
    formats = [f.strip().lower() for f in args.format.split(',')]
    
    # Generate reports in requested formats
    reports_generated = []
    
    for format_type in formats:
        try:
            if format_type == 'json':
                report_content = reporter.generate_json_report(results, target_url, auth_info)
            elif format_type == 'html':
                report_content = reporter.generate_html_report(results, target_url, auth_info)
            elif format_type == 'csv':
                report_content = reporter.generate_csv_report(results, target_url, auth_info)
            else:  # markdown (default)
                report_content = reporter.generate_authenticated_report(results, target_url, auth_info)
            
            # Save report if output specified
            if args.output:
                filename = f"{args.output}.{format_type}" if format_type != 'markdown' else f"{args.output}.md"
                saved_filename = reporter.save_report(report_content, filename, format_type)
                reports_generated.append(saved_filename)
                
                if not args.quiet:
                    print(f"   📄 {format_type.upper()} report saved to: {saved_filename}")
            else:
                # Print markdown report to console if no output file specified
                if format_type == 'markdown':
                    print("\n" + "="*80)
                    print(report_content)
        
        except Exception as e:
            print(f"❌ Failed to generate {format_type} report: {e}")
    
    # Calculate and display summary
    total_vulns = sum(len(vulns) if isinstance(vulns, list) else 0 for vulns in results.values())
    high_vulns = sum(1 for vulns in results.values() if isinstance(vulns, list) 
                    for vuln in vulns if vuln.get('severity') == 'High')
    medium_vulns = sum(1 for vulns in results.values() if isinstance(vulns, list) 
                      for vuln in vulns if vuln.get('severity') == 'Medium')
    low_vulns = sum(1 for vulns in results.values() if isinstance(vulns, list) 
                   for vuln in vulns if vuln.get('severity') == 'Low')
    
    if not args.quiet:
        print(f"\n🎯 Scan completed in {test_time:.2f}s!")
        print(f"   Target: {target_url}")
        print(f"   Endpoints scanned: {len(endpoints)}")
        print(f"   Total vulnerabilities: {total_vulns}")
        print(f"   High severity: {high_vulns}")
        print(f"   Medium severity: {medium_vulns}")
        print(f"   Low severity: {low_vulns}")
        
        if auth_handler.logged_in:
            print(f"   Authenticated scan: ✅")
            session_info = authenticated_scanner.get_session_info()
            print(f"   Active session cookies: {len(session_info['cookies'])}")
        else:
            print(f"   Authenticated scan: ❌")
        
        if reports_generated:
            print(f"   Reports generated: {len(reports_generated)}")
            for report in reports_generated:
                print(f"     - {report}")
    
    # Log summary to file if configured
    if config.get('output', 'log_file'):
        logging.info(f"Scan completed - Target: {target_url}, Vulnerabilities: {total_vulns} "
                    f"(High: {high_vulns}, Medium: {medium_vulns}, Low: {low_vulns})")
    
    # Exit with appropriate code based on severity threshold
    severity_threshold = config.get('reporting', 'severity_threshold', 'Low')
    
    if severity_threshold == 'High' and high_vulns > 0:
        sys.exit(1)
    elif severity_threshold == 'Medium' and (high_vulns > 0 or medium_vulns > 0):
        sys.exit(1)
    elif severity_threshold == 'Low' and total_vulns > 0:
        sys.exit(1)
    
    sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        logging.exception("Unexpected error occurred")
        sys.exit(1)