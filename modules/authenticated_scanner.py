import requests
from urllib.parse import urljoin, urlparse
import logging
from .auth_handler import AuthHandler
from .crawler import WebCrawler

class AuthenticatedScanner:
    def __init__(self, auth_handler=None):
        self.auth_handler = auth_handler or AuthHandler()
        self.session = self.auth_handler.session
        self.crawler = None
        
    def setup_authentication(self, auth_config):
        """Setup authentication based on configuration"""
        auth_type = auth_config.get('type', 'cookies')
        
        if auth_type == 'form':
            return self.auth_handler.login_form_based(
                auth_config['login_url'],
                auth_config['username'],
                auth_config['password'],
                auth_config.get('username_field', 'username'),
                auth_config.get('password_field', 'password')
            )
        elif auth_type == 'basic':
            return self.auth_handler.login_basic_auth(
                auth_config['url'],
                auth_config['username'],
                auth_config['password']
            )
        elif auth_type == 'cookies':
            return self.auth_handler.login_with_cookies(auth_config['cookies'])
        elif auth_type == 'headers':
            return self.auth_handler.login_with_headers(auth_config['headers'])
        else:
            logging.error(f"Unsupported authentication type: {auth_type}")
            return False
    
    def scan_authenticated_endpoints(self, base_url, max_depth=2):
        """Scan endpoints that require authentication"""
        if not self.auth_handler.logged_in:
            logging.error("Not authenticated. Cannot scan protected endpoints.")
            return []
        
        # Initialize crawler with authenticated session
        self.crawler = WebCrawler(session=self.session)
        
        # Discover endpoints
        endpoints = self.crawler.crawl(base_url, max_depth)
        
        # Filter and validate authenticated endpoints
        authenticated_endpoints = []
        for endpoint in endpoints:
            if self.validate_authenticated_access(endpoint):
                authenticated_endpoints.append(endpoint)
        
        return authenticated_endpoints
    
    def validate_authenticated_access(self, endpoint):
        """Validate that endpoint requires and accepts authentication"""
        try:
            # Test with authenticated session
            auth_response = self.session.get(endpoint['url'], timeout=10)
            
            # Test without authentication (new session)
            unauth_session = requests.Session()
            unauth_response = unauth_session.get(endpoint['url'], timeout=10)
            
            # Compare responses to determine if authentication is required
            if (auth_response.status_code == 200 and 
                unauth_response.status_code in [401, 403, 302]):
                return True
            
            # Check content differences
            if (auth_response.status_code == 200 and 
                unauth_response.status_code == 200 and
                len(auth_response.text) > len(unauth_response.text)):
                return True
            
            return False
            
        except Exception as e:
            logging.error(f"Error validating authenticated access for {endpoint['url']}: {e}")
            return False
    
    def test_session_management(self, base_url):
        """Test session management vulnerabilities"""
        vulnerabilities = []
        
        if not self.auth_handler.logged_in:
            return vulnerabilities
        
        # Test session fixation
        session_fixation = self.test_session_fixation(base_url)
        if session_fixation:
            vulnerabilities.append(session_fixation)
        
        # Test session timeout
        session_timeout = self.test_session_timeout(base_url)
        if session_timeout:
            vulnerabilities.append(session_timeout)
        
        # Test concurrent sessions
        concurrent_sessions = self.test_concurrent_sessions(base_url)
        if concurrent_sessions:
            vulnerabilities.append(concurrent_sessions)
        
        return vulnerabilities
    
    def test_session_fixation(self, base_url):
        """Test for session fixation vulnerabilities"""
        try:
            # Get initial session ID
            initial_cookies = dict(self.session.cookies)
            
            # Perform login (if not already logged in)
            if not self.auth_handler.logged_in:
                return None
            
            # Get session ID after login
            post_login_cookies = dict(self.session.cookies)
            
            # Check if session ID changed after login
            session_id_fields = ['PHPSESSID', 'JSESSIONID', 'SESSIONID', 'session_id']
            
            for field in session_id_fields:
                if (field in initial_cookies and field in post_login_cookies and
                    initial_cookies[field] == post_login_cookies[field]):
                    return {
                        'type': 'session_fixation',
                        'severity': 'High',
                        'description': 'Session ID not regenerated after login',
                        'endpoint': base_url,
                        'details': f'Session field {field} remains unchanged after authentication'
                    }
            
            return None
            
        except Exception as e:
            logging.error(f"Error testing session fixation: {e}")
            return None
    
    def test_session_timeout(self, base_url):
        """Test session timeout implementation"""
        try:
            # This is a simplified test - in practice, you'd wait for actual timeout
            response = self.session.get(base_url, timeout=10)
            
            # Check for session timeout indicators in response
            timeout_indicators = [
                'session expired', 'session timeout', 'please login again',
                'session invalid', 'authentication expired'
            ]
            
            response_text = response.text.lower()
            has_timeout = any(indicator in response_text for indicator in timeout_indicators)
            
            if not has_timeout and response.status_code == 200:
                return {
                    'type': 'session_timeout',
                    'severity': 'Medium',
                    'description': 'No apparent session timeout mechanism',
                    'endpoint': base_url,
                    'details': 'Session appears to have no timeout or very long timeout'
                }
            
            return None
            
        except Exception as e:
            logging.error(f"Error testing session timeout: {e}")
                        return None
    
    def test_concurrent_sessions(self, base_url):
        """Test if multiple concurrent sessions are allowed"""
        try:
            if not self.auth_handler.logged_in:
                return None
            
            # Create a second session with same credentials
            second_session = requests.Session()
            second_auth = AuthHandler(second_session)
            
            # Try to login with second session (assuming form-based auth)
            if self.auth_handler.login_url:
                login_success = second_auth.login_form_based(
                    self.auth_handler.login_url,
                    "admin",  # This would need to be parameterized
                    "password"
                )
                
                if login_success:
                    # Test if both sessions are active
                    response1 = self.session.get(base_url, timeout=10)
                    response2 = second_session.get(base_url, timeout=10)
                    
                    if (response1.status_code == 200 and response2.status_code == 200 and
                        self.auth_handler.verify_authentication(response1) and
                        second_auth.verify_authentication(response2)):
                        
                        return {
                            'type': 'concurrent_sessions',
                            'severity': 'Medium',
                            'description': 'Multiple concurrent sessions allowed',
                            'endpoint': base_url,
                            'details': 'Same user can maintain multiple active sessions simultaneously'
                        }
            
            return None
            
        except Exception as e:
            logging.error(f"Error testing concurrent sessions: {e}")
            return None
    
    def test_privilege_escalation(self, endpoints):
        """Test for privilege escalation vulnerabilities"""
        vulnerabilities = []
        
        if not self.auth_handler.logged_in:
            return vulnerabilities
        
        # Test for admin endpoints accessible by regular users
        admin_patterns = [
            '/admin', '/administrator', '/manage', '/control',
            '/dashboard/admin', '/panel', '/backend'
        ]
        
        for endpoint in endpoints:
            url = endpoint['url']
            
            # Check if this looks like an admin endpoint
            is_admin_endpoint = any(pattern in url.lower() for pattern in admin_patterns)
            
            if is_admin_endpoint:
                try:
                    response = self.session.get(url, timeout=10)
                    
                    if response.status_code == 200:
                        # Check if response contains admin functionality
                        admin_indicators = [
                            'delete user', 'manage users', 'system settings',
                            'admin panel', 'user management', 'system configuration'
                        ]
                        
                        response_text = response.text.lower()
                        has_admin_content = any(indicator in response_text for indicator in admin_indicators)
                        
                        if has_admin_content:
                            vulnerabilities.append({
                                'type': 'privilege_escalation',
                                'severity': 'High',
                                'description': 'Admin functionality accessible to regular user',
                                'endpoint': url,
                                'method': 'GET',
                                'details': 'Admin panel or functionality accessible without proper authorization'
                            })
                
                except Exception as e:
                    logging.error(f"Error testing privilege escalation for {url}: {e}")
        
        return vulnerabilities
    
    def get_session_info(self):
        """Get current session information"""
        return {
            'authenticated': self.auth_handler.logged_in,
            'cookies': dict(self.session.cookies),
            'headers': dict(self.session.headers),
            'auth_info': self.auth_handler.get_auth_info()
        }
