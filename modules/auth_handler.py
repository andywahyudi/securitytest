import requests
import re
from urllib.parse import urljoin, urlparse
import logging

class AuthHandler:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.logged_in = False
        self.login_url = None
        self.auth_cookies = {}
        self.auth_headers = {}
        self.csrf_tokens = {}
        
    def detect_login_form(self, url):
        """Detect login forms on a page"""
        try:
            response = self.session.get(url, timeout=10)
            
            # Look for common login form patterns
            login_patterns = [
                r'<form[^>]*action[^>]*login[^>]*>',
                r'<form[^>]*login[^>]*>',
                r'<input[^>]*type=["\']password["\'][^>]*>',
                r'<input[^>]*name=["\']password["\'][^>]*>',
                r'<input[^>]*name=["\']username["\'][^>]*>',
                r'<input[^>]*name=["\']email["\'][^>]*>'
            ]
            
            for pattern in login_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True
                    
            return False
            
        except Exception as e:
            logging.error(f"Error detecting login form: {e}")
            return False
    
    def extract_csrf_token(self, html_content, token_names=None):
        """Extract CSRF token from HTML content"""
        if token_names is None:
            token_names = ['csrf_token', '_token', 'authenticity_token', 'csrfmiddlewaretoken']
        
        for token_name in token_names:
            # Look for hidden input fields
            pattern = rf'<input[^>]*name=["\']?{token_name}["\']?[^>]*value=["\']?([^"\'>\s]+)["\']?[^>]*>'
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                return {token_name: match.group(1)}
        
        # Look for meta tags
        meta_pattern = r'<meta[^>]*name=["\']?csrf-token["\']?[^>]*content=["\']?([^"\'>\s]+)["\']?[^>]*>'
        match = re.search(meta_pattern, html_content, re.IGNORECASE)
        if match:
            return {'csrf_token': match.group(1)}
        
        return {}
    
    def login_form_based(self, login_url, username, password, username_field='username', password_field='password'):
        """Perform form-based authentication"""
        try:
            # Get login page
            response = self.session.get(login_url, timeout=10)
            if response.status_code != 200:
                logging.error(f"Failed to access login page: {response.status_code}")
                return False
            
            # Extract CSRF token if present
            csrf_tokens = self.extract_csrf_token(response.text)
            
            # Prepare login data
            login_data = {
                username_field: username,
                password_field: password
            }
            
            # Add CSRF tokens
            login_data.update(csrf_tokens)
            
            # Extract form action
            form_action_pattern = r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*>'
            form_match = re.search(form_action_pattern, response.text, re.IGNORECASE)
            
            if form_match:
                action_url = urljoin(login_url, form_match.group(1))
            else:
                action_url = login_url
            
            # Perform login
            login_response = self.session.post(action_url, data=login_data, timeout=10)
            
            # Check if login was successful
            if self.verify_authentication(login_response):
                self.logged_in = True
                self.login_url = login_url
                self.auth_cookies = dict(self.session.cookies)
                logging.info("Successfully authenticated via form-based login")
                return True
            else:
                logging.error("Form-based authentication failed")
                return False
                
        except Exception as e:
            logging.error(f"Error during form-based login: {e}")
            return False
    
    def login_basic_auth(self, url, username, password):
        """Perform HTTP Basic Authentication"""
        try:
            from requests.auth import HTTPBasicAuth
            self.session.auth = HTTPBasicAuth(username, password)
            
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                self.logged_in = True
                logging.info("Successfully authenticated via Basic Auth")
                return True
            else:
                logging.error(f"Basic authentication failed: {response.status_code}")
                return False
                
        except Exception as e:
            logging.error(f"Error during basic authentication: {e}")
            return False
    
    def login_with_cookies(self, cookies_string):
        """Set authentication cookies manually"""
        try:
            # Parse cookies string (format: name1=value1;name2=value2)
            cookies = {}
            for cookie in cookies_string.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    cookies[name] = value
            
            # Set cookies in session
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
            
            self.auth_cookies = cookies
            self.logged_in = True
            logging.info("Authentication cookies set successfully")
            return True
            
        except Exception as e:
            logging.error(f"Error setting authentication cookies: {e}")
            return False
    
    def login_with_headers(self, headers_string):
        """Set authentication headers manually"""
        try:
            # Parse headers string (format: Header1:Value1,Header2:Value2)
            headers = {}
            for header in headers_string.split(','):
                if ':' in header:
                    name, value = header.strip().split(':', 1)
                    headers[name] = value.strip()
            
            # Set headers in session
            self.session.headers.update(headers)
            self.auth_headers = headers
            self.logged_in = True
            logging.info("Authentication headers set successfully")
            return True
            
        except Exception as e:
            logging.error(f"Error setting authentication headers: {e}")
            return False
    
    def verify_authentication(self, response):
        """Verify if authentication was successful"""
        # Check for common authentication failure indicators
        failure_indicators = [
            'login failed', 'invalid credentials', 'authentication failed',
            'incorrect username', 'incorrect password', 'access denied',
            'unauthorized', 'please log in', 'login required'
        ]
        
        response_text = response.text.lower()
        
        # Check for failure indicators
        for indicator in failure_indicators:
            if indicator in response_text:
                return False
        
        # Check for success indicators
        success_indicators = [
            'dashboard', 'welcome', 'logout', 'profile', 'settings',
            'admin panel', 'user panel', 'my account'
        ]
        
        for indicator in success_indicators:
            if indicator in response_text:
                return True
        
        # Check status code and redirects
        if response.status_code == 200 and 'login' not in response.url.lower():
            return True
        
        return False
    
    def maintain_session(self, url):
        """Maintain authentication session by refreshing tokens if needed"""
        try:
            response = self.session.get(url, timeout=10)
            
            # Check if we're still authenticated
            if not self.verify_authentication(response):
                logging.warning("Session appears to have expired")
                return False
            
            # Update CSRF tokens if found
            new_tokens = self.extract_csrf_token(response.text)
            self.csrf_tokens.update(new_tokens)
            
            return True
            
        except Exception as e:
            logging.error(f"Error maintaining session: {e}")
            return False
    
    def get_authenticated_session(self):
        """Get the authenticated session object"""
        return self.session if self.logged_in else None
    
    def get_auth_info(self):
        """Get authentication information for reporting"""
        return {
            'logged_in': self.logged_in,
            'login_url': self.login_url,
            'cookies': list(self.auth_cookies.keys()),
            'headers': list(self.auth_headers.keys()),
            'csrf_tokens': list(self.csrf_tokens.keys())
        }