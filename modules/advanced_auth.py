import requests
import json
import time
import base64
from urllib.parse import urljoin, urlparse, parse_qs
import logging
from .auth_handler import AuthHandler

class AdvancedAuthHandler(AuthHandler):
    def __init__(self, session=None):
        super().__init__(session)
        self.auth_flow_history = []
        self.token_refresh_url = None
        self.refresh_token = None
        
    def login_multi_step(self, steps):
        """Handle multi-step authentication process"""
        try:
            for i, step in enumerate(steps):
                logging.info(f"Executing authentication step {i+1}/{len(steps)}")
                
                url = step['url']
                method = step.get('method', 'POST').upper()
                data = step.get('data', {})
                headers = step.get('headers', {})
                
                # Add any CSRF tokens from previous steps
                if hasattr(self, 'csrf_tokens'):
                    data.update(self.csrf_tokens)
                
                # Execute step
                if method == 'POST':
                    response = self.session.post(url, data=data, headers=headers, timeout=10)
                elif method == 'GET':
                    response = self.session.get(url, params=data, headers=headers, timeout=10)
                else:
                    logging.error(f"Unsupported HTTP method: {method}")
                    return False
                
                # Store step in history
                self.auth_flow_history.append({
                    'step': i+1,
                    'url': url,
                    'method': method,
                    'status_code': response.status_code,
                    'response_length': len(response.text)
                })
                
                # Extract tokens for next step
                self.csrf_tokens.update(self.extract_csrf_token(response.text))
                
                # Check if step was successful
                if not self.verify_step_success(response, step):
                    logging.error(f"Authentication step {i+1} failed")
                    return False
            
            # Verify final authentication
            if self.verify_authentication(response):
                self.logged_in = True
                logging.info("Multi-step authentication completed successfully")
                return True
            else:
                logging.error("Multi-step authentication failed at final verification")
                return False
                
        except Exception as e:
            logging.error(f"Error during multi-step authentication: {e}")
            return False
    
    def verify_step_success(self, response, step_config):
        """Verify if an authentication step was successful"""
        # Check status code
        expected_status = step_config.get('expected_status', [200, 302])
        if isinstance(expected_status, int):
            expected_status = [expected_status]
        
        if response.status_code not in expected_status:
            return False
        
        # Check for success indicators
        success_indicators = step_config.get('success_indicators', [])
        if success_indicators:
            response_text = response.text.lower()
            for indicator in success_indicators:
                if indicator.lower() in response_text:
                    return True
            return False
        
        # Check for failure indicators
        failure_indicators = step_config.get('failure_indicators', [])
        if failure_indicators:
            response_text = response.text.lower()
            for indicator in failure_indicators:
                if indicator.lower() in response_text:
                    return False
        
        return True
    
    def login_oauth_simulation(self, config):
        """Simulate OAuth authentication flow"""
        try:
            # Step 1: Get authorization code
            auth_url = config['authorization_url']
            client_id = config['client_id']
            redirect_uri = config['redirect_uri']
            
            auth_params = {
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'response_type': 'code',
                'scope': config.get('scope', 'read')
            }
            
            # This is a simplified simulation - in real OAuth, user would authorize
            auth_response = self.session.get(auth_url, params=auth_params, timeout=10)
            
            # Extract authorization code (simplified)
            auth_code = self.extract_auth_code(auth_response.text)
            if not auth_code:
                logging.error("Failed to extract authorization code")
                return False
            
            # Step 2: Exchange code for token
            token_url = config['token_url']
            token_data = {
                'grant_type': 'authorization_code',
                'code': auth_code,
                'client_id': client_id,
                'client_secret': config['client_secret'],
                'redirect_uri': redirect_uri
            }
            
            token_response = self.session.post(token_url, data=token_data, timeout=10)
            
            if token_response.status_code == 200:
                token_data = token_response.json()
                access_token = token_data.get('access_token')
                
                if access_token:
                    # Set authorization header
                    self.session.headers['Authorization'] = f"Bearer {access_token}"
                    self.logged_in = True
                    
                    # Store refresh token if available
                    self.refresh_token = token_data.get('refresh_token')
                    self.token_refresh_url = token_url
                    
                    logging.info("OAuth authentication successful")
                    return True
            
            logging.error("OAuth token exchange failed")
            return False
            
        except Exception as e:
            logging.error(f"Error during OAuth authentication: {e}")
            return False
    
    def extract_auth_code(self, html_content):
        """Extract authorization code from OAuth response"""
        # This is a simplified extraction - real implementation would be more robust
        import re
        
        patterns = [
            r'code=([^&\s"\']+)',
            r'"code":\s*"([^"]+)"',
            r'authorization_code["\']?\s*:\s*["\']?([^"\'&\s]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html_content)
            if match:
                return match.group(1)
        
        return None
    
    def refresh_access_token(self):
        """Refresh OAuth access token"""
        if not self.refresh_token or not self.token_refresh_url:
            return False
        
        try:
            refresh_data = {
                'grant_type': 'refresh_token',
                'refresh_token': self.refresh_token
            }
            
            response = self.session.post(self.token_refresh_url, data=refresh_data, timeout=10)
            
            if response.status_code == 200:
                token_data = response.json()
                new_access_token = token_data.get('access_token')
                
                if new_access_token:
                    self.session.headers['Authorization'] = f"Bearer {new_access_token}"
                    
                    # Update refresh token if provided
                    new_refresh_token = token_data.get('refresh_token')
                    if new_refresh_token:
                        self.refresh_token = new_refresh_token
                    
                    logging.info("Access token refreshed successfully")
                    return True
            
            logging.error("Failed to refresh access token")
            return False
            
        except Exception as e:
            logging.error(f"Error refreshing access token: {e}")
            return False
    
    def login_with_captcha(self, login_url, username, password, captcha_solver=None):
        """Handle login with CAPTCHA protection"""
        try:
            # Get login page
            response = self.session.get(login_url, timeout=10)
            
            # Extract CAPTCHA challenge
            captcha_challenge = self.extract_captcha_challenge(response.text)
            
            if captcha_challenge:
                if captcha_solver:
                    captcha_solution = captcha_solver(captcha_challenge)
                else:
                    # For demo purposes, use a simple bypass
                    captcha_solution = "bypass"
                
                # Prepare login data with CAPTCHA solution
                login_data = {
                    'username': username,
                    'password': password,
                    'captcha': captcha_solution
                }
            else:
                login_data = {
                    'username': username,
                    'password': password
                }
            
            # Add CSRF tokens
            csrf_tokens = self.extract_csrf_token(response.text)
            login_data.update(csrf_tokens)
            
            # Perform login
            login_response = self.session.post(login_url, data=login_data, timeout=10)
            
            if self.verify_authentication(login_response):
                self.logged_in = True
                logging.info("Login with CAPTCHA successful")
                return True
            else:
                logging.error("Login with CAPTCHA failed")
                return False
                
        except Exception as e:
            logging.error(f"Error during CAPTCHA login: {e}")
            return False
    
    def extract_captcha_challenge(self, html_content):
        """Extract CAPTCHA challenge from HTML"""
        import re
        
        # Look for common CAPTCHA patterns
        patterns = [
            r'<img[^>]*src=["\']?([^"\'>\s]*captcha[^"\'>\s]*)["\']?[^>]*>',
            r'data-captcha=["\']?([^"\'>\s]+)["\']?',
            r'captcha_challenge["\']?\s*:\s*["\']?([^"\'&\s]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def test_authentication_bypass(self, protected_url):
        """Test various authentication bypass techniques"""
        bypass_results = []
        
        # Test 1: Direct access
        try:
            response = requests.get(protected_url, timeout=10)
            if response.status_code == 200 and self.verify_authentication(response):
                bypass_results.append({
                    'method': 'direct_access',
                    'success': True,
                    'description': 'Protected resource accessible without authentication'
                })
        except:
            pass
        
        # Test 2: HTTP method bypass
        methods = ['POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        for method in methods:
            try:
                response = requests.request(method, protected_url, timeout=10)
                if response.status_code == 200:
                    bypass_results.append({
                        'method': f'http_method_{method.lower()}',
                        'success': True,
                        'description': f'Protected resource accessible via {method} method'
                    })
            except:
                pass
        
        # Test 3: Header manipulation
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Original-URL': '/admin'},
            {'Referer': 'http://localhost/admin'},
            {'User-Agent': 'GoogleBot/2.1'}
        ]
        
        for headers in bypass_headers:
            try:
                response = requests.get(protected_url, headers=headers, timeout=10)
                if response.status_code == 200 and self.verify_authentication(response):
                    bypass_results.append({
                        'method': 'header_manipulation',
                        'success': True,
                        'description': f'Bypass using headers: {headers}',
                        'headers': headers
                    })
            except:
                pass
        
        # Test 4: URL manipulation
        parsed_url = urlparse(protected_url)
        url_variations = [
            f"{protected_url}/",
            f"{protected_url}//",
            f"{protected_url}/../admin",
            f"{protected_url}%2e%2e/admin",
            f"{protected_url}?admin=true",
            f"{protected_url}#admin"
        ]
        
        for url in url_variations:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200 and self.verify_authentication(response):
                    bypass_results.append({
                        'method': 'url_manipulation',
                        'success': True,
                        'description': f'Bypass using URL: {url}',
                        'url': url
                    })
            except:
                pass
        
        return bypass_results
    
    def get_auth_flow_history(self):
        """Get authentication flow history for debugging"""
        return self.auth_flow_history
    
    def export_session(self, filename):
        """Export current session for reuse"""
        session_data = {
            'cookies': dict(self.session.cookies),
            'headers': dict(self.session.headers),
            'auth_info': self.get_auth_info(),
            'csrf_tokens': self.csrf_tokens,
            'logged_in': self.logged_in,
            'login_url': self.login_url
        }
        try:
            with open(filename, 'w') as f:
                json.dump(session_data, f, indent=2)
            logging.info(f"Session exported to {filename}")
            return True
        except Exception as e:
            logging.error(f"Failed to export session: {e}")
            return False
    
    def import_session(self, filename):
        """Import previously saved session"""
        try:
            with open(filename, 'r') as f:
                session_data = json.load(f)
            
            # Restore cookies
            for name, value in session_data.get('cookies', {}).items():
                self.session.cookies.set(name, value)
            
            # Restore headers
            self.session.headers.update(session_data.get('headers', {}))
            
            # Restore auth info
            self.csrf_tokens = session_data.get('csrf_tokens', {})
            self.logged_in = session_data.get('logged_in', False)
            self.login_url = session_data.get('login_url')
            
            logging.info(f"Session imported from {filename}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to import session: {e}")
            return False