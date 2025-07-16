import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import time

class CSRFTester:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.setup_session()
        
        # Common CSRF token names
        self.csrf_token_names = [
            'csrf_token', 'csrftoken', '_token', 'authenticity_token',
            'csrf', '_csrf', 'token', '_wpnonce', 'nonce',
            'csrf_protection_token', 'form_token'
        ]
        
        # Sensitive actions that should have CSRF protection
        self.sensitive_actions = [
            'delete', 'remove', 'update', 'edit', 'change',
            'password', 'email', 'profile', 'admin',
            'transfer', 'payment', 'purchase', 'order'
        ]
    
    def setup_session(self):
        """Setup session with cookies and headers"""
        if self.config.cookies:
            cookie_dict = {}
            for cookie in self.config.cookies.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    cookie_dict[name] = value
            self.session.cookies.update(cookie_dict)
        
        if self.config.headers:
            for header in self.config.headers.split(','):
                if ':' in header:
                    name, value = header.strip().split(':', 1)
                    self.session.headers[name] = value.strip()
    
    def test_endpoints(self, endpoints):
        """Test all endpoints for CSRF vulnerabilities"""
        results = []
        
        for endpoint in endpoints:
            if endpoint['type'] == 'form':
                results.extend(self.test_form_csrf(endpoint))
        
        return results
    
    def test_form_csrf(self, endpoint):
        """Test forms for CSRF vulnerabilities"""
        results = []
        url = endpoint['url']
        method = endpoint.get('method', 'GET').upper()
        inputs = endpoint.get('inputs', [])
        
        # Skip GET forms (typically search forms)
        if method == 'GET':
            return results
        
        # Check if this is a sensitive form
        is_sensitive = self.is_sensitive_form(url, inputs)
        
        # Test 1: Check for CSRF token presence
        csrf_token_present = self.check_csrf_token_presence(inputs)
        
        # Test 2: Test CSRF token validation
        csrf_validation_result = self.test_csrf_validation(endpoint)
        
        # Test 3: Test SameSite cookie protection
        samesite_protection = self.check_samesite_protection()
        
        # Test 4: Test Referer header validation
        referer_validation = self.test_referer_validation(endpoint)
        
        # Analyze results
        vulnerability = self.analyze_csrf_results(
            url, method, is_sensitive, csrf_token_present,
            csrf_validation_result, samesite_protection, referer_validation
        )
        
        if vulnerability:
            results.append(vulnerability)
        
        return results
    
    def is_sensitive_form(self, url, inputs):
        """Check if form performs sensitive actions"""
        url_lower = url.lower()
        
        # Check URL for sensitive keywords
        for action in self.sensitive_actions:
            if action in url_lower:
                return True
        
        # Check input names and values for sensitive keywords
        for input_field in inputs:
            name = input_field.get('name', '').lower()
            value = input_field.get('value', '').lower()
            
            for action in self.sensitive_actions:
                if action in name or action in value:
                    return True
        
        return False
    
    def check_csrf_token_presence(self, inputs):
        """Check if CSRF token is present in form"""
        for input_field in inputs:
            name = input_field.get('name', '').lower()
            input_type = input_field.get('type', '').lower()
            
            # Check for CSRF token by name
            for token_name in self.csrf_token_names:
                if token_name in name:
                    return True
            
            # Check for hidden fields that might be tokens
            if input_type == 'hidden' and len(input_field.get('value', '')) > 10:
                return True
        
        return False
    
    def test_csrf_validation(self, endpoint):
        """Test if CSRF token is properly validated"""
        url = endpoint['url']
        inputs = endpoint.get('inputs', [])
        
        try:
            # First, get the original form to extract CSRF token
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find the form
            forms = soup.find_all('form')
            target_form = None
            
            for form in forms:
                form_inputs = form.find_all(['input', 'textarea', 'select'])
                if len(form_inputs) >= len(inputs):
                    target_form = form
                    break
            
            if not target_form:
                return {'status': 'error', 'message': 'Form not found'}
            
            # Extract form data
            form_data = {}
            csrf_token_field = None
            
            for input_elem in target_form.find_all(['input', 'textarea']):
                name = input_elem.get('name')
                value = input_elem.get('value', '')
                
                if name:
                    form_data[name] = value
                    
                    # Check if this is a CSRF token
                    if any(token_name in name.lower() for token_name in self.csrf_token_names):
                        csrf_token_field = name
            
            if not csrf_token_field:
                return {'status': 'no_token', 'message': 'No CSRF token found'}
            
            # Test 1: Submit with original token (should succeed)
            original_response = self.session.post(url, data=form_data, timeout=10)
            
            # Test 2: Submit with modified token (should fail)
            modified_data = form_data.copy()
            modified_data[csrf_token_field] = 'invalid_token_12345'
            
            modified_response = self.session.post(url, data=modified_data, timeout=10)
            
            # Test 3: Submit without token (should fail)
            no_token_data = form_data.copy()
            del no_token_data[csrf_token_field]
            
            no_token_response = self.session.post(url, data=no_token_data, timeout=10)
            
            # Analyze responses
            return self.analyze_csrf_responses(
                original_response, modified_response, no_token_response
            )
        
        except requests.RequestException as e:
            return {'status': 'error', 'message': str(e)}
    
    def analyze_csrf_responses(self, original, modified, no_token):
        """Analyze CSRF validation responses"""
        # Check if modified token request was rejected
        modified_rejected = (
            modified.status_code != original.status_code or
            'error' in modified.text.lower() or
            'invalid' in modified.text.lower() or
            'forbidden' in modified.text.lower()
        )
        
        # Check if no token request was rejected
        no_token_rejected = (
            no_token.status_code != original.status_code or
            'error' in no_token.text.lower() or
            'invalid' in no_token.text.lower() or
            'forbidden' in no_token.text.lower()
        )
        
        if modified_rejected and no_token_rejected:
            return {'status': 'protected', 'message': 'CSRF token properly validated'}
        elif not modified_rejected and not no_token_rejected:
            return {'status': 'vulnerable', 'message': 'CSRF token not validated'}
        else:
            return {'status': 'partial', 'message': 'Partial CSRF protection'}
    
    def check_samesite_protection(self):
        """Check if cookies have SameSite protection"""
        # This would need to be implemented by checking Set-Cookie headers
        # For now, return a basic check
        return {'status': 'unknown', 'message': 'SameSite check not implemented'}
    
    def test_referer_validation(self, endpoint):
        """Test if Referer header is validated"""
        url = endpoint['url']
        inputs = endpoint.get('inputs', [])
        
        try:
            # Prepare form data
            form_data = {}
            for input_field in inputs:
                name = input_field.get('name')
                if name:
                    form_data[name] = 'test_value'
            
            # Test with valid referer
            headers_valid = {'Referer': url}
            valid_response = self.session.post(url, data=form_data, headers=headers_valid, timeout=10)
            
            # Test with invalid referer
            headers_invalid = {'Referer': 'http://evil.com/'}
            invalid_response = self.session.post(url, data=form_data, headers=headers_invalid, timeout=10)
            
            # Test without referer
            no_referer_response = self.session.post(url, data=form_data, timeout=10)
            
            # Analyze responses
            if (invalid_response.status_code != valid_response.status_code or
                no_referer_response.status_code != valid_response.status_code):
                return {'status': 'protected', 'message': 'Referer validation present'}
            else:
                return {'status': 'vulnerable', 'message': 'No referer validation'}
        
        except requests.RequestException as e:
            return {'status': 'error', 'message': str(e)}
    
    def analyze_csrf_results(self, url, method, is_sensitive, csrf_token_present,
                           csrf_validation, samesite_protection, referer_validation):
        """Analyze all CSRF test results"""
        
        if not is_sensitive:
            return None  # Not a sensitive form, skip
        
        vulnerabilities = []
        severity = 'Low'
        
        # Check CSRF token presence
        if not csrf_token_present:
            vulnerabilities.append('No CSRF token found')
            severity = 'High'
        
        # Check CSRF validation
        if csrf_validation['status'] == 'vulnerable':
            vulnerabilities.append('CSRF token not properly validated')
            severity = 'High'
        elif csrf_validation['status'] == 'partial':
            vulnerabilities.append('Partial CSRF protection')
            severity = 'Medium'
        
        # Check referer validation
        if referer_validation['status'] == 'vulnerable':
            vulnerabilities.append('No referer header validation')
            if severity == 'Low':
                severity = 'Medium'
        
        if vulnerabilities:
            return {
                'type': 'CSRF',
                'endpoint': url,
                'method': method,
                'severity': severity,
                'vulnerabilities': vulnerabilities,
                'description': f'CSRF vulnerability found: {", ".join(vulnerabilities)}',
                'csrf_validation': csrf_validation,
                'referer_validation': referer_validation
            }
        
        return None
