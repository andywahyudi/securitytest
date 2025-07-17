#!/usr/bin/env python3
"""
CSRF (Cross-Site Request Forgery) Scanner Module
Detects CSRF vulnerabilities in web applications
"""

import requests
import re
import urllib.parse
from bs4 import BeautifulSoup
import time
import logging
import hashlib
import random
import string

class CSRFScanner:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        
        # Common CSRF token names
        self.csrf_token_names = [
            'csrf_token', 'csrftoken', '_token', 'authenticity_token',
            'csrf', '_csrf', 'token', '_wpnonce', 'nonce',
            'csrf_protection_token', 'form_token', 'security_token'
        ]
        
        # Common CSRF header names
        self.csrf_headers = [
            'X-CSRF-Token', 'X-CSRFToken', 'X-XSRF-TOKEN',
            'X-Requested-With', 'X-CSRF-HEADER'
        ]
        
        self.vulnerabilities = []
    
    def scan_endpoints(self, endpoints):
        """Scan multiple endpoints for CSRF vulnerabilities"""
        vulnerabilities = []
        
        logging.info(f"Starting CSRF scan on {len(endpoints)} endpoints")
        
        for i, endpoint in enumerate(endpoints):
            try:
                logging.debug(f"Scanning endpoint {i+1}/{len(endpoints)}: {endpoint.get('url', 'unknown')}")
                endpoint_vulns = self.scan_endpoint(endpoint)
                vulnerabilities.extend(endpoint_vulns)
                time.sleep(0.1)  # Rate limiting
            except Exception as e:
                logging.error(f"Error scanning endpoint {endpoint.get('url', 'unknown')}: {e}")
                continue
        
        logging.info(f"CSRF scan completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def scan_endpoint(self, endpoint):
        """Scan a single endpoint for CSRF vulnerabilities"""
        vulnerabilities = []
        url = endpoint.get('url', '')
        
        if not url:
            return vulnerabilities
        
        try:
            # Get the page to find forms
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            
            for form in forms:
                form_vulns = self._test_form_csrf(url, form, response)
                vulnerabilities.extend(form_vulns)
            
            # Test AJAX endpoints
            ajax_vulns = self._test_ajax_csrf(url, response)
            vulnerabilities.extend(ajax_vulns)
            
        except Exception as e:
            logging.error(f"Error scanning endpoint {url}: {e}")
        
        return vulnerabilities
    
    def _test_form_csrf(self, base_url, form, page_response):
        """Test form for CSRF vulnerabilities"""
        vulnerabilities = []
        
        try:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            # Skip GET forms (typically not vulnerable to CSRF)
            if method == 'GET':
                return vulnerabilities
            
            # Construct form URL
            if action.startswith('http'):
                form_url = action
            elif action.startswith('/'):
                parsed_base = urllib.parse.urlparse(base_url)
                form_url = f"{parsed_base.scheme}://{parsed_base.netloc}{action}"
            else:
                form_url = urllib.parse.urljoin(base_url, action)
            
            # Extract form data
            form_data = self._extract_form_data(form)
            
            # Test 1: Missing CSRF token
            csrf_missing_vuln = self._test_missing_csrf_token(form_url, form_data, method)
            if csrf_missing_vuln:
                vulnerabilities.append(csrf_missing_vuln)
            
            # Test 2: Weak CSRF token
            csrf_weak_vuln = self._test_weak_csrf_token(form_url, form_data, method, form)
            if csrf_weak_vuln:
                vulnerabilities.append(csrf_weak_vuln)
            
            # Test 3: CSRF token bypass
            csrf_bypass_vulns = self._test_csrf_token_bypass(form_url, form_data, method, form)
            vulnerabilities.extend(csrf_bypass_vulns)
            
            # Test 4: Referer header bypass
            referer_bypass_vuln = self._test_referer_bypass(form_url, form_data, method)
            if referer_bypass_vuln:
                vulnerabilities.append(referer_bypass_vuln)
            
        except Exception as e:
            logging.error(f"Error testing form CSRF: {e}")
        
        return vulnerabilities
    
    def _test_ajax_csrf(self, url, response):
        """Test AJAX endpoints for CSRF vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Look for AJAX endpoints in JavaScript
            js_patterns = [
                r'\.post\(["\']([^"\']+)["\']',
                r'\.ajax\({[^}]*url:\s*["\']([^"\']+)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'XMLHttpRequest.*open\(["\']POST["\'],\s*["\']([^"\']+)["\']'
            ]
            
            ajax_endpoints = set()
            
            for pattern in js_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    if match.startswith('/'):
                        parsed_url = urllib.parse.urlparse(url)
                        ajax_url = f"{parsed_url.scheme}://{parsed_url.netloc}{match}"
                    elif match.startswith('http'):
                        ajax_url = match
                    else:
                        ajax_url = urllib.parse.urljoin(url, match)
                    
                    ajax_endpoints.add(ajax_url)
            
            # Test each AJAX endpoint
            for ajax_url in list(ajax_endpoints)[:5]:  # Limit to 5 for performance
                ajax_vuln = self._test_ajax_endpoint_csrf(ajax_url)
                if ajax_vuln:
                    vulnerabilities.append(ajax_vuln)
            
        except Exception as e:
            logging.error(f"Error testing AJAX CSRF: {e}")
        
        return vulnerabilities
    
    def _extract_form_data(self, form):
        """Extract form data from form element"""
        form_data = {}
        
        inputs = form.find_all(['input', 'textarea', 'select'])
        
        for input_elem in inputs:
            name = input_elem.get('name', '')
            input_type = input_elem.get('type', 'text')
            value = input_elem.get('value', '')
            
            if name and input_type not in ['submit', 'button', 'reset']:
                if input_type == 'checkbox':
                    form_data[name] = 'on' if input_elem.get('checked') else ''
                elif input_type == 'radio':
                    if input_elem.get('checked'):
                        form_data[name] = value or 'on'
                elif input_elem.name == 'select':
                    selected = input_elem.find('option', selected=True)
                    form_data[name] = selected.get('value', '') if selected else ''
                elif input_elem.name == 'textarea':
                    form_data[name] = input_elem.get_text()
                else:
                    form_data[name] = value or 'test_value'
        
        return form_data
    
    def _test_missing_csrf_token(self, url, form_data, method):
        """Test if form is vulnerable due to missing CSRF token"""
        try:
            # Remove any potential CSRF tokens
            clean_data = {}
            for key, value in form_data.items():
                if not any(csrf_name in key.lower() for csrf_name in self.csrf_token_names):
                    clean_data[key] = value
            
            # Try to submit form without CSRF token
            if method == 'POST':
                response = self.session.post(url, data=clean_data)
            else:
                response = self.session.request(method, url, data=clean_data)
            
            # Check if request was successful (indicating missing CSRF protection)
            if response.status_code in [200, 201, 302, 303]:
                # Additional checks to confirm it's not just accepting the request
                if not self._has_csrf_error_indicators(response.text):
                    return {
                        'type': 'CSRF',
                        'subtype': 'Missing CSRF Token',
                        'severity': 'High',
                        'endpoint': url,
                        'method': method,
                        'description': 'Form does not implement CSRF protection',
                        'evidence': f'Form submission successful without CSRF token (Status: {response.status_code})',
                        'recommendation': 'Implement CSRF tokens for all state-changing operations',
                        'confidence': 'High'
                    }
            
        except Exception as e:
            logging.error(f"Error testing missing CSRF token: {e}")
        
        return None
    
    def _test_weak_csrf_token(self, url, form_data, method, form):
        """Test for weak CSRF token implementation"""
        vulnerabilities = []
        
        try:
            # Find CSRF token in form
            csrf_token_field = None
            csrf_token_value = None
            
            for key, value in form_data.items():
                if any(csrf_name in key.lower() for csrf_name in self.csrf_token_names):
                    csrf_token_field = key
                    csrf_token_value = value
                    break
            
            if not csrf_token_field or not csrf_token_value:
                return None
            
            # Test 1: Predictable token
            if self._is_predictable_token(csrf_token_value):
                return {
                    'type': 'CSRF',
                    'subtype': 'Weak CSRF Token',
                    'severity': 'Medium',
                    'endpoint': url,
                    'method': method,
                    'description': 'CSRF token appears to be predictable or weak',
                    'evidence': f'Token value: {csrf_token_value}',
                    'recommendation': 'Use cryptographically secure random tokens',
                    'confidence': 'Medium'
                }
            
            # Test 2: Token reuse
            reuse_vuln = self._test_token_reuse(url, form_data, method, csrf_token_field)
            if reuse_vuln:
                return reuse_vuln
            
        except Exception as e:
            logging.error(f"Error testing weak CSRF token: {e}")
        
        return None
    
    def _test_csrf_token_bypass(self, url, form_data, method, form):
        """Test various CSRF token bypass techniques"""
        vulnerabilities = []
        
        try:
            # Find CSRF token
            csrf_token_field = None
            for key in form_data.keys():
                if any(csrf_name in key.lower() for csrf_name in self.csrf_token_names):
                    csrf_token_field = key
                    break
            
            if not csrf_token_field:
                return vulnerabilities
            
            # Test 1: Empty token
            empty_token_vuln = self._test_empty_token(url, form_data, method, csrf_token_field)
            if empty_token_vuln:
                vulnerabilities.append(empty_token_vuln)
            
            # Test 2: Invalid token
            invalid_token_vuln = self._test_invalid_token(url, form_data, method, csrf_token_field)
            if invalid_token_vuln:
                vulnerabilities.append(invalid_token_vuln)
            
            # Test 3: Token parameter removal
            removal_vuln = self._test_token_removal(url, form_data, method, csrf_token_field)
            if removal_vuln:
                vulnerabilities.append(removal_vuln)
            
            # Test 4: Method override
            method_override_vuln = self._test_method_override(url, form_data, csrf_token_field)
            if method_override_vuln:
                vulnerabilities.append(method_override_vuln)
            
        except Exception as e:
            logging.error(f"Error testing CSRF token bypass: {e}")
        
        return vulnerabilities
    
    def _test_referer_bypass(self, url, form_data, method):
        """Test if CSRF protection relies only on Referer header"""
        try:
            # Test with missing Referer header
            headers = {'Referer': ''}
            
            if method == 'POST':
                response = self.session.post(url, data=form_data, headers=headers)
            else:
                response = self.session.request(method, url, data=form_data, headers=headers)
            
            if response.status_code in [200, 201, 302, 303]:
                if not self._has_csrf_error_indicators(response.text):
                    return {
                        'type': 'CSRF',
                        'subtype': 'Referer Header Bypass',
                        'severity': 'Medium',
                        'endpoint': url,
                        'method': method,
                        'description': 'CSRF protection can be bypassed by removing Referer header',
                        'evidence': f'Request successful without Referer header (Status: {response.status_code})',
                        'recommendation': 'Implement proper CSRF tokens instead of relying on Referer header',
                        'confidence': 'Medium'
                    }
            
        except Exception as e:
            logging.error(f"Error testing referer bypass: {e}")
        
        return None
    
    def _test_ajax_endpoint_csrf(self, url):
        """Test AJAX endpoint for CSRF vulnerabilities"""
        try:
            # Test without CSRF headers
            test_data = {'test': 'data'}
            
            response = self.session.post(url, json=test_data)
            
            if response.status_code in [200, 201, 202]:
                # Check if it requires specific headers
                headers_required = False
                
                # Test with common AJAX headers
                for header in self.csrf_headers:
                    test_response = self.session.post(url, json=test_data, headers={header: 'test'})
                    if test_response.status_code != response.status_code:
                        headers_required = True
                        break
                
                if not headers_required:
                    return {
                        'type': 'CSRF',
                        'subtype': 'AJAX CSRF',
                        'severity': 'High',
                        'endpoint': url,
                        'method': 'POST',
                        'description': 'AJAX endpoint vulnerable to CSRF attacks',
                        'evidence': f'AJAX request successful without CSRF protection (Status: {response.status_code})',
                        'recommendation': 'Implement CSRF tokens or custom headers for AJAX requests',
                        'confidence': 'High'
                    }
            
        except Exception as e:
            logging.error(f"Error testing AJAX CSRF: {e}")
        
        return None
    
    def _is_predictable_token(self, token):
        """Check if CSRF token is predictable"""
        if not token:
            return True
        
        # Check for common weak patterns
        weak_patterns = [
            r'^\d+$',  # Only numbers
            r'^[a-f0-9]{32}$',  # MD5 hash pattern
            r'^[a-f0-9]{40}$',  # SHA1 hash pattern
            r'^(test|admin|user|token|csrf).*',  # Predictable prefixes
            r'.*\d{10,}$',  # Timestamp-based
        ]
        
        for pattern in weak_patterns:
            if re.match(pattern, token, re.IGNORECASE):
                return True
        
        # Check for insufficient entropy
        if len(token) < 16:
            return True
        
        # Check for repeated characters
        if len(set(token)) < len(token) * 0.5:
            return True
        
        return False
    
    def _test_token_reuse(self, url, form_data, method, csrf_field):
        """Test if CSRF token can be reused"""
        try:
            original_token = form_data[csrf_field]
            
            # Submit form first time
            if method == 'POST':
                response1 = self.session.post(url, data=form_data)
            else:
                response1 = self.session.request(method, url, data=form_data)
            
            # Try to reuse the same token
            if method == 'POST':
                response2 = self.session.post(url, data=form_data)
            else:
                response2 = self.session.request(method, url, data=form_data)
            
            # If both requests succeed, token might be reusable
            if (response1.status_code in [200, 201, 302, 303] and 
                response2.status_code in [200, 201, 302, 303]):
                
                return {
                    'type': 'CSRF',
                    'subtype': 'Token Reuse',
                    'severity': 'Medium',
                    'endpoint': url,
                    'method': method,
                    'description': 'CSRF token can be reused multiple times',
                    'evidence': f'Token reused successfully: {original_token}',
                    'recommendation': 'Implement single-use CSRF tokens',
                    'confidence': 'Medium'
                }
            
        except Exception as e:
            logging.error(f"Error testing token reuse: {e}")
        
        return None
    
    def _test_empty_token(self, url, form_data, method, csrf_field):
        """Test if empty CSRF token is accepted"""
        try:
            test_data = form_data.copy()
            test_data[csrf_field] = ''
            
            if method == 'POST':
                response = self.session.post(url, data=test_data)
            else:
                response = self.session.request(method, url, data=test_data)
            
            if response.status_code in [200, 201, 302, 303]:
                if not self._has_csrf_error_indicators(response.text):
                    return {
                        'type': 'CSRF',
                        'subtype': 'Empty Token Bypass',
                        'severity': 'High',
                        'endpoint': url,
                        'method': method,
                        'description': 'Empty CSRF token is accepted',
                        'evidence': f'Request successful with empty token (Status: {response.status_code})',
                        'recommendation': 'Validate CSRF token presence and value',
                        'confidence': 'High'
                    }
            
        except Exception as e:
            logging.error(f"Error testing empty token: {e}")
        
        return None
    
    def _test_invalid_token(self, url, form_data, method, csrf_field):
        """Test if invalid CSRF token is accepted"""
        try:
            test_data = form_data.copy()
            test_data[csrf_field] = 'invalid_token_12345'
            
            if method == 'POST':
                response = self.session.post(url, data=test_data)
            else:
                response = self.session.request(method, url, data=test_data)
            
            if response.status_code in [200, 201, 302, 303]:
                if not self._has_csrf_error_indicators(response.text):
                    return {
                        'type': 'CSRF',
                        'subtype': 'Invalid Token Bypass',
                        'severity': 'High',
                        'endpoint': url,
                        'method': method,
                        'description': 'Invalid CSRF token is accepted',
                        'evidence': f'Request successful with invalid token (Status: {response.status_code})',
                        'recommendation': 'Implement proper CSRF token validation',
                        'confidence': 'High'
                    }
            
        except Exception as e:
            logging.error(f"Error testing invalid token: {e}")
        
        return None
    
    def _test_token_removal(self, url, form_data, method, csrf_field):
        """Test if CSRF token parameter can be removed"""
        try:
            test_data = form_data.copy()
            del test_data[csrf_field]
            
            if method == 'POST':
                response = self.session.post(url, data=test_data)
            else:
                response = self.session.request(method, url, data=test_data)
            
            if response.status_code in [200, 201, 302, 303]:
                if not self._has_csrf_error_indicators(response.text):
                    return {
                        'type': 'CSRF',
                        'subtype': 'Token Removal Bypass',
                        'severity': 'High',
                        'endpoint': url,
                        'method': method,
                        'description': 'CSRF protection can be bypassed by removing token parameter',
                        'evidence': f'Request successful without token parameter (Status: {response.status_code})',
                        'recommendation': 'Ensure CSRF token is required and validated',
                        'confidence': 'High'
                    }
            
        except Exception as e:
            logging.error(f"Error testing token removal: {e}")
        
        return None
    
    def _test_method_override(self, url, form_data, csrf_field):
        """Test if CSRF protection can be bypassed using method override"""
        try:
            # Test GET method override
            test_data = form_data.copy()
            test_data['_method'] = 'POST'
            
            response = self.session.get(url, params=test_data)
            
            if response.status_code in [200, 201, 302, 303]:
                if not self._has_csrf_error_indicators(response.text):
                    return {
                        'type': 'CSRF',
                        'subtype': 'Method Override Bypass',
                        'severity': 'Medium',
                        'endpoint': url,
                        'method': 'GET (Override)',
                        'description': 'CSRF protection bypassed using HTTP method override',
                        'evidence': f'POST request successful via GET with method override (Status: {response.status_code})',
                        'recommendation': 'Validate HTTP method and disable method override for sensitive operations',
                        'confidence': 'Medium'
                    }
            
        except Exception as e:
            logging.error(f"Error testing method override: {e}")
        
        return None
    
    def _has_csrf_error_indicators(self, response_text):
        """Check if response contains CSRF error indicators"""
        error_indicators = [
            'csrf',
            'token',
            'forbidden',
            'invalid',
            'expired',
            'missing',
            'unauthorized',
            'access denied',
            'security',
            'verification failed'
        ]
        
        response_lower = response_text.lower()
        
        for indicator in error_indicators:
            if indicator in response_lower:
                return True
        
        return False
    
    def generate_csrf_poc(self, vulnerability):
        """Generate CSRF Proof of Concept"""
        endpoint = vulnerability.get('endpoint', '')
        method = vulnerability.get('method', 'POST')
        
        # Generate random form ID
        form_id = ''.join(random.choices(string.ascii_lowercase, k=8))
        
        poc_html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Proof of Concept</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p><strong>Target:</strong> {endpoint}</p>
    <p><strong>Method:</strong> {method}</p>
    <p><strong>Vulnerability:</strong> {vulnerability.get('subtype', 'CSRF')}</p>
    
    <form id="{form_id}" action="{endpoint}" method="{method}">
        <input type="hidden" name="test_param" value="csrf_test_value">
        <input type="submit" value="Execute CSRF Attack">
    </form>
    
    <script>
        // Auto-submit form (uncomment for automatic execution)
        // document.getElementById('{form_id}').submit();
    </script>
    
    <h2>Manual Testing:</h2>
    <ol>
        <li>Host this HTML file on a different domain</li>
        <li>Ensure the victim is logged into the target application</li>
        <li>Have the victim visit this page</li>
        <li>Click the submit button or enable auto-submit</li>
        <li>Check if the request is processed successfully</li>
    </ol>
    
    <h2>Remediation:</h2>
    <ul>
        <li>Implement CSRF tokens for all state-changing operations</li>
        <li>Validate the Referer/Origin headers</li>
        <li>Use SameSite cookie attributes</li>
        <li>Implement proper session management</li>
    </ul>
</body>
</html>
"""
        
        return poc_html
    
    def test_samesite_bypass(self, url, form_data, method):
        """Test SameSite cookie bypass techniques"""
        vulnerabilities = []
        
        try:
            # Test with different origins
            test_origins = [
                'https://evil.com',
                'https://attacker.example.com',
                'null'
            ]
            
            for origin in test_origins:
                headers = {
                    'Origin': origin,
                    'Referer': f"{origin}/attack.html"
                }
                
                if method == 'POST':
                    response = self.session.post(url, data=form_data, headers=headers)
                else:
                    response = self.session.request(method, url, data=form_data, headers=headers)
                
                if response.status_code in [200, 201, 302, 303]:
                    if not self._has_csrf_error_indicators(response.text):
                        vulnerabilities.append({
                            'type': 'CSRF',
                            'subtype': 'SameSite Bypass',
                            'severity': 'Medium',
                            'endpoint': url,
                            'method': method,
                            'description': f'CSRF protection bypassed from origin: {origin}',
                            'evidence': f'Cross-origin request successful (Status: {response.status_code})',
                            'recommendation': 'Implement proper SameSite cookie attributes and Origin validation',
                            'confidence': 'Medium'
                        })
            
        except Exception as e:
            logging.error(f"Error testing SameSite bypass: {e}")
        
        return vulnerabilities
    
    def get_csrf_statistics(self):
        """Get statistics about CSRF scan results"""
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerability_types': {
                'missing_token': len([v for v in self.vulnerabilities if v.get('subtype') == 'Missing CSRF Token']),
                'weak_token': len([v for v in self.vulnerabilities if v.get('subtype') == 'Weak CSRF Token']),
                'token_bypass': len([v for v in self.vulnerabilities if 'Bypass' in v.get('subtype', '')]),
                'ajax_csrf': len([v for v in self.vulnerabilities if v.get('subtype') == 'AJAX CSRF'])
            }
        }