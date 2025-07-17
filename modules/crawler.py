#!/usr/bin/env python3
"""
Web Crawler Module
Discovers endpoints and forms in web applications
"""

import requests
import urllib.parse
from bs4 import BeautifulSoup
import time
import logging
import re
from collections import deque
from urllib.robotparser import RobotFileParser

class WebCrawler:
    def __init__(self, session=None, user_agent=None):
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        
        if user_agent:
            self.session.headers.update({'User-Agent': user_agent})
        else:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
            })
        
        self.visited_urls = set()
        self.discovered_endpoints = []
        self.robots_parser = None
        
        # File extensions to skip
        self.skip_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.tar', '.gz', '.mp3', '.mp4', '.avi',
            '.css', '.js', '.woff', '.woff2', '.ttf', '.eot'
        }
        
        # Common parameter names to look for
        self.common_params = [
            'id', 'user', 'username', 'email', 'search', 'q', 'query',
            'name', 'message', 'comment', 'content', 'data', 'input',
            'page', 'limit', 'offset', 'sort', 'order', 'filter',
            'category', 'type', 'status', 'action', 'cmd', 'file'
        ]
    
    def crawl(self, start_url, max_depth=2, max_pages=100, delay=0.1):
        """Crawl website starting from given URL"""
        logging.info(f"Starting crawl of {start_url} with max depth {max_depth}")
        
        # Parse robots.txt
        self._parse_robots_txt(start_url)
        
        # Initialize crawling queue
        queue = deque([(start_url, 0)])  # (url, depth)
        pages_crawled = 0
        
        while queue and pages_crawled < max_pages:
            current_url, depth = queue.popleft()
            
            if depth > max_depth:
                continue
            
            if current_url in self.visited_urls:
                continue
            
            if not self._should_crawl_url(current_url):
                continue
            
            try:
                logging.debug(f"Crawling: {current_url} (depth: {depth})")
                
                response = self.session.get(current_url)
                self.visited_urls.add(current_url)
                pages_crawled += 1
                
                # Extract endpoint information
                endpoint_info = self._extract_endpoint_info(current_url, response)
                if endpoint_info:
                    self.discovered_endpoints.append(endpoint_info)
                
                # Find new URLs to crawl
                if depth < max_depth:
                    new_urls = self._extract_urls(current_url, response.text)
                    for new_url in new_urls:
                        if new_url not in self.visited_urls:
                            queue.append((new_url, depth + 1))
                
                time.sleep(delay)
                
            except Exception as e:
                logging.error(f"Error crawling {current_url}: {e}")
                continue
        
        logging.info(f"Crawl completed. Discovered {len(self.discovered_endpoints)} endpoints")
        return self.discovered_endpoints
    
    def _parse_robots_txt(self, base_url):
        """Parse robots.txt file"""
        try:
            parsed_url = urllib.parse.urlparse(base_url)
            robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
            
            self.robots_parser = RobotFileParser()
            self.robots_parser.set_url(robots_url)
            self.robots_parser.read()
            
            logging.debug(f"Parsed robots.txt from {robots_url}")
            
        except Exception as e:
            logging.debug(f"Could not parse robots.txt: {e}")
            self.robots_parser = None
    
    def _should_crawl_url(self, url):
        """Check if URL should be crawled"""
        try:
            # Check robots.txt
            if self.robots_parser:
                user_agent = self.session.headers.get('User-Agent', '*')
                if not self.robots_parser.can_fetch(user_agent, url):
                    return False
            
            # Check file extension
            parsed_url = urllib.parse.urlparse(url)
            path = parsed_url.path.lower()
            
            for ext in self.skip_extensions:
                if path.endswith(ext):
                    return False
            
            # Skip common non-HTML files
            if any(keyword in path for keyword in ['/api/docs', '/swagger', '/admin/static']):
                return False
            
            return True
            
        except Exception as e:
            logging.error(f"Error checking if should crawl {url}: {e}")
            return False
    
    def _extract_endpoint_info(self, url, response):
        """Extract endpoint information from response"""
        try:
            endpoint_info = {
                'url': url,
                'method': 'GET',
                'status_code': response.status_code,
                'content_type': response.headers.get('Content-Type', ''),
                'forms': [],
                'parameters': [],
                'links': []
            }
            
            # Only process HTML responses
            if 'text/html' not in endpoint_info['content_type']:
                return endpoint_info
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            forms = soup.find_all('form')
            for form in forms:
                form_info = self._extract_form_info(url, form)
                if form_info:
                    endpoint_info['forms'].append(form_info)
            
            # Extract URL parameters
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.query:
                params = urllib.parse.parse_qs(parsed_url.query)
                endpoint_info['parameters'] = list(params.keys())
            
            # Extract links
            links = soup.find_all('a', href=True)
            for link in links:
                href = link['href']
                absolute_url = urllib.parse.urljoin(url, href)
                endpoint_info['links'].append(absolute_url)
            
            return endpoint_info
            
        except Exception as e:
            logging.error(f"Error extracting endpoint info from {url}: {e}")
            return None
    
    def _extract_form_info(self, base_url, form):
        """Extract information from form element"""
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
            
            # Extract form inputs
            inputs = []
            form_inputs = form.find_all(['input', 'textarea', 'select'])
            
            for input_elem in form_inputs:
                input_info = {
                    'name': input_elem.get('name', ''),
                    'type': input_elem.get('type', 'text'),
                    'value': input_elem.get('value', ''),
                    'required': input_elem.has_attr('required')
                }
                
                if input_info['name']:
                    inputs.append(input_info)
            
            return {
                'url': form_url,
                'method': method,
                'inputs': inputs,
                'has_file_upload': any(inp['type'] == 'file' for inp in inputs)
            }
            
        except Exception as e:
            logging.error(f"Error extracting form info: {e}")
            return None
    
    def _extract_urls(self, base_url, html_content):
        """Extract URLs from HTML content"""
        urls = set()
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract from links
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urllib.parse.urljoin(base_url, href)
                urls.add(absolute_url)
            
            # Extract from forms
            for form in soup.find_all('form', action=True):
                action = form['action']
                absolute_url = urllib.parse.urljoin(base_url, action)
                urls.add(absolute_url)
            
            # Extract from JavaScript (basic patterns)
            js_url_patterns = [
                r'["\']([^"\']*\.(?:php|asp|aspx|jsp|html|htm))["\']',
                r'url:\s*["\']([^"\']+)["\']',
                r'location\.href\s*=\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in js_url_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    absolute_url = urllib.parse.urljoin(base_url, match)
                    urls.add(absolute_url)
            
            # Filter URLs to same domain
            base_domain = urllib.parse.urlparse(base_url).netloc
            filtered_urls = []
            
            for url in urls:
                parsed_url = urllib.parse.urlparse(url)
                if parsed_url.netloc == base_domain:
                    # Remove fragment
                    clean_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        parsed_url.query,
                        ''
                ))
                    filtered_urls.append(clean_url)
            
            return filtered_urls
            
        except Exception as e:
            logging.error(f"Error extracting URLs from {base_url}: {e}")
            return []
    
    def discover_api_endpoints(self, base_url):
        """Discover API endpoints using common patterns"""
        api_endpoints = []
        
        # Common API paths
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
            '/admin/api', '/user/api', '/public/api',
            '/services', '/webservice', '/ws'
        ]
        
        # Common API endpoints
        common_endpoints = [
            'users', 'user', 'login', 'auth', 'token',
            'admin', 'config', 'settings', 'status',
            'health', 'info', 'version', 'docs'
        ]
        
        for api_path in api_paths:
            for endpoint in common_endpoints:
                test_url = urllib.parse.urljoin(base_url, f"{api_path}/{endpoint}")
                
                try:
                    response = self.session.get(test_url)
                    
                    if response.status_code in [200, 201, 401, 403]:
                        api_endpoints.append({
                            'url': test_url,
                            'method': 'GET',
                            'status_code': response.status_code,
                            'content_type': response.headers.get('Content-Type', ''),
                            'type': 'api'
                        })
                        
                        logging.debug(f"Found API endpoint: {test_url}")
                    
                    time.sleep(0.1)
                    
                except Exception as e:
                    logging.debug(f"Error testing API endpoint {test_url}: {e}")
                    continue
        
        return api_endpoints
    
    def discover_admin_panels(self, base_url):
        """Discover admin panels and sensitive directories"""
        admin_paths = [
            '/admin', '/administrator', '/admin.php', '/admin/',
            '/wp-admin', '/phpmyadmin', '/adminer',
            '/manager', '/management', '/control',
            '/dashboard', '/panel', '/console',
            '/backend', '/cms', '/system'
        ]
        
        admin_endpoints = []
        
        for path in admin_paths:
            test_url = urllib.parse.urljoin(base_url, path)
            
            try:
                response = self.session.get(test_url)
                
                # Check for admin panel indicators
                if (response.status_code in [200, 401, 403] or 
                    any(keyword in response.text.lower() for keyword in 
                        ['login', 'admin', 'dashboard', 'management', 'control panel'])):
                    
                    admin_endpoints.append({
                        'url': test_url,
                        'method': 'GET',
                        'status_code': response.status_code,
                        'content_type': response.headers.get('Content-Type', ''),
                        'type': 'admin'
                    })
                    
                    logging.debug(f"Found admin endpoint: {test_url}")
                
                time.sleep(0.1)
                
            except Exception as e:
                logging.debug(f"Error testing admin path {test_url}: {e}")
                continue
        
        return admin_endpoints
    
    def discover_backup_files(self, base_url):
        """Discover backup files and sensitive files"""
        backup_extensions = [
            '.bak', '.backup', '.old', '.orig', '.tmp',
            '.save', '.swp', '.swo', '~', '.copy'
        ]
        
        sensitive_files = [
            'config.php', 'database.php', 'settings.php',
            'wp-config.php', '.env', '.htaccess',
            'web.config', 'app.config', 'config.xml',
            'backup.sql', 'dump.sql', 'database.sql'
        ]
        
        backup_endpoints = []
        
        # Test backup versions of sensitive files
        for file in sensitive_files:
            for ext in backup_extensions:
                test_url = urllib.parse.urljoin(base_url, f"/{file}{ext}")
                
                try:
                    response = self.session.get(test_url)
                    
                    if response.status_code == 200:
                        backup_endpoints.append({
                            'url': test_url,
                            'method': 'GET',
                            'status_code': response.status_code,
                            'content_type': response.headers.get('Content-Type', ''),
                            'type': 'backup',
                            'file_size': len(response.content)
                        })
                        
                        logging.warning(f"Found backup file: {test_url}")
                    
                    time.sleep(0.1)
                    
                except Exception as e:
                    logging.debug(f"Error testing backup file {test_url}: {e}")
                    continue
        
        return backup_endpoints
    
    def get_crawl_statistics(self):
        """Get crawling statistics"""
        stats = {
            'total_urls_visited': len(self.visited_urls),
            'total_endpoints_discovered': len(self.discovered_endpoints),
            'endpoints_by_method': {},
            'forms_discovered': 0,
            'parameters_discovered': 0
        }
        
        # Count methods
        for endpoint in self.discovered_endpoints:
            method = endpoint.get('method', 'GET')
            stats['endpoints_by_method'][method] = stats['endpoints_by_method'].get(method, 0) + 1
            
            # Count forms and parameters
            stats['forms_discovered'] += len(endpoint.get('forms', []))
            stats['parameters_discovered'] += len(endpoint.get('parameters', []))
        
        return stats
    
    def export_endpoints(self, filename):
        """Export discovered endpoints to file"""
        try:
            import json
            
            export_data = {
                'crawl_info': {
                    'total_endpoints': len(self.discovered_endpoints),
                    'total_urls_visited': len(self.visited_urls),
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                },
                'endpoints': self.discovered_endpoints,
                'visited_urls': list(self.visited_urls)
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logging.info(f"Endpoints exported to {filename}")
            return True
            
        except Exception as e:
            logging.error(f"Error exporting endpoints: {e}")
            return False