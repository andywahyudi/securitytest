import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
import time
from collections import deque

class WebScanner:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.visited_urls = set()
        self.discovered_endpoints = []
        self.setup_session()
    
    def setup_session(self):
        """Setup session with cookies and headers"""
        self.session.headers.update({
            'User-Agent': 'Security-Tester/1.0 (Penetration Testing Tool)'
        })
        
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
    
    def discover_endpoints(self):
        """Discover all endpoints in the web application"""
        self.crawl_website()
        return self.discovered_endpoints
    
    def crawl_website(self):
        """Crawl website to discover forms and URLs"""
        queue = deque([(self.config.target_url, 0)])
        
        while queue:
            url, depth = queue.popleft()
            
            if depth > self.config.depth or url in self.visited_urls:
                continue
            
            self.visited_urls.add(url)
            
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    # Extract forms
                    self.extract_forms(url, response.text)
                    
                    # Extract URLs with parameters
                    self.extract_parameterized_urls(url, response.text)
                    
                    # Find new URLs to crawl
                    if depth < self.config.depth:
                        new_urls = self.extract_links(url, response.text)
                        for new_url in new_urls:
                            if new_url not in self.visited_urls:
                                queue.append((new_url, depth + 1))
            
            except requests.RequestException:
                continue
            
            # Rate limiting
            time.sleep(0.1)
    
    def extract_forms(self, url, html_content):
        """Extract forms from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            # Resolve relative URLs
            if action:
                form_url = urljoin(url, action)
            else:
                form_url = url
            
            # Extract form inputs
            inputs = []
            for input_elem in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    'name': input_elem.get('name'),
                    'type': input_elem.get('type', 'text'),
                    'value': input_elem.get('value', ''),
                    'required': input_elem.has_attr('required')
                }
                
                # Handle select options
                if input_elem.name == 'select':
                    options = [opt.get('value', opt.text) for opt in input_elem.find_all('option')]
                    input_info['options'] = options
                
                inputs.append(input_info)
            
            endpoint = {
                'type': 'form',
                'url': form_url,
                'method': method,
                'inputs': inputs,
                'source_url': url
            }
            
            self.discovered_endpoints.append(endpoint)
    
    def extract_parameterized_urls(self, url, html_content):
        """Extract URLs with parameters from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find all links with parameters
        links = soup.find_all('a', href=True)
        
        for link in links:
            href = link['href']
            full_url = urljoin(url, href)
            
            # Check if URL has parameters
            parsed_url = urlparse(full_url)
            if parsed_url.query:
                endpoint = {
                    'type': 'url',
                    'url': full_url,
                    'method': 'GET',
                    'parameters': parse_qs(parsed_url.query),
                    'source_url': url
                }
                
                self.discovered_endpoints.append(endpoint)
    
    def extract_links(self, base_url, html_content):
        """Extract all links from HTML content for crawling"""
        soup = BeautifulSoup(html_content, 'html.parser')
        links = set()
        
        # Extract from anchor tags
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            
            # Only include same-domain links
            if self.is_same_domain(full_url, self.config.target_url):
                links.add(full_url)
        
        # Extract from form actions
        for form in soup.find_all('form', action=True):
            action = form['action']
            full_url = urljoin(base_url, action)
            
            if self.is_same_domain(full_url, self.config.target_url):
                links.add(full_url)
        
        return list(links)
    
    def is_same_domain(self, url1, url2):
        """Check if two URLs belong to the same domain"""
        domain1 = urlparse(url1).netloc
        domain2 = urlparse(url2).netloc
        return domain1 == domain2
