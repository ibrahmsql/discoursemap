#!/usr/bin/env python3
"""
Discourse Security Scanner - Passive Scanning Module

Performs passive reconnaissance without aggressive probing
"""

import re
import time
import json
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from .utils import make_request

class PassiveScannerModule:
    """Passive scanning module for Discourse forums"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Passive Scanner',
            'target': scanner.target_url,
            'discourse_info': {},
            'server_info': {},
            'technology_stack': {},
            'exposed_endpoints': [],
            'meta_information': {},
            'security_headers': {},
            'robots_txt': {},
            'sitemap_info': {},
            'dns_info': {},
            'ssl_info': {},
            'scan_time': 0
        }
        self.start_time = time.time()
    
    def run(self):
        """Run passive scanner module"""
        self.scanner.log("Starting passive reconnaissance...")
        
        # Gather basic information
        self._gather_discourse_info()
        
        # Analyze server headers
        self._analyze_server_headers()
        
        # Check security headers
        self._check_security_headers()
        
        # Analyze robots.txt
        self._analyze_robots_txt()
        
        # Check sitemap
        self._check_sitemap()
        
        # Gather meta information
        self._gather_meta_info()
        
        # Detect technology stack
        self._detect_technology_stack()
        
        # Find exposed endpoints
        self._find_exposed_endpoints()
        
        # SSL/TLS analysis
        self._analyze_ssl_info()
        
        self.results['scan_time'] = time.time() - self.start_time
        return self.results
    
    def _gather_discourse_info(self):
        """Gather basic Discourse information passively"""
        self.scanner.log("Gathering Discourse information...", 'debug')
        
        # Check main page
        response = self.scanner.make_request(self.scanner.target_url)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract Discourse version from meta tags
            generator = soup.find('meta', {'name': 'generator'})
            if generator:
                content = generator.get('content', '')
                if 'discourse' in content.lower():
                    version_match = re.search(r'discourse\s+([\d\.]+)', content, re.IGNORECASE)
                    if version_match:
                        self.results['discourse_info']['version'] = version_match.group(1)
            
            # Extract site title
            title = soup.find('title')
            if title:
                self.results['discourse_info']['site_title'] = title.text.strip()
            
            # Extract description
            description = soup.find('meta', {'name': 'description'})
            if description:
                self.results['discourse_info']['description'] = description.get('content', '')
        
        # Check about.json endpoint
        about_url = urljoin(self.scanner.target_url, '/about.json')
        response = self.scanner.make_request(about_url)
        if response and response.status_code == 200:
            try:
                about_data = response.json()
                self.results['discourse_info']['about'] = about_data
                if 'version' in about_data:
                    self.results['discourse_info']['version'] = about_data['version']
            except:
                pass
    
    def _analyze_server_headers(self):
        """Analyze server response headers"""
        self.scanner.log("Analyzing server headers...", 'debug')
        
        response = self.scanner.make_request(self.scanner.target_url)
        if response:
            headers = dict(response.headers)
            
            # Extract server information
            server = headers.get('Server', '')
            if server:
                self.results['server_info']['server'] = server
            
            # Extract powered-by information
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                self.results['server_info']['powered_by'] = powered_by
            
            # Extract other interesting headers
            interesting_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Discourse-Route',
                'X-Discourse-Username',
                'X-Runtime'
            ]
            
            for header in interesting_headers:
                if header in headers:
                    self.results['server_info'][header.lower().replace('-', '_')] = headers[header]
    
    def _check_security_headers(self):
        """Check security-related headers"""
        self.scanner.log("Checking security headers...", 'debug')
        
        response = self.scanner.make_request(self.scanner.target_url)
        if response:
            headers = dict(response.headers)
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'X-XSS-Protection': 'XSS protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content injection protection',
                'Referrer-Policy': 'Referrer information control',
                'Permissions-Policy': 'Feature policy control'
            }
            
            for header, description in security_headers.items():
                if header in headers:
                    self.results['security_headers'][header] = {
                        'present': True,
                        'value': headers[header],
                        'description': description
                    }
                else:
                    self.results['security_headers'][header] = {
                        'present': False,
                        'description': description,
                        'risk': 'Missing security header'
                    }
    
    def _analyze_robots_txt(self):
        """Analyze robots.txt file"""
        self.scanner.log("Analyzing robots.txt...", 'debug')
        
        robots_url = urljoin(self.scanner.target_url, '/robots.txt')
        response = self.scanner.make_request(robots_url)
        
        if response and response.status_code == 200:
            robots_content = response.text
            self.results['robots_txt']['content'] = robots_content
            
            # Extract disallowed paths
            disallow_pattern = r'Disallow:\s*(.+)'
            disallowed = re.findall(disallow_pattern, robots_content, re.IGNORECASE)
            self.results['robots_txt']['disallowed_paths'] = disallowed
            
            # Extract allowed paths
            allow_pattern = r'Allow:\s*(.+)'
            allowed = re.findall(allow_pattern, robots_content, re.IGNORECASE)
            self.results['robots_txt']['allowed_paths'] = allowed
            
            # Extract sitemap references
            sitemap_pattern = r'Sitemap:\s*(.+)'
            sitemaps = re.findall(sitemap_pattern, robots_content, re.IGNORECASE)
            self.results['robots_txt']['sitemaps'] = sitemaps
        else:
            self.results['robots_txt']['status'] = 'Not found'
    
    def _check_sitemap(self):
        """Check sitemap files"""
        self.scanner.log("Checking sitemap...", 'debug')
        
        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemaps/sitemap.xml'
        ]
        
        for sitemap_path in sitemap_urls:
            sitemap_url = urljoin(self.scanner.target_url, sitemap_path)
            response = self.scanner.make_request(sitemap_url)
            
            if response and response.status_code == 200:
                self.results['sitemap_info'][sitemap_path] = {
                    'found': True,
                    'size': len(response.content),
                    'content_type': response.headers.get('content-type', 'unknown')
                }
                
                # Extract URLs from sitemap
                url_pattern = r'<loc>([^<]+)</loc>'
                urls = re.findall(url_pattern, response.text)
                self.results['sitemap_info'][sitemap_path]['urls'] = urls[:50]  # Limit to first 50
            else:
                self.results['sitemap_info'][sitemap_path] = {'found': False}
    
    def _gather_meta_info(self):
        """Gather meta information from HTML"""
        self.scanner.log("Gathering meta information...", 'debug')
        
        response = self.scanner.make_request(self.scanner.target_url)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all meta tags
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                name = meta.get('name') or meta.get('property') or meta.get('http-equiv')
                content = meta.get('content')
                if name and content:
                    self.results['meta_information'][name] = content
            
            # Extract JavaScript files
            scripts = soup.find_all('script', {'src': True})
            js_files = [script['src'] for script in scripts]
            self.results['meta_information']['javascript_files'] = js_files[:20]  # Limit to first 20
            
            # Extract CSS files
            links = soup.find_all('link', {'rel': 'stylesheet'})
            css_files = [link['href'] for link in links if link.get('href')]
            self.results['meta_information']['css_files'] = css_files[:20]  # Limit to first 20
    
    def _detect_technology_stack(self):
        """Detect technology stack passively"""
        self.scanner.log("Detecting technology stack...", 'debug')
        
        response = self.scanner.make_request(self.scanner.target_url)
        if response:
            headers = dict(response.headers)
            content = response.text
            
            # Detect web server
            server = headers.get('Server', '')
            if server:
                if 'nginx' in server.lower():
                    self.results['technology_stack']['web_server'] = 'Nginx'
                elif 'apache' in server.lower():
                    self.results['technology_stack']['web_server'] = 'Apache'
                elif 'cloudflare' in server.lower():
                    self.results['technology_stack']['cdn'] = 'Cloudflare'
            
            # Detect Ruby on Rails (Discourse is built on Rails)
            if 'X-Runtime' in headers or 'rails' in content.lower():
                self.results['technology_stack']['framework'] = 'Ruby on Rails'
            
            # Detect Redis (commonly used with Discourse)
            if 'redis' in content.lower():
                self.results['technology_stack']['cache'] = 'Redis'
            
            # Detect PostgreSQL (Discourse's database)
            if 'postgresql' in content.lower() or 'postgres' in content.lower():
                self.results['technology_stack']['database'] = 'PostgreSQL'
            
            # Detect JavaScript frameworks
            if 'ember' in content.lower():
                self.results['technology_stack']['frontend'] = 'Ember.js'
            if 'jquery' in content.lower():
                self.results['technology_stack']['javascript_library'] = 'jQuery'
    
    def _find_exposed_endpoints(self):
        """Find exposed endpoints passively"""
        self.scanner.log("Finding exposed endpoints...", 'debug')
        
        # Common Discourse endpoints to check passively
        endpoints = [
            '/about.json',
            '/site.json',
            '/categories.json',
            '/latest.json',
            '/top.json',
            '/users.json',
            '/groups.json',
            '/badges.json',
            '/tags.json',
            '/search.json',
            '/admin',
            '/admin/dashboard',
            '/admin/users',
            '/login',
            '/signup',
            '/privacy',
            '/tos',
            '/faq'
        ]
        
        for endpoint in endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = self.scanner.make_request(url)
            
            if response:
                self.results['exposed_endpoints'].append({
                    'endpoint': endpoint,
                    'url': url,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('content-type', 'unknown'),
                    'size': len(response.content)
                })
    
    def _analyze_ssl_info(self):
        """Analyze SSL/TLS information"""
        self.scanner.log("Analyzing SSL information...", 'debug')
        
        if self.scanner.target_url.startswith('https://'):
            try:
                import ssl
                import socket
                from urllib.parse import urlparse
                
                parsed_url = urlparse(self.scanner.target_url)
                hostname = parsed_url.hostname
                port = parsed_url.port or 443
                
                # Get SSL certificate info
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        self.results['ssl_info'] = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert['version'],
                            'serial_number': cert['serialNumber'],
                            'not_before': cert['notBefore'],
                            'not_after': cert['notAfter'],
                            'signature_algorithm': cert.get('signatureAlgorithm', 'unknown')
                        }
                        
                        # Check for SAN (Subject Alternative Names)
                        if 'subjectAltName' in cert:
                            self.results['ssl_info']['subject_alt_names'] = [name[1] for name in cert['subjectAltName']]
            
            except Exception as e:
                self.results['ssl_info']['error'] = str(e)
        else:
            self.results['ssl_info']['status'] = 'HTTP only - no SSL/TLS'