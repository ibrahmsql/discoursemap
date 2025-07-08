#!/usr/bin/env python3
"""
Discourse Security Scanner - Endpoint Discovery Module

Discovers hidden endpoints, API routes, and admin panels
"""

import re
import time
import json
import threading
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

class EndpointModule:
    """Endpoint discovery module for Discourse forums"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Endpoint Discovery',
            'target': scanner.target_url,
            'discovered_endpoints': [],
            'api_endpoints': [],
            'admin_endpoints': [],
            'backup_files': [],
            'config_files': [],
            'debug_endpoints': [],
            'tests_performed': 0,
            'scan_time': 0
        }
        self.start_time = time.time()
        self.found_endpoints = set()
        self.lock = threading.Lock()
    
    def run(self):
        """Run endpoint discovery module"""
        self.scanner.log("Starting endpoint discovery...")
        
        # Discover common Discourse endpoints
        self._discover_common_endpoints()
        
        # API endpoint discovery
        self._discover_api_endpoints()
        
        # Admin panel discovery
        self._discover_admin_endpoints()
        
        # Backup and config file discovery
        self._discover_backup_files()
        
        # Debug endpoint discovery
        self._discover_debug_endpoints()
        
        # Robots.txt and sitemap analysis
        self._analyze_robots_sitemap()
        
        # JavaScript analysis for endpoints
        self._analyze_javascript_endpoints()
        
        self.results['scan_time'] = time.time() - self.start_time
        return self.results
    
    def _discover_common_endpoints(self):
        """Discover common Discourse endpoints"""
        self.scanner.log("Discovering common endpoints...", 'debug')
        
        # Common Discourse endpoints
        common_endpoints = [
            # Main pages
            '/', '/latest', '/top', '/categories', '/unread', '/new',
            '/hot', '/random', '/search', '/tags', '/badges',
            
            # User-related
            '/users', '/u', '/my', '/preferences', '/notifications',
            '/messages', '/drafts', '/bookmarks',
            
            # Topic and post related
            '/t', '/posts', '/new-topic', '/new-message',
            
            # Authentication
            '/session', '/login', '/signup', '/logout', '/auth',
            '/password-reset', '/activate-account',
            
            # API endpoints
            '/site.json', '/about.json', '/categories.json',
            '/latest.json', '/top.json', '/directory_items.json',
            
            # Admin areas
            '/admin', '/admin/dashboard', '/admin/users', '/admin/groups',
            '/admin/site_settings', '/admin/customize', '/admin/plugins',
            '/admin/backups', '/admin/logs', '/admin/reports',
            
            # Plugin endpoints
            '/chat', '/calendar', '/events', '/polls',
            
            # Static files
            '/uploads', '/assets', '/images', '/stylesheets',
            '/javascripts', '/fonts',
            
            # Special pages
            '/faq', '/tos', '/privacy', '/guidelines', '/about',
            '/contact', '/404', '/500'
        ]
        
        # Test endpoints with threading
        with ThreadPoolExecutor(max_workers=self.scanner.threads) as executor:
            futures = []
            
            for endpoint in common_endpoints:
                future = executor.submit(self._test_endpoint, endpoint, 'common')
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.scanner.log(f"Error testing endpoint: {e}", 'debug')
    
    def _discover_api_endpoints(self):
        """Discover API endpoints"""
        self.scanner.log("Discovering API endpoints...", 'debug')
        
        # API endpoint patterns
        api_endpoints = [
            # Core API
            '/site.json', '/about.json', '/categories.json',
            '/latest.json', '/top.json', '/hot.json', '/new.json',
            
            # User API
            '/users.json', '/directory_items.json',
            '/u/{username}.json', '/u/{username}/summary.json',
            '/u/{username}/activity.json',
            
            # Topic API
            '/t/{id}.json', '/t/{slug}/{id}.json',
            '/t/{id}/posts.json', '/t/{id}/similar.json',
            
            # Search API
            '/search.json', '/search/query.json',
            
            # Category API
            '/c/{category}.json', '/c/{category}/l/latest.json',
            
            # Admin API
            '/admin/dashboard.json', '/admin/users.json',
            '/admin/groups.json', '/admin/site_settings.json',
            '/admin/reports.json', '/admin/logs.json',
            
            # Plugin APIs
            '/chat/api', '/calendar/api', '/polls/api',
            
            # Upload API
            '/uploads.json', '/uploads/lookup.json',
            
            # Notification API
            '/notifications.json', '/notifications/mark-read.json'
        ]
        
        with ThreadPoolExecutor(max_workers=self.scanner.threads) as executor:
            futures = []
            
            for endpoint in api_endpoints:
                future = executor.submit(self._test_endpoint, endpoint, 'api')
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.scanner.log(f"Error testing API endpoint: {e}", 'debug')
    
    def _discover_admin_endpoints(self):
        """Discover admin panel endpoints"""
        self.scanner.log("Discovering admin endpoints...", 'debug')
        
        admin_endpoints = [
            # Main admin areas
            '/admin', '/admin/dashboard', '/admin/users', '/admin/groups',
            '/admin/site_settings', '/admin/customize', '/admin/plugins',
            '/admin/backups', '/admin/logs', '/admin/reports',
            '/admin/flags', '/admin/email', '/admin/api',
            
            # User management
            '/admin/users/list', '/admin/users/new', '/admin/users/active',
            '/admin/users/staff', '/admin/users/suspended',
            
            # Content management
            '/admin/customize/themes', '/admin/customize/colors',
            '/admin/customize/css_html', '/admin/customize/email_templates',
            
            # System settings
            '/admin/site_settings/category/all_results',
            '/admin/site_settings/category/basic',
            '/admin/site_settings/category/login',
            '/admin/site_settings/category/users',
            
            # Logs and monitoring
            '/admin/logs/staff_action_logs', '/admin/logs/screened_emails',
            '/admin/logs/screened_ip_addresses', '/admin/logs/screened_urls',
            
            # API and webhooks
            '/admin/api/keys', '/admin/api/web_hooks',
            
            # Backup and maintenance
            '/admin/backups/logs', '/admin/backups/settings',
            '/admin/upgrade', '/admin/docker'
        ]
        
        with ThreadPoolExecutor(max_workers=self.scanner.threads) as executor:
            futures = []
            
            for endpoint in admin_endpoints:
                future = executor.submit(self._test_endpoint, endpoint, 'admin')
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.scanner.log(f"Error testing admin endpoint: {e}", 'debug')
    
    def _discover_backup_files(self):
        """Discover backup and configuration files"""
        self.scanner.log("Discovering backup and config files...", 'debug')
        
        backup_files = [
            # Backup files
            '/backup', '/backups', '/backup.tar.gz', '/backup.zip',
            '/site-backup.tar.gz', '/discourse-backup.tar.gz',
            '/dump.sql', '/database.sql', '/db.sql',
            
            # Configuration files
            '/.env', '/.env.local', '/.env.production',
            '/config/database.yml', '/config/secrets.yml',
            '/config/application.yml', '/config/discourse.conf',
            '/app.yml', '/containers/app.yml',
            
            # Docker files
            '/docker-compose.yml', '/Dockerfile',
            
            # Git files
            '/.git', '/.git/config', '/.git/HEAD',
            '/.gitignore', '/.gitmodules',
            
            # SVN files
            '/.svn', '/.svn/entries',
            
            # Log files
            '/log', '/logs', '/var/log',
            '/production.log', '/development.log',
            '/unicorn.stderr.log', '/unicorn.stdout.log',
            
            # Temporary files
            '/tmp', '/temp', '/cache',
            
            # Ruby/Rails specific
            '/Gemfile', '/Gemfile.lock', '/config.ru',
            '/config/routes.rb', '/config/environment.rb'
        ]
        
        with ThreadPoolExecutor(max_workers=self.scanner.threads) as executor:
            futures = []
            
            for file_path in backup_files:
                future = executor.submit(self._test_endpoint, file_path, 'backup')
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.scanner.log(f"Error testing backup file: {e}", 'debug')
    
    def _discover_debug_endpoints(self):
        """Discover debug and development endpoints"""
        self.scanner.log("Discovering debug endpoints...", 'debug')
        
        debug_endpoints = [
            # Debug pages
            '/debug', '/debug/info', '/debug/routes',
            '/rails/info', '/rails/info/routes',
            '/rails/info/properties',
            
            # Development tools
            '/dev', '/development', '/test',
            
            # Server status
            '/status', '/health', '/ping', '/version',
            '/server-status', '/server-info',
            
            # Monitoring
            '/metrics', '/stats', '/statistics',
            '/monitoring', '/performance',
            
            # Error pages
            '/500', '/404', '/403', '/error',
            
            # PHP info (if mixed environment)
            '/phpinfo.php', '/info.php',
            
            # Database admin tools
            '/phpmyadmin', '/adminer', '/phppgadmin',
            
            # Redis/Memcached
            '/redis', '/memcached'
        ]
        
        with ThreadPoolExecutor(max_workers=self.scanner.threads) as executor:
            futures = []
            
            for endpoint in debug_endpoints:
                future = executor.submit(self._test_endpoint, endpoint, 'debug')
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.scanner.log(f"Error testing debug endpoint: {e}", 'debug')
    
    def _test_endpoint(self, endpoint, category):
        """Test a single endpoint"""
        url = urljoin(self.scanner.target_url, endpoint)
        
        # Skip if already tested
        with self.lock:
            if url in self.found_endpoints:
                return
            self.found_endpoints.add(url)
        
        response = self.scanner.make_request(url)
        
        if response:
            endpoint_info = {
                'url': url,
                'endpoint': endpoint,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': response.headers.get('Content-Type', ''),
                'category': category,
                'response_time': response.elapsed.total_seconds()
            }
            
            # Analyze response
            if response.status_code == 200:
                endpoint_info['accessible'] = True
                endpoint_info['title'] = self._extract_title(response.text)
                endpoint_info['interesting_headers'] = self._extract_interesting_headers(response.headers)
                
                # Check for sensitive information
                if self._contains_sensitive_info(response.text):
                    endpoint_info['contains_sensitive_info'] = True
                
                self.scanner.log(f"Found accessible endpoint: {endpoint}", 'success')
                
            elif response.status_code == 403:
                endpoint_info['accessible'] = False
                endpoint_info['note'] = 'Forbidden - endpoint exists but access denied'
                self.scanner.log(f"Found protected endpoint: {endpoint}", 'info')
                
            elif response.status_code == 401:
                endpoint_info['accessible'] = False
                endpoint_info['note'] = 'Unauthorized - authentication required'
                self.scanner.log(f"Found auth-protected endpoint: {endpoint}", 'info')
                
            elif response.status_code in [301, 302, 307, 308]:
                endpoint_info['accessible'] = True
                endpoint_info['redirect_location'] = response.headers.get('Location', '')
                endpoint_info['note'] = f'Redirects to {endpoint_info["redirect_location"]}'
                
            # Categorize the endpoint
            if category == 'api':
                self.results['api_endpoints'].append(endpoint_info)
            elif category == 'admin':
                self.results['admin_endpoints'].append(endpoint_info)
            elif category == 'backup':
                self.results['backup_files'].append(endpoint_info)
            elif category == 'debug':
                self.results['debug_endpoints'].append(endpoint_info)
            else:
                self.results['discovered_endpoints'].append(endpoint_info)
        
        with self.lock:
            self.results['tests_performed'] += 1
    
    def _extract_title(self, html_content):
        """Extract page title from HTML"""
        try:
            # Check if content is XML and use appropriate parser
            if html_content.strip().startswith('<?xml') or '<urlset' in html_content or '<sitemapindex' in html_content:
                # Suppress XML parsing warning for XML content
                import warnings
                from bs4 import XMLParsedAsHTMLWarning
                warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
                
            soup = BeautifulSoup(html_content, 'html.parser')
            title = soup.find('title')
            return title.get_text().strip() if title else ''
        except:
            return ''
    
    def _extract_interesting_headers(self, headers):
        """Extract interesting HTTP headers"""
        interesting = {}
        interesting_header_names = [
            'Server', 'X-Powered-By', 'X-Frame-Options',
            'X-Content-Type-Options', 'X-XSS-Protection',
            'Strict-Transport-Security', 'Content-Security-Policy',
            'X-Discourse-Route', 'X-Discourse-Username'
        ]
        
        for header_name in interesting_header_names:
            if header_name in headers:
                interesting[header_name] = headers[header_name]
        
        return interesting
    
    def _contains_sensitive_info(self, content):
        """Check if content contains sensitive information"""
        sensitive_patterns = [
            r'password["\']?\s*[:=]\s*["\'][^"\'\']+["\']',
            r'api_key["\']?\s*[:=]\s*["\'][^"\'\']+["\']',
            r'secret["\']?\s*[:=]\s*["\'][^"\'\']+["\']',
            r'token["\']?\s*[:=]\s*["\'][^"\'\']+["\']',
            r'database["\']?\s*[:=]\s*["\'][^"\'\']+["\']',
            r'mysql://[^\s]+',
            r'postgresql://[^\s]+',
            r'redis://[^\s]+'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _analyze_robots_sitemap(self):
        """Analyze robots.txt and sitemap for additional endpoints"""
        self.scanner.log("Analyzing robots.txt and sitemap...", 'debug')
        
        # Check robots.txt
        robots_url = urljoin(self.scanner.target_url, '/robots.txt')
        response = self.scanner.make_request(robots_url)
        
        if response and response.status_code == 200:
            # Extract disallowed paths
            disallow_pattern = r'Disallow:\s*([^\s]+)'
            disallowed_paths = re.findall(disallow_pattern, response.text)
            
            for path in disallowed_paths:
                if path not in ['/', '*'] and len(path) > 1:
                    self._test_endpoint(path, 'robots_disallow')
        
        # Check sitemap.xml
        sitemap_url = urljoin(self.scanner.target_url, '/sitemap.xml')
        response = self.scanner.make_request(sitemap_url)
        
        if response and response.status_code == 200:
            # Extract URLs from sitemap
            url_pattern = r'<loc>([^<]+)</loc>'
            urls = re.findall(url_pattern, response.text)
            
            for url in urls[:20]:  # Limit to first 20 URLs
                parsed_url = urlparse(url)
                if parsed_url.path and parsed_url.path != '/':
                    self._test_endpoint(parsed_url.path, 'sitemap')
    
    def _analyze_javascript_endpoints(self):
        """Analyze JavaScript files for endpoint references"""
        self.scanner.log("Analyzing JavaScript for endpoints...", 'debug')
        
        # Get main page to find JavaScript files
        response = self.scanner.make_request(self.scanner.target_url)
        if not response:
            return
        
        soup = BeautifulSoup(response.text, 'html.parser')
        script_tags = soup.find_all('script', src=True)
        
        for script in script_tags[:5]:  # Limit to first 5 scripts
            script_url = urljoin(self.scanner.target_url, script['src'])
            js_response = self.scanner.make_request(script_url)
            
            if js_response and js_response.status_code == 200:
                # Look for API endpoints in JavaScript
                endpoint_patterns = [
                    r'["\'](/[a-zA-Z0-9/_-]+\.json)["\']',
                    r'["\'](/api/[a-zA-Z0-9/_-]+)["\']',
                    r'["\'](/admin/[a-zA-Z0-9/_-]+)["\']',
                    r'url:\s*["\']([^"\'\']+)["\']',
                    r'endpoint:\s*["\']([^"\'\']+)["\']'
                ]
                
                for pattern in endpoint_patterns:
                    endpoints = re.findall(pattern, js_response.text)
                    for endpoint in endpoints[:10]:  # Limit endpoints per script
                        if endpoint.startswith('/') and len(endpoint) > 1:
                            self._test_endpoint(endpoint, 'javascript')