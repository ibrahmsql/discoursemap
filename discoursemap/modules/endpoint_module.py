#!/usr/bin/env python3
"""
Discourse Endpoint Discovery Module

Specialized endpoint discovery module for Discourse forums.
Discovers and tests Discourse-specific endpoints including APIs, admin panels,
backup files, configuration files, and platform-specific vulnerabilities.

Author: ibrahimsql
Version: 2.0
"""

import requests
import re
import time
import threading
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style

class EndpointModule:
    """Module for discovering and testing various endpoints"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.discovered_endpoints = set()
        self.results = {
            'module_name': 'Discourse Endpoint Discovery',
            'discourse_api_endpoints': [],
            'discourse_admin_endpoints': [],
            'discourse_backup_endpoints': [],
            'discourse_config_endpoints': [],
            'discourse_debug_endpoints': [],
            'discourse_plugin_endpoints': [],
            'discourse_theme_endpoints': [],
            'discourse_robots_endpoints': [],
            'discourse_sitemap_endpoints': [],
            'javascript_endpoints': [],
            'total_endpoints': 0,
            'scan_time': 0
        }
        self.lock = threading.Lock()
    
    def run(self):
        """Run Discourse-specific endpoint discovery"""
        print(f"\n{Fore.CYAN}[*] Starting Discourse endpoint discovery...{Style.RESET_ALL}")
        start_time = time.time()
        
        # Run Discourse-specific discovery methods
        discovery_methods = [
            self._discover_discourse_api_endpoints,
            self._discover_discourse_admin_endpoints,
            self._discover_discourse_backup_files,
            self._discover_discourse_config_files,
            self._discover_discourse_debug_endpoints,
            self._discover_discourse_plugin_endpoints,
            self._discover_discourse_theme_endpoints,
            self._analyze_discourse_robots_sitemap,
            self._analyze_javascript_endpoints
        ]
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(method) for method in discovery_methods]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[!] Error in endpoint discovery: {e}")
        
        # Calculate total endpoints found
        endpoint_categories = [
            'discourse_api_endpoints', 'discourse_admin_endpoints', 'discourse_backup_endpoints',
            'discourse_config_endpoints', 'discourse_debug_endpoints', 'discourse_plugin_endpoints', 
            'discourse_theme_endpoints', 'discourse_robots_endpoints', 'discourse_sitemap_endpoints',
            'javascript_endpoints'
        ]
        
        total = sum(len(self.results.get(category, [])) for category in endpoint_categories)
        self.results['total_endpoints'] = total
        self.results['scan_time'] = time.time() - start_time
        
        print(f"\n[+] Discourse endpoint discovery completed in {self.results['scan_time']:.2f} seconds")
        print(f"[+] Total endpoints discovered: {total}")
        
        # Print summary by category
        for category in endpoint_categories:
            count = len(self.results.get(category, []))
            if count > 0:
                category_name = category.replace('_endpoints', '').replace('_', ' ').title()
                print(f"[+] {category_name}: {count} endpoints")
        
        return self.results
    
    def _discover_discourse_api_endpoints(self):
        """Discover Discourse API endpoints"""
        # Core Discourse API endpoints based on official documentation
        discourse_api_endpoints = [
            # Public API endpoints
            '/latest.json',
            '/categories.json', 
            '/c/{category_id}.json',
            '/c/{category_slug}.json',
            '/t/{topic_id}.json',
            '/posts.json',
            '/users.json',
            '/u/{username}.json',
            '/search.json',
            '/search/query.json',
            '/tags.json',
            '/tag/{tag_name}.json',
            '/groups.json',
            '/g/{group_name}.json',
            '/site.json',
            '/site/statistics.json',
            '/about.json',
            '/badges.json',
            '/user_badges/{username}.json',
            
            # Session and authentication
            '/session/current.json',
            '/session/csrf.json',
            '/login.json',
            '/logout',
            '/auth/{provider}/callback',
            
            # User API endpoints
            '/user-api-key/new',
            '/user-api-key/otp',
            '/user-api-key/revoke',
            
            # Notification endpoints
            '/notifications.json',
            '/notifications/mark-read.json',
            
            # Upload endpoints
            '/uploads.json',
            '/uploads/lookup-metadata.json',
            '/uploads/generate-presigned-put.json'
        ]
        
        for endpoint in discourse_api_endpoints:
            if endpoint not in self.discovered_endpoints:
                self._test_endpoint(endpoint, 'discourse_api')
    
    def _discover_discourse_admin_endpoints(self):
        """Discover Discourse admin endpoints"""
        # Discourse admin panel endpoints based on platform structure
        discourse_admin_endpoints = [
            # Main admin routes
            '/admin',
            '/admin/',
            '/admin/dashboard',
            '/admin/dashboard.json',
            
            # User management
            '/admin/users',
            '/admin/users.json',
            '/admin/users/list/active.json',
            '/admin/users/list/new.json',
            '/admin/users/list/staff.json',
            '/admin/users/list/suspended.json',
            '/admin/users/list/silenced.json',
            '/admin/users/{id}.json',
            '/admin/users/{id}/suspend.json',
            '/admin/users/{id}/silence.json',
            '/admin/users/{id}/log.json',
            
            # Site settings
            '/admin/site_settings',
            '/admin/site_settings.json',
            '/admin/site_settings/{setting_name}.json',
            
            # Email settings
            '/admin/email',
            '/admin/email.json',
            '/admin/email/test.json',
            '/admin/email/logs.json',
            '/admin/email/bounced.json',
            '/admin/email/rejected.json',
            
            # Logs and monitoring
            '/admin/logs',
            '/admin/logs.json',
            '/admin/logs/staff_action_logs.json',
            '/admin/logs/screened_emails.json',
            '/admin/logs/screened_ip_addresses.json',
            '/admin/logs/screened_urls.json',
            
            # Backups
            '/admin/backups',
            '/admin/backups.json',
            '/admin/backups/logs.json',
            '/admin/backups/status.json',
            '/admin/backups/cancel.json',
            '/admin/backups/rollback.json',
            
            # Plugins and themes
            '/admin/plugins',
            '/admin/plugins.json',
            '/admin/themes',
            '/admin/themes.json',
            '/admin/customize',
            '/admin/customize/themes',
            '/admin/customize/themes.json',
            
            # API keys
            '/admin/api',
            '/admin/api.json',
            '/admin/api/keys.json',
            '/admin/api/web_hooks.json',
            
            # Reports and analytics
            '/admin/reports',
            '/admin/reports.json',
            '/admin/reports/{report_type}.json',
            '/admin/dashboard/general.json',
            '/admin/dashboard/moderation.json',
            '/admin/dashboard/security.json',
            '/admin/dashboard/reports.json'
        ]
        
        for endpoint in discourse_admin_endpoints:
            if endpoint not in self.discovered_endpoints:
                self._test_endpoint(endpoint, 'discourse_admin')
    
    def _discover_discourse_backup_files(self):
        """Discover Discourse backup files and sensitive data"""
        from .suspicious_file_scanner import SuspiciousFileScanner
        suspicious_scanner = SuspiciousFileScanner(self.scanner)
        discourse_backup_files = suspicious_scanner.discover_discourse_backup_files()
        
        for endpoint in discourse_backup_files:
            if endpoint not in self.discovered_endpoints:
                self._test_endpoint(endpoint, 'discourse_backup')
    
    def _discover_discourse_config_files(self):
        """Discover Discourse configuration files"""
        from .suspicious_file_scanner import SuspiciousFileScanner
        suspicious_scanner = SuspiciousFileScanner(self.scanner)
        discourse_config_files = suspicious_scanner.discover_discourse_config_files()
        
        for endpoint in discourse_config_files:
            if endpoint not in self.discovered_endpoints:
                self._test_endpoint(endpoint, 'discourse_config')
    
    def _discover_discourse_debug_endpoints(self):
        """Discover Discourse debug and development endpoints"""
        # Discourse-specific debug and development endpoints
        discourse_debug_endpoints = [
            # Discourse debug information
            '/srv/status',
            '/admin/logs',
            '/admin/logs/staff_action_logs',
            '/admin/logs/screened_emails',
            '/admin/logs/screened_ip_addresses',
            '/admin/logs/screened_urls',
            '/admin/reports',
            '/admin/reports/consolidated_page_views',
            '/admin/reports/page_view_total_reqs',
            '/admin/reports/http_total_reqs',
            '/admin/reports/http_2xx_reqs',
            '/admin/reports/http_background_reqs',
            '/admin/reports/http_3xx_reqs',
            '/admin/reports/http_4xx_reqs',
            '/admin/reports/http_5xx_reqs',
            
            # Rails development endpoints
            '/rails/info',
            '/rails/info/properties',
            '/rails/info/routes',
            '/rails/mailers',
            '/rails/conductor/action_mailbox/inbound_emails',
            
            # Discourse health checks
            '/srv/status',
            '/health',
            '/readiness',
            '/liveness',
            
            # Discourse version and build info
            '/admin/upgrade',
            '/admin/docker',
            '/admin/version_check',
            
            # Discourse error handling
            '/exception-log',
            '/logs/exception',
            '/admin/logs/staff_action_logs.json',
            
            # Discourse monitoring
            '/admin/dashboard',
            '/admin/dashboard/general',
            '/admin/dashboard/moderation',
            '/admin/dashboard/security',
            '/admin/dashboard/reports',
            
            # Discourse API documentation
            '/api-docs',
            '/api/docs',
            '/docs/api',
            '/swagger-ui',
            '/openapi.json',
            
            # Discourse development tools
            '/qunit',
            '/tests',
            '/styleguide',
            '/wizard',
            '/finish-installation',
            
            # Discourse sidekiq (background jobs)
            '/sidekiq',
            '/sidekiq/stats',
            '/sidekiq/queues',
            '/sidekiq/cron',
            '/admin/sidekiq',
            
            # Discourse email preview
            '/rails/mailers',
            '/admin/email',
            '/admin/email/preview-digest',
            '/admin/email/sent',
            '/admin/email/skipped',
            '/admin/email/bounced',
            '/admin/email/received'
        ]
        
        for endpoint in discourse_debug_endpoints:
            if endpoint not in self.discovered_endpoints:
                self._test_endpoint(endpoint, 'discourse_debug')
    
    def _test_endpoint(self, endpoint, category):
        """Test a single endpoint"""
        try:
            url = urljoin(self.scanner.target_url, endpoint)
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            with self.lock:
                self.discovered_endpoints.add(endpoint)
            
            result = {
                'endpoint': endpoint,
                'url': url,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds(),
                'headers': dict(response.headers),
                'title': self._extract_title(response.text) if response.text else None,
                'interesting_headers': self._extract_interesting_headers(response.headers),
                'contains_sensitive': self._contains_sensitive_info(response.text) if response.text else False
            }
            
            # Enhanced filtering to reduce false positives
            is_valid_discourse_endpoint = self._is_valid_discourse_endpoint(response, endpoint, category)
            
            if is_valid_discourse_endpoint:
                with self.lock:
                    # Map category to correct key in results
                    category_mapping = {
                        'discourse_api': 'discourse_api_endpoints',
                        'discourse_admin': 'discourse_admin_endpoints', 
                        'discourse_backup': 'discourse_backup_endpoints',
                        'discourse_config': 'discourse_config_endpoints',
                        'discourse_debug': 'discourse_debug_endpoints',
                        'discourse_plugin': 'discourse_plugin_endpoints',
                        'discourse_theme': 'discourse_theme_endpoints',
                        'discourse_robots': 'discourse_robots_endpoints',
                        'discourse_sitemap': 'discourse_sitemap_endpoints',
                        'javascript': 'javascript_endpoints'
                    }
                    
                    category_key = category_mapping.get(category, f"{category}_endpoints")
                    if category_key in self.results:
                        self.results[category_key].append(result)
                    
                    # Color code based on status
                    if response.status_code == 200:
                        color = Fore.GREEN
                    elif response.status_code in [401, 403]:
                        color = Fore.RED
                    else:
                        color = Fore.YELLOW
                    
                    print(f"{color}[+] Found {category} endpoint: {endpoint} [{response.status_code}]{Style.RESET_ALL}")
        
        except requests.exceptions.RequestException:
            pass  # Silently ignore connection errors
        except Exception as e:
            print(f"[!] Error testing endpoint {endpoint}: {e}")
    
    def _is_valid_discourse_endpoint(self, response, endpoint, category):
        """Enhanced validation to reduce false positives for Discourse endpoints"""
        status_code = response.status_code
        content = response.text.lower() if response.text else ""
        headers = response.headers
        
        # Immediate rejections for obvious false positives
        if status_code == 404:
            return False
        
        # Check for generic error pages that aren't Discourse-specific
        generic_error_indicators = [
            'apache default page',
            'nginx default page', 
            'iis default page',
            'page not found',
            'file not found',
            'directory listing',
            'index of /',
            'forbidden - you don\'t have permission'
        ]
        
        for indicator in generic_error_indicators:
            if indicator in content:
                return False
        
        # Positive indicators for Discourse
        discourse_indicators = [
            'discourse',
            'ember.js',
            'data-discourse',
            'discourse-application',
            'discourse/app',
            'discourse_development',
            'discourse_production',
            'rails',
            'csrf-token',
            'x-discourse',
            'discourse-cdn'
        ]
        
        # Check headers for Discourse indicators
        header_indicators = [
            'x-discourse-route',
            'x-discourse-username', 
            'x-discourse-present',
            'x-frame-options',
            'x-request-id'
        ]
        
        # Strong positive signals
        if status_code == 200:
            # Check content for Discourse indicators
            discourse_score = sum(1 for indicator in discourse_indicators if indicator in content)
            header_score = sum(1 for indicator in header_indicators if indicator in headers)
            
            # Require at least some Discourse indicators for 200 responses
            if discourse_score >= 1 or header_score >= 1:
                return True
            
            # Special handling for JSON endpoints
            if endpoint.endswith('.json'):
                try:
                    json_data = response.json()
                    # Check for Discourse-specific JSON structure
                    discourse_json_keys = ['users', 'topics', 'posts', 'categories', 'badges', 'site_settings']
                    if any(key in json_data for key in discourse_json_keys):
                        return True
                except:
                    pass
            
            # For admin endpoints, be more strict
            if 'admin' in endpoint:
                return discourse_score >= 2 or header_score >= 1
            
            # For API endpoints, check for JSON content type
            if 'api' in endpoint or endpoint.endswith('.json'):
                content_type = headers.get('content-type', '')
                if 'application/json' in content_type:
                    return True
        
        # Authentication required responses are valuable
        elif status_code in [401, 403]:
            # Check if it's a Discourse authentication page
            auth_indicators = ['login', 'sign in', 'authentication', 'csrf', 'session']
            if any(indicator in content for indicator in auth_indicators):
                return True
            
            # Check for Discourse-specific auth headers
            if any(indicator in headers for indicator in header_indicators):
                return True
        
        # Redirects can be valuable if they're Discourse-related
        elif status_code in [301, 302, 307, 308]:
            location = headers.get('location', '')
            if location and ('login' in location or 'admin' in location or 'discourse' in location):
                return True
        
        # Check for sensitive information regardless of status code
        if self._contains_sensitive_info(response.text):
            return True
        
        # Check for interesting headers
        if self._extract_interesting_headers(headers):
            return True
        
        return False
    
    def _extract_title(self, html_content):
        """Extract title from HTML content"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                return title_tag.get_text().strip()[:100]
        except Exception:
            pass
        return None
    
    def _extract_interesting_headers(self, headers):
        """Extract interesting headers"""
        interesting = {}
        interesting_header_names = [
            'server', 'x-powered-by', 'x-generator', 'x-cms',
            'x-framework', 'x-version', 'x-debug', 'x-trace-id'
        ]
        
        for header_name in interesting_header_names:
            if header_name in headers:
                interesting[header_name] = headers[header_name]
        
        return interesting
    
    def _contains_sensitive_info(self, content):
        """Check if content contains Discourse-specific sensitive information"""
        if not content:
            return False
        
        # Discourse-specific sensitive patterns
        discourse_sensitive_patterns = [
            # Discourse configuration
            r'discourse[_-]?api[_-]?key\s*[=:]\s*["\']?[^\s"\';\n]+',
            r'discourse[_-]?secret[_-]?key\s*[=:]\s*["\']?[^\s"\';\n]+',
            r'rails[_-]?secret[_-]?key[_-]?base\s*[=:]\s*["\']?[^\s"\';\n]+',
            r'secret[_-]?key[_-]?base\s*[=:]\s*["\']?[^\s"\';\n]+',
            
            # Database credentials
            r'database[_-]?url\s*[=:]\s*["\']?postgres://[^\s"\';\n]+',
            r'redis[_-]?url\s*[=:]\s*["\']?redis://[^\s"\';\n]+',
            r'db[_-]?password\s*[=:]\s*["\']?[^\s"\';\n]+',
            
            # Email configuration
            r'smtp[_-]?password\s*[=:]\s*["\']?[^\s"\';\n]+',
            r'mail[_-]?password\s*[=:]\s*["\']?[^\s"\';\n]+',
            r'email[_-]?password\s*[=:]\s*["\']?[^\s"\';\n]+',
            
            # OAuth and SSO
            r'oauth[_-]?client[_-]?secret\s*[=:]\s*["\']?[^\s"\';\n]+',
            r'sso[_-]?secret\s*[=:]\s*["\']?[^\s"\';\n]+',
            r'github[_-]?client[_-]?secret\s*[=:]\s*["\']?[^\s"\';\n]+',
            r'google[_-]?client[_-]?secret\s*[=:]\s*["\']?[^\s"\';\n]+',
            
            # AWS and cloud services
            r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?[^\s"\';\n]+',
            r's3[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?[^\s"\';\n]+',
            
            # Discourse-specific tokens
            r'discourse[_-]?webhook[_-]?secret\s*[=:]\s*["\']?[^\s"\';\n]+',
            r'api[_-]?username\s*[=:]\s*["\']?[^\s"\';\n]+',
            
            # General sensitive patterns
            r'private[_-]?key\s*[=:]\s*["\']?[^\s"\';\n]+',
            r'csrf[_-]?token\s*[=:]\s*["\']?[^\s"\';\n]+'
        ]
        
        for pattern in discourse_sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        # Check for Discourse-specific error messages that might leak info
        discourse_error_patterns = [
            r'ActiveRecord::[A-Za-z]+Error',
            r'PG::[A-Za-z]+Error', 
            r'Redis::[A-Za-z]+Error',
            r'Discourse::[A-Za-z]+Error',
            r'Rails\.application\.secrets',
            r'config/database\.yml',
            r'/var/discourse/'
        ]
        
        for pattern in discourse_error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _analyze_robots_sitemap(self):
        """Analyze robots.txt and sitemap.xml for additional endpoints"""
        try:
            # Check robots.txt
            robots_url = urljoin(self.scanner.target_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=10)
            
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line.strip().startswith(('Disallow:', 'Allow:')):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/' and not path.startswith('*'):
                            self._test_endpoint(path, 'robots')
            
            # Check sitemap.xml
            sitemap_url = urljoin(self.scanner.target_url, '/sitemap.xml')
            response = self.session.get(sitemap_url, timeout=10)
            
            if response.status_code == 200:
                # Extract URLs from sitemap
                urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                for url in urls[:20]:  # Limit to first 20 URLs
                    parsed = urlparse(url)
                    if parsed.path and parsed.path != '/':
                        self._test_endpoint(parsed.path, 'sitemap')
        
        except Exception as e:
            print(f"[!] Error analyzing robots/sitemap: {e}")
    
    def _test_backup_endpoint(self, endpoint):
        """Test backup endpoint with additional checks"""
        try:
            url = urljoin(self.scanner.target_url, endpoint)
            response = self.session.get(url, timeout=10)
            
            with self.lock:
                self.discovered_endpoints.add(endpoint)
            
            if response.status_code == 200:
                filename = endpoint.split('/')[-1]
                
                result = {
                    'endpoint': endpoint,
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'is_backup': self._is_backup_file(response, filename),
                    'is_config': self._is_config_file(response, filename),
                    'is_log': self._is_log_file(response, filename),
                    'sensitive_data': self._extract_sensitive_config_data(response.text) if response.text else None
                }
                
                if (result['is_backup'] or result['is_config'] or 
                    result['is_log'] or result['sensitive_data']):
                    
                    with self.lock:
                        self.results['backup_files'].append(result)
                    
                    print(f"{Fore.RED}[+] Found sensitive file: {endpoint} [{response.status_code}]{Style.RESET_ALL}")
        
        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            print(f"{Fore.RED}[!] Error testing backup endpoint {endpoint}: {e}{Style.RESET_ALL}")
    
    def _attempt_directory_traversal(self):
        """Attempt directory traversal attacks"""
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '../../../var/log/apache2/access.log',
            '../../../proc/version',
            '../../../etc/shadow'
        ]
        
        common_params = ['file', 'path', 'page', 'include', 'doc', 'document']
        
        for param in common_params:
            for payload in traversal_payloads:
                try:
                    url = f"{self.scanner.target_url}?{param}={payload}"
                    response = self.session.get(url, timeout=10)
                    
                    if response.status_code == 200 and len(response.text) > 100:
                        # Check for signs of successful traversal
                        if ('root:' in response.text or 
                            'daemon:' in response.text or 
                            'Linux version' in response.text or 
                            'Windows' in response.text):
                            
                            result = {
                                'url': url,
                                'payload': payload,
                                'param': param,
                                'status_code': response.status_code,
                                'content_preview': response.text[:200]
                            }
                            
                            with self.lock:
                                self.results['directory_traversal'].append(result)
                            
                            print(f"{Fore.RED}[+] Possible directory traversal: {param}={payload}{Style.RESET_ALL}")
                
                except Exception:
                    continue
    
    def _is_backup_file(self, response, filename):
        """Check if response indicates a backup file"""
        backup_indicators = [
            'CREATE TABLE', 'INSERT INTO', 'DROP TABLE',
            'mysqldump', 'pg_dump', 'sqlite_master',
            'backup', 'dump', 'export'
        ]
        
        backup_extensions = ['.sql', '.db', '.sqlite', '.bak', '.backup']
        
        # Check file extension
        if any(filename.endswith(ext) for ext in backup_extensions):
            return True
        
        # Check content
        if response.text:
            content_lower = response.text.lower()
            return any(indicator.lower() in content_lower for indicator in backup_indicators)
        
        return False
    
    def _is_config_file(self, response, filename):
        """Check if response indicates a configuration file"""
        config_indicators = [
            'database_host', 'db_host', 'mysql_host',
            'password', 'secret_key', 'api_key',
            'config', 'settings', 'configuration'
        ]
        
        config_extensions = ['.env', '.config', '.ini', '.conf', '.cfg']
        
        # Check file extension
        if any(filename.endswith(ext) for ext in config_extensions):
            return True
        
        # Check content
        if response.text:
            content_lower = response.text.lower()
            return any(indicator in content_lower for indicator in config_indicators)
        
        return False
    
    def _is_log_file(self, response, filename):
        """Check if response indicates a log file"""
        log_indicators = [
            'error', 'warning', 'info', 'debug',
            'exception', 'traceback', 'stack trace',
            'access log', 'error log'
        ]
        
        log_extensions = ['.log', '.txt']
        
        # Check file extension
        if any(filename.endswith(ext) for ext in log_extensions):
            return True
        
        # Check content
        if response.text:
            content_lower = response.text.lower()
            return any(indicator in content_lower for indicator in log_indicators)
        
        return False
    
    def _extract_sensitive_config_data(self, content):
        """Extract sensitive configuration data"""
        if not content:
            return None
        
        patterns = {
            'database_passwords': r'(?:db_password|database_password|mysql_password)\s*[=:]\s*["\']?([^\s"\';\n]+)',
            'api_keys': r'(?:api_key|apikey|api_secret)\s*[=:]\s*["\']?([^\s"\';\n]+)',
            'secret_keys': r'(?:secret_key|secret|private_key)\s*[=:]\s*["\']?([^\s"\';\n]+)',
            'database_hosts': r'(?:db_host|database_host|mysql_host)\s*[=:]\s*["\']?([^\s"\';\n]+)',
            'email_passwords': r'(?:mail_password|email_password|smtp_password)\s*[=:]\s*["\']?([^\s"\';\n]+)'
        }
        
        found_data = {}
        for key, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                found_data[key] = matches[:5]  # Limit to first 5 matches
        
        return found_data if found_data else None
    
    def _analyze_log_content(self, content):
        """Analyze log content for sensitive information"""
        if not content:
            return None
        
        log_patterns = {
            'errors': r'(?:error|exception|fatal).*',
            'warnings': r'(?:warning|warn).*',
            'sql_queries': r'(?:SELECT|INSERT|UPDATE|DELETE)\s+.*',
            'file_paths': r'(?:/[a-zA-Z0-9_./]+|[A-Z]:\\[a-zA-Z0-9_.\\]+)',
            'ip_addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        }
        
        found_data = {}
        for key, pattern in log_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                found_data[key] = matches[:10]  # Limit to first 10 matches
        
        return found_data if found_data else None
    
    def _analyze_javascript_endpoints(self):
        """Analyze JavaScript files for endpoint references"""
        from .asset_file_checker import AssetFileChecker
        asset_checker = AssetFileChecker(self.scanner)
        found_endpoints = asset_checker.analyze_javascript_endpoints()
        
        for endpoint_info in found_endpoints:
            endpoint = endpoint_info['endpoint']
            if endpoint not in self.discovered_endpoints:
                self._test_endpoint(endpoint, 'javascript')
    
    def _discover_discourse_plugin_endpoints(self):
        """Discover Discourse plugin endpoints"""
        # Common Discourse plugin endpoints
        discourse_plugin_endpoints = [
            # Plugin management
            '/admin/plugins',
            '/admin/plugins.json',
            '/admin/plugins/installed',
            '/admin/plugins/available',
            '/admin/plugins/updates',
            
            # Popular Discourse plugins
            '/discourse-oauth2-basic',
            '/discourse-saml',
            '/discourse-ldap-auth',
            '/discourse-google-oauth2',
            '/discourse-github-oauth2',
            '/discourse-facebook-oauth2',
            '/discourse-twitter-oauth2',
            '/discourse-linkedin-oauth2',
            
            # Chat plugin
            '/chat',
            '/chat/api',
            '/chat/channels',
            '/chat/messages',
            '/admin/plugins/chat',
            
            # Calendar plugin
            '/calendar',
            '/discourse-calendar',
            '/admin/plugins/discourse-calendar',
            
            # Voting plugin
            '/voting',
            '/discourse-voting',
            '/admin/plugins/discourse-voting',
            
            # Solved plugin
            '/solved',
            '/discourse-solved',
            '/admin/plugins/discourse-solved',
            
            # Assign plugin
            '/assign',
            '/discourse-assign',
            '/admin/plugins/discourse-assign',
            
            # Checklist plugin
            '/checklist',
            '/discourse-checklist',
            '/admin/plugins/discourse-checklist',
            
            # Math plugin
            '/math',
            '/discourse-math',
            '/admin/plugins/discourse-math',
            
            # Polls plugin
            '/polls',
            '/discourse-polls',
            '/admin/plugins/discourse-polls',
            
            # Data explorer plugin
            '/admin/plugins/explorer',
            '/admin/plugins/data-explorer',
            '/admin/plugins/discourse-data-explorer',
            
            # Akismet plugin
            '/admin/plugins/akismet',
            '/admin/plugins/discourse-akismet',
            
            # Sitemap plugin
            '/sitemap',
            '/sitemap.xml',
            '/admin/plugins/discourse-sitemap',
            
            # Custom plugin paths
            '/plugins',
            '/plugins.json',
            '/plugin-outlets',
            '/plugin-api'
        ]
        
        for endpoint in discourse_plugin_endpoints:
            if endpoint not in self.discovered_endpoints:
                self._test_endpoint(endpoint, 'discourse_plugin')
    
    def _discover_discourse_theme_endpoints(self):
        """Discover Discourse theme endpoints"""
        from .theme_file_checker import ThemeFileChecker
        theme_checker = ThemeFileChecker(self.scanner)
        discourse_theme_endpoints = theme_checker.discover_discourse_theme_endpoints()
        
        for endpoint in discourse_theme_endpoints:
            if endpoint not in self.discovered_endpoints:
                self._test_endpoint(endpoint, 'discourse_theme')
    
    def _analyze_discourse_robots_sitemap(self):
        """Analyze Discourse robots.txt and sitemap for additional endpoints"""
        from .asset_file_checker import AssetFileChecker
        asset_checker = AssetFileChecker(self.scanner)
        found_endpoints = asset_checker.analyze_discourse_robots_sitemap()
        
        for endpoint_info in found_endpoints:
            endpoint = endpoint_info['endpoint']
            source_type = endpoint_info.get('type', 'unknown')
            
            if endpoint not in self.discovered_endpoints:
                if source_type == 'disallowed':
                    self._test_endpoint(endpoint, 'discourse_robots')
                elif source_type == 'sitemap_url':
                    self._test_endpoint(endpoint, 'discourse_sitemap')
                else:
                    self._test_endpoint(endpoint, 'discourse_robots')