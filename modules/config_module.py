#!/usr/bin/env python3
"""
Discourse Security Scanner - Configuration Security Module

Tests configuration-related security issues and misconfigurations
"""

import re
import time
import json
import yaml
from urllib.parse import urljoin, quote
from bs4 import BeautifulSoup
from .utils import extract_csrf_token, make_request

class ConfigModule:
    """Configuration security testing module for Discourse forums"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Configuration Security Testing',
            'target': scanner.target_url,
            'config_files': [],
            'sensitive_configs': [],
            'debug_info': [],
            'backup_files': [],
            'environment_disclosure': [],
            'ssl_issues': [],
            'security_headers': [],
            'cors_misconfig': [],
            'admin_access': [],
            'default_credentials': []
        }
        
    def run_scan(self):
        """Run complete configuration security scan"""
        print(f"\n{self.scanner.colors['info']}[*] Yapılandırma güvenlik taraması başlatılıyor...{self.scanner.colors['reset']}")
        
        # Yapılandırma dosyaları
        self._discover_config_files()
        
        # Hassas yapılandırmalar
        self._check_sensitive_configs()
        
        # Debug bilgileri
        self._check_debug_info()
        
        # Yedek dosyalar
        self._discover_backup_files()
        
        # Environment bilgi sızıntısı
        self._check_environment_disclosure()
        
        # SSL/TLS yapılandırması
        self._check_ssl_config()
        
        # Güvenlik başlıkları
        self._check_security_headers()
        
        # CORS yanlış yapılandırması
        self._check_cors_misconfig()
        
        # Admin erişim kontrolü
        self._check_admin_access()
        
        # Varsayılan kimlik bilgileri
        self._check_default_credentials()
        
        return self.results
    
    def _discover_config_files(self):
        """Discover configuration files"""
        print(f"{self.scanner.colors['info']}[*] Yapılandırma dosyaları taranıyor...{self.scanner.colors['reset']}")
        
        config_files = [
            # Discourse specific
            '/config/discourse.conf',
            '/config/database.yml',
            '/config/redis.yml',
            '/config/application.yml',
            '/config/environments/production.rb',
            '/config/environments/development.rb',
            '/config/initializers/discourse.rb',
            '/config/site_settings.yml',
            
            # General config files
            '/.env',
            '/.env.local',
            '/.env.production',
            '/.env.development',
            '/config.json',
            '/config.yml',
            '/config.yaml',
            '/settings.json',
            '/settings.yml',
            '/app.config',
            '/web.config',
            '/nginx.conf',
            '/apache.conf',
            '/.htaccess',
            '/robots.txt',
            '/sitemap.xml',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml',
            
            # Docker configs
            '/docker-compose.yml',
            '/Dockerfile',
            '/.dockerignore',
            
            # Git configs
            '/.git/config',
            '/.gitignore',
            '/.gitmodules',
            
            # Package managers
            '/package.json',
            '/package-lock.json',
            '/yarn.lock',
            '/Gemfile',
            '/Gemfile.lock',
            '/requirements.txt',
            '/composer.json',
            '/composer.lock'
        ]
        
        for config_file in config_files:
            url = urljoin(self.scanner.target_url, config_file)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                
                # Check if it's actually a config file
                if any(ct in content_type for ct in ['text/', 'application/json', 'application/yaml']):
                    self.results['config_files'].append({
                        'file': config_file,
                        'size': len(response.text),
                        'content_type': content_type,
                        'accessible': True,
                        'content_preview': response.text[:500]
                    })
                    
                    # Analyze content for sensitive information
                    self._analyze_config_content(config_file, response.text)
    
    def _analyze_config_content(self, filename, content):
        """Analyze configuration file content for sensitive information"""
        sensitive_patterns = {
            'database_password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\';]+)',
            'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            'secret_key': r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            'jwt_secret': r'(?i)(jwt[_-]?secret|jwtsecret)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            'encryption_key': r'(?i)(encryption[_-]?key|encryptionkey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            'private_key': r'-----BEGIN (RSA )?PRIVATE KEY-----',
            'aws_credentials': r'(?i)(aws[_-]?(access[_-]?key|secret))',
            'database_url': r'(?i)(database[_-]?url|db[_-]?url)\s*[:=]\s*["\']?([^\s"\';]+)',
            'redis_url': r'(?i)(redis[_-]?url)\s*[:=]\s*["\']?([^\s"\';]+)',
            'smtp_password': r'(?i)(smtp[_-]?password|mail[_-]?password)\s*[:=]\s*["\']?([^\s"\';]+)',
            'oauth_secret': r'(?i)(oauth[_-]?secret|client[_-]?secret)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})'
        }
        
        for pattern_name, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                for match in matches:
                    value = match[1] if isinstance(match, tuple) else match
                    self.results['sensitive_configs'].append({
                        'file': filename,
                        'type': pattern_name,
                        'value': value[:20] + '...' if len(value) > 20 else value,
                        'severity': 'Critical' if 'password' in pattern_name or 'secret' in pattern_name else 'High',
                        'description': f'{pattern_name} found in {filename}'
                    })
    
    def _check_sensitive_configs(self):
        """Check for sensitive configuration exposures"""
        print(f"{self.scanner.colors['info']}[*] Hassas yapılandırmalar kontrol ediliyor...{self.scanner.colors['reset']}")
        
        # Admin site settings
        admin_settings_url = urljoin(self.scanner.target_url, '/admin/site_settings')
        response = make_request(self.scanner.session, 'GET', admin_settings_url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for exposed sensitive settings
            sensitive_settings = [
                'smtp_password',
                'pop3_polling_password',
                's3_secret_access_key',
                'github_client_secret',
                'google_oauth2_client_secret',
                'facebook_app_secret',
                'twitter_consumer_secret',
                'discord_secret'
            ]
            
            for setting in sensitive_settings:
                setting_element = soup.find('input', {'name': setting})
                if setting_element and setting_element.get('value'):
                    self.results['sensitive_configs'].append({
                        'setting': setting,
                        'exposed': True,
                        'severity': 'Critical',
                        'description': f'Sensitive setting {setting} exposed in admin panel'
                    })
        
        # API endpoints that might expose config
        config_endpoints = [
            '/admin/site_settings.json',
            '/admin/config.json',
            '/site.json',
            '/srv/status',
            '/admin/dashboard.json'
        ]
        
        for endpoint in config_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    self._analyze_json_config(endpoint, data)
                except json.JSONDecodeError:
                    pass
    
    def _analyze_json_config(self, endpoint, data):
        """Analyze JSON configuration data"""
        sensitive_keys = [
            'password', 'secret', 'key', 'token', 'credential',
            'smtp_password', 'api_key', 'private_key', 'access_key'
        ]
        
        def search_dict(obj, path=''):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    if any(sensitive in key.lower() for sensitive in sensitive_keys):
                        if isinstance(value, str) and len(value) > 5:
                            self.results['sensitive_configs'].append({
                                'endpoint': endpoint,
                                'key': current_path,
                                'value': str(value)[:20] + '...' if len(str(value)) > 20 else str(value),
                                'severity': 'High',
                                'description': f'Sensitive configuration exposed at {endpoint}'
                            })
                    
                    search_dict(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    search_dict(item, f"{path}[{i}]")
        
        search_dict(data)
    
    def _check_debug_info(self):
        """Check for debug information disclosure"""
        print(f"{self.scanner.colors['info']}[*] Debug bilgi sızıntıları kontrol ediliyor...{self.scanner.colors['reset']}")
        
        debug_endpoints = [
            '/debug',
            '/debug/routes',
            '/debug/pry',
            '/rails/info',
            '/rails/info/routes',
            '/rails/info/properties',
            '/__debug__',
            '/server-info',
            '/server-status',
            '/info.php',
            '/phpinfo.php',
            '/test.php',
            '/debug.php'
        ]
        
        for endpoint in debug_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                debug_indicators = [
                    'ruby version',
                    'rails version',
                    'environment:',
                    'database:',
                    'secret_key_base',
                    'stack trace',
                    'backtrace',
                    'exception',
                    'debug mode',
                    'development mode'
                ]
                
                content_lower = response.text.lower()
                found_indicators = [indicator for indicator in debug_indicators if indicator in content_lower]
                
                if found_indicators:
                    self.results['debug_info'].append({
                        'endpoint': endpoint,
                        'indicators': found_indicators,
                        'severity': 'Medium',
                        'description': f'Debug information exposed at {endpoint}'
                    })
    
    def _discover_backup_files(self):
        """Discover backup files"""
        print(f"{self.scanner.colors['info']}[*] Yedek dosyalar taranıyor...{self.scanner.colors['reset']}")
        
        backup_extensions = ['.bak', '.backup', '.old', '.orig', '.copy', '.tmp', '.save']
        backup_patterns = [
            'backup',
            'database_backup',
            'db_backup',
            'site_backup',
            'discourse_backup',
            'export',
            'dump'
        ]
        
        # Common backup file locations
        backup_files = [
            '/backup.sql',
            '/database.sql',
            '/db.sql',
            '/dump.sql',
            '/backup.tar.gz',
            '/backup.zip',
            '/site_backup.tar.gz',
            '/discourse_backup.tar.gz',
            '/config.bak',
            '/database.yml.bak',
            '/application.yml.old',
            '/.env.backup',
            '/backup/',
            '/backups/',
            '/dumps/',
            '/exports/'
        ]
        
        for backup_file in backup_files:
            url = urljoin(self.scanner.target_url, backup_file)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                self.results['backup_files'].append({
                    'file': backup_file,
                    'size': len(response.content),
                    'content_type': response.headers.get('content-type', ''),
                    'severity': 'High',
                    'description': f'Backup file accessible at {backup_file}'
                })
        
        # Check for backup files with extensions
        common_files = ['config', 'database', 'application', '.env', 'settings']
        for file_base in common_files:
            for ext in backup_extensions:
                backup_file = f'/{file_base}{ext}'
                url = urljoin(self.scanner.target_url, backup_file)
                response = make_request(self.scanner.session, 'GET', url)
                
                if response and response.status_code == 200:
                    self.results['backup_files'].append({
                        'file': backup_file,
                        'size': len(response.content),
                        'severity': 'High',
                        'description': f'Backup file accessible at {backup_file}'
                    })
    
    def _check_environment_disclosure(self):
        """Check for environment variable disclosure"""
        print(f"{self.scanner.colors['info']}[*] Environment bilgi sızıntısı kontrol ediliyor...{self.scanner.colors['reset']}")
        
        env_endpoints = [
            '/env',
            '/environment',
            '/.env',
            '/config/environment',
            '/admin/environment',
            '/debug/environment',
            '/server/environment'
        ]
        
        for endpoint in env_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                env_indicators = [
                    'PATH=',
                    'HOME=',
                    'USER=',
                    'RAILS_ENV=',
                    'DATABASE_URL=',
                    'REDIS_URL=',
                    'SECRET_KEY_BASE='
                ]
                
                content = response.text
                found_vars = [var for var in env_indicators if var in content]
                
                if found_vars:
                    self.results['environment_disclosure'].append({
                        'endpoint': endpoint,
                        'variables': found_vars,
                        'severity': 'High',
                        'description': f'Environment variables exposed at {endpoint}'
                    })
    
    def _check_ssl_config(self):
        """Check SSL/TLS configuration"""
        print(f"{self.scanner.colors['info']}[*] SSL/TLS yapılandırması kontrol ediliyor...{self.scanner.colors['reset']}")
        
        # Check if HTTPS is enforced
        http_url = self.scanner.target_url.replace('https://', 'http://')
        response = make_request(self.scanner.session, 'GET', http_url, allow_redirects=False)
        
        if response:
            if response.status_code not in [301, 302, 308]:
                self.results['ssl_issues'].append({
                    'issue': 'HTTP not redirected to HTTPS',
                    'severity': 'Medium',
                    'description': 'Site accessible over HTTP without redirect to HTTPS'
                })
            elif 'location' in response.headers:
                location = response.headers['location']
                if not location.startswith('https://'):
                    self.results['ssl_issues'].append({
                        'issue': 'Insecure redirect',
                        'severity': 'Medium',
                        'description': 'HTTP redirects to non-HTTPS URL'
                    })
        
        # Check SSL Labs API for detailed SSL analysis (if available)
        try:
            import ssl
            import socket
            from urllib.parse import urlparse
            
            parsed_url = urlparse(self.scanner.target_url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate validity
                    import datetime
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.datetime.now():
                        self.results['ssl_issues'].append({
                            'issue': 'Expired SSL certificate',
                            'severity': 'High',
                            'description': f'SSL certificate expired on {cert["notAfter"]}'
                        })
                    
                    # Check weak ciphers
                    if cipher and len(cipher) >= 3:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', 'MD5', 'SHA1']):
                            self.results['ssl_issues'].append({
                                'issue': 'Weak SSL cipher',
                                'cipher': cipher_name,
                                'severity': 'Medium',
                                'description': f'Weak SSL cipher in use: {cipher_name}'
                            })
        except Exception as e:
            pass
    
    def _check_security_headers(self):
        """Check security headers"""
        print(f"{self.scanner.colors['info']}[*] Güvenlik başlıkları kontrol ediliyor...{self.scanner.colors['reset']}")
        
        response = make_request(self.scanner.session, 'GET', self.scanner.target_url)
        
        if response:
            headers = response.headers
            
            # Required security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS not implemented',
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-Content-Type-Options': 'MIME type sniffing protection missing',
                'X-XSS-Protection': 'XSS protection header missing',
                'Content-Security-Policy': 'CSP not implemented',
                'Referrer-Policy': 'Referrer policy not set',
                'Permissions-Policy': 'Permissions policy not set'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    severity = 'High' if header in ['Strict-Transport-Security', 'Content-Security-Policy'] else 'Medium'
                    self.results['security_headers'].append({
                        'header': header,
                        'status': 'missing',
                        'severity': severity,
                        'description': description
                    })
                else:
                    # Check header values for misconfigurations
                    header_value = headers[header]
                    self._analyze_security_header(header, header_value)
    
    def _analyze_security_header(self, header_name, header_value):
        """Analyze security header values for misconfigurations"""
        if header_name == 'Content-Security-Policy':
            # Check for unsafe CSP directives
            unsafe_directives = ['unsafe-inline', 'unsafe-eval', '*']
            for directive in unsafe_directives:
                if directive in header_value:
                    self.results['security_headers'].append({
                        'header': header_name,
                        'status': 'misconfigured',
                        'issue': f'Unsafe directive: {directive}',
                        'severity': 'Medium',
                        'description': f'CSP contains unsafe directive: {directive}'
                    })
        
        elif header_name == 'X-Frame-Options':
            if header_value.upper() not in ['DENY', 'SAMEORIGIN']:
                self.results['security_headers'].append({
                    'header': header_name,
                    'status': 'misconfigured',
                    'value': header_value,
                    'severity': 'Medium',
                    'description': f'X-Frame-Options has weak value: {header_value}'
                })
    
    def _check_cors_misconfig(self):
        """Check for CORS misconfigurations"""
        print(f"{self.scanner.colors['info']}[*] CORS yanlış yapılandırması kontrol ediliyor...{self.scanner.colors['reset']}")
        
        # Test CORS with various origins
        test_origins = [
            'https://evil.com',
            'http://evil.com',
            'null',
            '*',
            'https://attacker.com'
        ]
        
        for origin in test_origins:
            headers = {'Origin': origin}
            response = make_request(self.scanner.session, 'GET', self.scanner.target_url, headers=headers)
            
            if response:
                cors_headers = {
                    'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
                    'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
                    'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods'),
                    'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers')
                }
                
                # Check for dangerous CORS configurations
                if cors_headers['Access-Control-Allow-Origin'] == '*':
                    if cors_headers['Access-Control-Allow-Credentials'] == 'true':
                        self.results['cors_misconfig'].append({
                            'issue': 'Wildcard origin with credentials',
                            'origin': origin,
                            'severity': 'High',
                            'description': 'CORS allows wildcard origin with credentials'
                        })
                
                elif cors_headers['Access-Control-Allow-Origin'] == origin:
                    self.results['cors_misconfig'].append({
                        'issue': 'Reflected origin allowed',
                        'origin': origin,
                        'severity': 'Medium',
                        'description': f'CORS reflects arbitrary origin: {origin}'
                    })
    
    def _check_admin_access(self):
        """Check admin access controls"""
        print(f"{self.scanner.colors['info']}[*] Admin erişim kontrolü test ediliyor...{self.scanner.colors['reset']}")
        
        admin_endpoints = [
            '/admin',
            '/admin/',
            '/admin/dashboard',
            '/admin/users',
            '/admin/site_settings',
            '/admin/plugins',
            '/admin/themes',
            '/admin/logs',
            '/admin/api',
            '/sidekiq',
            '/sidekiq/cron'
        ]
        
        for endpoint in admin_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response:
                if response.status_code == 200:
                    # Check if admin panel is accessible without authentication
                    if any(keyword in response.text.lower() for keyword in ['admin', 'dashboard', 'settings', 'users']):
                        self.results['admin_access'].append({
                            'endpoint': endpoint,
                            'status': 'accessible',
                            'severity': 'Critical',
                            'description': f'Admin endpoint accessible without authentication: {endpoint}'
                        })
                
                elif response.status_code == 401:
                    # Check authentication method
                    auth_header = response.headers.get('WWW-Authenticate', '')
                    if 'Basic' in auth_header:
                        self.results['admin_access'].append({
                            'endpoint': endpoint,
                            'status': 'basic_auth',
                            'severity': 'Medium',
                            'description': f'Admin endpoint uses basic authentication: {endpoint}'
                        })
    
    def _check_default_credentials(self):
        """Check for default credentials"""
        print(f"{self.scanner.colors['info']}[*] Varsayılan kimlik bilgileri test ediliyor...{self.scanner.colors['reset']}")
        
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('discourse', 'discourse'),
            ('test', 'test'),
            ('demo', 'demo')
        ]
        
        login_url = urljoin(self.scanner.target_url, '/session')
        
        for username, password in default_creds:
            # Get CSRF token first
            csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
            
            login_data = {
                'login': username,
                'password': password,
                'authenticity_token': csrf_token
            }
            
            response = make_request(self.scanner.session, 'POST', login_url, data=login_data)
            
            if response:
                if response.status_code == 200 and 'error' not in response.text.lower():
                    # Check if login was successful
                    dashboard_url = urljoin(self.scanner.target_url, '/admin')
                    dashboard_response = make_request(self.scanner.session, 'GET', dashboard_url)
                    
                    if dashboard_response and dashboard_response.status_code == 200:
                        self.results['default_credentials'].append({
                            'username': username,
                            'password': password,
                            'severity': 'Critical',
                            'description': f'Default credentials work: {username}:{password}'
                        })
                        break  # Stop testing once we find working credentials
            
            time.sleep(1)  # Avoid rate limiting