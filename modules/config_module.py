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
        
    def run(self):
        """Run complete configuration security scan (main entry point)"""
        return self.run_scan()
    
    def run_scan(self):
        """Run complete configuration security scan"""
        from colorama import Fore, Style
        print(f"\n{Fore.CYAN}[*] Starting configuration security scan...{Style.RESET_ALL}")
        
        # Configuration files
        self._discover_config_files()
        
        # Sensitive configurations
        self._check_sensitive_configs()
        
        # Debug information
        self._check_debug_info()
        
        # Backup files
        self._discover_backup_files()
        
        # Environment information disclosure
        self._check_environment_disclosure()
        
        # SSL/TLS configuration
        self._check_ssl_config()
        
        # Security headers
        self._check_security_headers()
        
        # CORS misconfiguration
        self._check_cors_misconfig()
        
        # Admin access control
        self._check_admin_access()
        
        # Default credentials
        self._check_default_credentials()
        
        return self.results
    
    def _discover_config_files(self):
        """Discover configuration files"""
        from colorama import Fore, Style
        print(f"{Fore.CYAN}[*] Scanning configuration files...{Style.RESET_ALL}")
        
        config_files = [
            # Discourse specific configuration files
            '/config/discourse.conf',
            '/config/database.yml',
            '/config/redis.yml',
            '/config/application.yml',
            '/config/environments/production.rb',
            '/config/environments/development.rb',
            '/config/initializers/discourse.rb',
            '/config/site_settings.yml',
            '/config/secrets.yml',
            '/config/application.rb',
            '/config/boot.rb',
            '/config/environment.rb',
            '/config/routes.rb',
            '/config/puma.rb',
            '/config/schedule.rb',
            '/config/unicorn.rb',
            '/config/thin.yml',
            '/config/sidekiq.yml',
            '/config/nginx.conf',
            '/config/multisite.yml',
            '/config/locales/server.en.yml',
            '/config/locales/client.en.yml',
            
            # Discourse Ruby on Rails specific
            '/Rakefile',
            '/config.ru',
            '/Capfile',
            '/Guardfile',
            '/Procfile',
            '/app/models/discourse.rb',
            '/lib/discourse.rb',
            '/lib/version.rb',
            '/lib/tasks/discourse.rake',
            
            # Discourse backup and log files
            '/backup.sql',
            '/discourse_backup.tar.gz',
            '/backups/default.tar.gz',
            '/tmp/backups/discourse.tar.gz',
            '/var/discourse/shared/standalone/backups/default.tar.gz',
            '/logs/production.log',
            '/logs/unicorn.stderr.log',
            '/logs/unicorn.stdout.log',
            '/logs/nginx.access.log',
            '/logs/nginx.error.log',
            '/log/production.log',
            '/log/development.log',
            '/log/test.log',
            '/log/sidekiq.log',
            '/var/log/discourse/rails/production.log',
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
            
            # Discourse sensitive system files
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/hostname',
            '/etc/issue',
            '/proc/version',
            '/proc/self/environ',
            '/home/discourse/.ssh/id_rsa',
            '/home/discourse/.ssh/id_rsa.pub',
            '/home/discourse/.ssh/authorized_keys',
            '/root/.ssh/id_rsa',
            '/var/discourse/shared/standalone/ssl/ssl.crt',
            '/var/discourse/shared/standalone/ssl/ssl.key',
            
            # Windows specific (for Windows Discourse installations)
            '/windows/system32/drivers/etc/hosts',
            '/windows/win.ini',
            '/boot.ini',
            '/windows/system32/config/sam',
            '/windows/repair/sam',
            '/windows/system32/config/system',
            '/inetpub/wwwroot/web.config',
            
            # General environment and config files
            '/.env',
            '/.env.local',
            '/.env.production',
            '/.env.development',
            '/.env.staging',
            '/.env.test',
            '/config.json',
            '/config.yml',
            '/config.yaml',
            '/settings.json',
            '/settings.yml',
            '/app.config',
            '/web.config',
            '/nginx.conf',
            '/apache.conf',
            '/apache2.conf',
            '/.htaccess',
            '/robots.txt',
            '/sitemap.xml',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml',
            '/humans.txt',
            '/security.txt',
            '/.well-known/security.txt',
            
            # Docker and containerization
            '/docker-compose.yml',
            '/docker-compose.yaml',
            '/docker-compose.override.yml',
            '/Dockerfile',
            '/Dockerfile.production',
            '/.dockerignore',
            '/.docker/config.json',
            '/kubernetes.yml',
            '/k8s.yml',
            
            # Version control systems
            '/.git/config',
            '/.git/HEAD',
            '/.git/index',
            '/.git/logs/HEAD',
            '/.git/refs/heads/master',
            '/.git/refs/heads/main',
            '/.git/objects/',
            '/.git/description',
            '/.git/hooks/',
            '/.git/info/refs',
            '/.git/packed-refs',
            '/.gitignore',
            '/.gitmodules',
            '/.gitattributes',
            '/.svn/',
            '/.svn/entries',
            '/.hg/',
            '/.bzr/',
            
            # Package managers and dependencies
            '/package.json',
            '/package-lock.json',
            '/yarn.lock',
            '/Gemfile',
            '/Gemfile.lock',
            '/requirements.txt',
            '/composer.json',
            '/composer.lock',
            '/bower.json',
            '/npm-shrinkwrap.json',
            '/pnpm-lock.yaml',
            '/poetry.lock',
            '/Pipfile',
            '/Pipfile.lock',
            
            # Documentation and info files
            '/README.md',
            '/README.txt',
            '/CHANGELOG.md',
            '/CHANGELOG.txt',
            '/LICENSE',
            '/LICENSE.txt',
            '/VERSION',
            '/INSTALL',
            '/INSTALL.txt',
            '/TODO',
            '/TODO.txt',
            '/CONTRIBUTING.md',
            '/SECURITY.md',
            
            # Development and debug files
            '/phpinfo.php',
            '/info.php',
            '/test.php',
            '/debug.php',
            '/status.php',
            '/health.php'
        ]
        
        for config_file in config_files:
            url = urljoin(self.scanner.target_url, config_file)
            response = make_request(url, 'GET')
            
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
        from colorama import Fore, Style
        print(f"{Fore.CYAN}[*] Checking sensitive configurations...{Style.RESET_ALL}")
        
        # Admin site settings
        admin_settings_url = urljoin(self.scanner.target_url, '/admin/site_settings')
        response = make_request(admin_settings_url, 'GET')
        
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
            # Core configuration endpoints
            '/admin/site_settings.json',
            '/admin/config.json',
            '/site.json',
            '/srv/status',
            '/admin/dashboard.json',
            '/admin/dashboard/general.json',
            '/admin/dashboard/moderation.json',
            '/admin/dashboard/security.json',
            '/admin/dashboard/reports.json',
            '/admin/dashboard/problems.json',
            '/admin/dashboard/version_check.json',
            '/settings.json',
            '/site_settings.json',
            
            # System and version information
            '/admin/system.json',
            '/admin/upgrade.json',
            '/admin/docker.json',
            '/health.json',
            '/status.json',
            '/about.json',
            '/srv/status',
            
            # User and admin information
            '/users.json',
            '/admin/users.json',
            '/admin/users/list.json',
            '/admin/users/list/active.json',
            '/admin/users/list/staff.json',
            '/admin/users/list/suspended.json',
            '/admin/users/list/new.json',
            '/admin/users/list/admins.json',
            '/admin/users/list/moderators.json',
            '/directory_items.json',
            '/groups.json',
            '/admin/groups.json',
            
            # API and authentication
            '/admin/api.json',
            '/admin/api/keys.json',
            
            # Email configuration
            '/admin/email.json',
            '/admin/email/sent.json',
            '/admin/email/skipped.json',
            '/admin/email/bounced.json',
            '/admin/email/received.json',
            '/admin/email/rejected.json',
            '/admin/customize/email_templates.json',
            
            # Backup and database information
            '/admin/backups.json',
            '/admin/export_csv.json',
            '/admin/import.json',
            
            # Logs and monitoring
            '/admin/logs.json',
            '/admin/logs/staff_action_logs.json',
            '/admin/logs/screened_emails.json',
            '/admin/logs/screened_ip_addresses.json',
            '/logs.json',
            
            # Customization and plugins
            '/admin/customize.json',
            '/admin/customize/themes.json',
            '/admin/plugins.json',
            '/admin/themes.json',
            
            # Search and categories
            '/admin/search_logs.json',
            '/categories.json',
            '/admin/categories.json',
            
            # Reports and analytics
            '/admin/reports.json',
            '/admin/reports/signups.json',
            '/admin/reports/posts.json',
            '/admin/reports/topics.json',
            '/admin/reports/users_by_trust_level.json',
            
            # Webhooks and integrations
            '/admin/web_hooks.json',
            '/admin/webhooks.json',
            '/admin/api/web_hooks.json'
        ]
        
        for endpoint in config_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(url, 'GET')
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    self._analyze_json_config(endpoint, data)
                except (json.JSONDecodeError, ValueError):
                    # Skip non-JSON responses
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
        from colorama import Fore, Style
        print(f"{Fore.CYAN}[*] Checking debug information disclosure...{Style.RESET_ALL}")
        
        debug_endpoints = [
            # Core debug endpoints
            '/debug',
            '/debug.json',
            '/debug/routes',
            '/debug/pry',
            '/__debug__',
            '/server-info',
            '/server-status',
            
            # Rails specific debug endpoints
            '/rails/info',
            '/rails/info/routes',
            '/rails/info/properties',
            '/rails/mailers',
            '/rails/info/environment',
            '/rails/info/database',
            
            # Admin debug and logs
            '/admin/logs',
            '/admin/logs.json',
            '/admin/logs/staff_action_logs',
            '/admin/logs/staff_action_logs.json',
            '/admin/logs/screened_emails',
            '/admin/logs/screened_ip_addresses',
            '/admin/system',
            '/admin/system.json',
            '/admin/upgrade',
            '/admin/upgrade.json',
            '/admin/docker',
            '/admin/docker.json',
            
            # General logs and monitoring
            '/logs',
            '/logs.json',
            '/error_log',
            '/access_log',
            '/health',
            '/health.json',
            '/status',
            '/status.json',
            '/srv/status',
            '/monitor',
            '/monitoring',
            
            # Development and test files
            '/info.php',
            '/phpinfo.php',
            '/test.php',
            '/debug.php',
            '/status.php',
            '/health.php',
            '/version.php',
            '/config.php',
            
            # Environment and configuration debug
            '/env',
            '/environment',
            '/config/environment',
            '/admin/environment',
            '/debug/environment',
            '/server/environment',
            
            # Error pages and stack traces
            '/500.html',
            '/404.html',
            '/error',
            '/errors',
            '/exception',
            '/exceptions',
            '/trace',
            '/backtrace',
            
            # Development tools
            '/console',
            '/irb',
            '/pry',
            '/shell',
            '/terminal'
        ]
        
        for endpoint in debug_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(url, 'GET')
            
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
        from colorama import Fore, Style
        print(f"{Fore.CYAN}[*] Scanning backup files...{Style.RESET_ALL}")
        
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
            # SQL dumps and database backups
            '/backup.sql',
            '/database.sql',
            '/db.sql',
            '/dump.sql',
            '/discourse.sql',
            '/production.sql',
            '/development.sql',
            '/test.sql',
            '/mysql.sql',
            '/postgresql.sql',
            '/postgres.sql',
            '/db_backup.sql',
            '/database_backup.sql',
            '/site_backup.sql',
            
            # Compressed backups
            '/backup.tar.gz',
            '/backup.zip',
            '/backup.tar',
            '/backup.rar',
            '/site_backup.tar.gz',
            '/discourse_backup.tar.gz',
            '/database_backup.tar.gz',
            '/full_backup.tar.gz',
            '/complete_backup.zip',
            '/export.tar.gz',
            '/dump.tar.gz',
            
            # Discourse specific backups
            '/backups/default.tar.gz',
            '/tmp/backups/discourse.tar.gz',
            '/var/discourse/shared/standalone/backups/default.tar.gz',
            '/var/discourse/backups/default.tar.gz',
            '/shared/backups/default.tar.gz',
            '/discourse/backups/default.tar.gz',
            
            # Configuration file backups
            '/config.bak',
            '/database.yml.bak',
            '/application.yml.old',
            '/discourse.conf.bak',
            '/secrets.yml.backup',
            '/site_settings.yml.old',
            '/.env.backup',
            '/.env.bak',
            '/.env.old',
            '/config/database.yml.backup',
            '/config/application.yml.bak',
            '/config/secrets.yml.old',
            
            # Log file backups
            '/logs/production.log.1',
            '/logs/production.log.old',
            '/log/production.log.backup',
            '/var/log/discourse/rails/production.log.1',
            '/var/log/nginx/access.log.1',
            '/var/log/nginx/error.log.old',
            
            # Directory listings
            '/backup/',
            '/backups/',
            '/dumps/',
            '/exports/',
            '/archive/',
            '/archives/',
            '/old/',
            '/tmp/',
            '/temp/',
            '/bak/',
            '/backup_files/',
            '/database_backups/',
            '/site_backups/',
            '/discourse_backups/',
            
            # System backups
            '/etc/passwd.bak',
            '/etc/shadow.backup',
            '/etc/hosts.old',
            '/home/discourse/.ssh/id_rsa.backup',
            '/root/.ssh/id_rsa.old',
            
            # Application backups
            '/app.tar.gz',
            '/application.zip',
            '/site.tar.gz',
            '/website.zip',
            '/forum.tar.gz',
            '/discourse.zip',
            '/rails_app.tar.gz',
            
            # Docker and container backups
            '/docker-compose.yml.bak',
            '/Dockerfile.backup',
            '/containers.tar.gz',
            '/volumes.tar.gz'
        ]
        
        for backup_file in backup_files:
            url = urljoin(self.scanner.target_url, backup_file)
            response = make_request(url, 'GET')
            
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
                response = make_request(url, 'GET')
                
                if response and response.status_code == 200:
                    self.results['backup_files'].append({
                        'file': backup_file,
                        'size': len(response.content),
                        'severity': 'High',
                        'description': f'Backup file accessible at {backup_file}'
                    })
    
    def _check_environment_disclosure(self):
        """Check for environment variable disclosure"""
        from colorama import Fore, Style
        print(f"{Fore.CYAN}[*] Checking environment information disclosure...{Style.RESET_ALL}")
        
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
            response = make_request(url, 'GET')
            
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
        from colorama import Fore, Style
        print(f"{Fore.CYAN}[*] Checking SSL/TLS configuration...{Style.RESET_ALL}")
        
        # Check if HTTPS is enforced
        http_url = self.scanner.target_url.replace('https://', 'http://')
        response = make_request(http_url, 'GET', allow_redirects=False)
        
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
        from colorama import Fore, Style
        print(f"{Fore.CYAN}[*] Checking security headers...{Style.RESET_ALL}")
        
        response = make_request(self.scanner.target_url, 'GET')
        
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
        from colorama import Fore, Style
        print(f"{Fore.CYAN}[*] Checking CORS misconfiguration...{Style.RESET_ALL}")
        
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
            response = make_request(self.scanner.target_url, 'GET', headers=headers)
            
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
        from colorama import Fore, Style
        print(f"{Fore.CYAN}[*] Testing admin access control...{Style.RESET_ALL}")
        
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
            response = make_request(url, 'GET')
            
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
        from colorama import Fore, Style
        print(f"{Fore.CYAN}[*] Testing default credentials...{Style.RESET_ALL}")
        
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
            response = make_request(self.scanner.target_url, 'GET')
            csrf_token = extract_csrf_token(response.text) if response else None
            
            login_data = {
                'login': username,
                'password': password,
                'authenticity_token': csrf_token
            }
            
            response = make_request(login_url, 'POST', data=login_data)
            
            if response:
                if response.status_code == 200 and 'error' not in response.text.lower():
                    # Check if login was successful
                    dashboard_url = urljoin(self.scanner.target_url, '/admin')
                    dashboard_response = make_request(dashboard_url, 'GET')
                    
                    if dashboard_response and dashboard_response.status_code == 200:
                        self.results['default_credentials'].append({
                            'username': username,
                            'password': password,
                            'severity': 'Critical',
                            'description': f'Default credentials work: {username}:{password}'
                        })
                        break  # Stop testing once we find working credentials
            
            time.sleep(1)  # Avoid rate limiting