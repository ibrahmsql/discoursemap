#!/usr/bin/env python3
"""
Discourse Security Scanner - Plugin File Checker

Checks Discourse plugin files for integrity and security issues
"""

import re
import json
from urllib.parse import urljoin
from .malicious_pattern_checker import MaliciousPatternChecker

class PluginFileChecker:
    """Checks Discourse plugin files for security and integrity issues"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.pattern_checker = MaliciousPatternChecker()
        
        # Common plugin file paths to check
        self.plugin_paths = [
            'plugins/',
            'plugins/discourse-',
            'plugins/docker_manager/',
            'plugins/discourse-solved/',
            'plugins/discourse-voting/',
            'plugins/discourse-calendar/',
            'plugins/discourse-chat-integration/',
            'plugins/discourse-data-explorer/',
            'plugins/discourse-math/',
            'plugins/discourse-spoiler-alert/',
            'plugins/discourse-assign/',
            'plugins/discourse-akismet/',
            'plugins/discourse-oauth2-basic/',
            'plugins/discourse-saml/',
            'plugins/discourse-openid-connect/',
            'plugins/discourse-github/',
            'plugins/discourse-google-analytics/',
            'plugins/discourse-sitemap/',
            'plugins/discourse-prometheus/',
            'plugins/discourse-backup-uploads-to-s3/',
            'plugins/discourse-encrypt/'
        ]
        
        # Plugin file extensions to check
        self.plugin_extensions = ['.rb', '.js', '.yml', '.yaml', '.json', '.erb', '.scss', '.css']
        
        # Suspicious plugin patterns
        self.suspicious_plugin_patterns = [
            r'eval\s*\(',
            r'system\s*\(',
            r'exec\s*\(',
            r'`[^`]*`',  # Backtick execution
            r'File\.open\s*\(',
            r'IO\.popen\s*\(',
            r'Net::HTTP',
            r'open\s*\(',
            r'require\s+["\']net/http["\']',
            r'require\s+["\']open-uri["\']',
            r'\$\{.*\}',  # Template injection
            r'<%.*%>',  # ERB injection
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'location\.href\s*=',
            r'window\.location',
            r'document\.cookie',
            r'localStorage',
            r'sessionStorage'
        ]
    
    def check_plugin_files(self):
        """Check plugin files for integrity and security issues"""
        self.scanner.log("Checking plugin files...", 'debug')
        
        plugin_issues = []
        
        # Check for plugin directory listing
        plugins_url = urljoin(self.scanner.target_url, 'plugins/')
        response = self.scanner.make_request(plugins_url)
        
        if response and response.status_code == 200:
            # Try to extract plugin names from directory listing or common paths
            plugin_names = self._extract_plugin_names(response.text)
            
            for plugin_name in plugin_names:
                plugin_issues.extend(self._check_individual_plugin(plugin_name))
        
        # Check common plugin paths even if directory listing is not available
        for plugin_path in self.plugin_paths:
            url = urljoin(self.scanner.target_url, plugin_path)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                plugin_name = plugin_path.split('/')[-1] or plugin_path.split('/')[-2]
                plugin_issues.extend(self._check_plugin_content(plugin_name, response.text, url))
        
        return plugin_issues
    
    def _extract_plugin_names(self, content):
        """Extract plugin names from directory listing or HTML content"""
        plugin_names = []
        
        # Look for common plugin directory patterns
        patterns = [
            r'href=["\']([^"\']*/plugins/[^"\'/]+/)["\']',
            r'discourse-[a-zA-Z0-9-]+',
            r'plugins/([a-zA-Z0-9-]+)/',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            plugin_names.extend(matches)
        
        # Remove duplicates and clean up
        plugin_names = list(set([name.strip('/') for name in plugin_names if name]))
        
        return plugin_names[:20]  # Limit to prevent excessive requests
    
    def _check_individual_plugin(self, plugin_name):
        """Check an individual plugin for security issues"""
        issues = []
        
        # Common plugin files to check
        plugin_files = [
            f'plugins/{plugin_name}/plugin.rb',
            f'plugins/{plugin_name}/config/settings.yml',
            f'plugins/{plugin_name}/assets/javascripts/discourse/initializers/{plugin_name}.js',
            f'plugins/{plugin_name}/assets/javascripts/discourse/components/{plugin_name}.js',
            f'plugins/{plugin_name}/assets/stylesheets/{plugin_name}.scss',
            f'plugins/{plugin_name}/lib/{plugin_name}.rb',
            f'plugins/{plugin_name}/app/controllers/{plugin_name}_controller.rb',
            f'plugins/{plugin_name}/app/models/{plugin_name}.rb'
        ]
        
        for file_path in plugin_files:
            url = urljoin(self.scanner.target_url, file_path)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                file_issues = self._check_plugin_content(plugin_name, response.text, url)
                issues.extend(file_issues)
        
        return issues
    
    def _check_plugin_content(self, plugin_name, content, url):
        """Check plugin content for security issues"""
        issues = []
        
        # Check for malicious patterns
        malicious_check = self.pattern_checker.check_malicious_patterns(content)
        if malicious_check['has_malicious']:
            issues.append({
                'type': 'malicious_code',
                'plugin': plugin_name,
                'url': url,
                'severity': 'Critical',
                'description': 'Plugin contains malicious code patterns',
                'patterns': malicious_check['patterns']
            })
        
        # Check for suspicious plugin-specific patterns
        suspicious_check = self.pattern_checker.check_suspicious_plugin_content(content)
        if suspicious_check['is_suspicious']:
            issues.append({
                'type': 'suspicious_plugin_code',
                'plugin': plugin_name,
                'url': url,
                'severity': 'High',
                'description': 'Plugin contains suspicious code patterns',
                'patterns': suspicious_check['patterns']
            })
        
        # Check for additional plugin-specific suspicious patterns
        for pattern in self.suspicious_plugin_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                issues.append({
                    'type': 'suspicious_pattern',
                    'plugin': plugin_name,
                    'url': url,
                    'severity': 'Medium',
                    'description': f'Plugin contains suspicious pattern: {pattern}',
                    'pattern': pattern
                })
        
        # Check for hardcoded credentials
        credential_patterns = [
            r'password\s*=\s*["\'][^"\'\'\\n\\r]{8,}["\']',
            r'api_key\s*=\s*["\'][^"\'\'\\n\\r]{16,}["\']',
            r'secret\s*=\s*["\'][^"\'\'\\n\\r]{16,}["\']',
            r'token\s*=\s*["\'][^"\'\'\\n\\r]{16,}["\']'
        ]
        
        for pattern in credential_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                issues.append({
                    'type': 'hardcoded_credentials',
                    'plugin': plugin_name,
                    'url': url,
                    'severity': 'High',
                    'description': 'Plugin may contain hardcoded credentials',
                    'pattern': pattern
                })
        
        return issues