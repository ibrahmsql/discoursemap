#!/usr/bin/env python3
"""
Plugin Security Tests

Handles plugin security testing and vulnerability detection.
"""

import re
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup


class PluginSecurityTests:
    """Plugin security testing functionality"""
    
    def __init__(self, scanner):
        self.scanner = scanner
    
    def test_plugin_vulnerabilities(self, plugins):
        """Test for plugin vulnerabilities"""
        vulnerabilities = []
        
        for plugin in plugins:
            plugin_name = plugin.get('name', '')
            
            # Test for common plugin vulnerabilities
            vulns = self._check_plugin_vulns(plugin)
            vulnerabilities.extend(vulns)
            
            # Test plugin file access
            file_access = self._test_plugin_file_access(plugin)
            if file_access:
                vulnerabilities.extend(file_access)
            
            # Test plugin permissions
            perms = self._test_plugin_permissions(plugin)
            if perms:
                vulnerabilities.extend(perms)
        
        return vulnerabilities
    
    def test_theme_vulnerabilities(self, themes):
        """Test for theme vulnerabilities"""
        vulnerabilities = []
        
        for theme in themes:
            theme_name = theme.get('name', '')
            
            # Test for theme injection
            injection = self._test_theme_injection(theme)
            if injection:
                vulnerabilities.extend(injection)
            
            # Test theme file access
            file_access = self._test_theme_file_access(theme)
            if file_access:
                vulnerabilities.extend(file_access)
        
        return vulnerabilities
    
    def _check_plugin_vulns(self, plugin):
        """Check for known plugin vulnerabilities"""
        vulnerabilities = []
        plugin_name = plugin.get('name', '').lower()
        
        # Known vulnerable plugins (simplified list)
        known_vulns = {
            'discourse-chat': ['XSS in chat messages', 'File upload bypass'],
            'discourse-calendar': ['SQL injection in events', 'CSRF in calendar'],
            'discourse-polls': ['Vote manipulation', 'XSS in poll options'],
            'discourse-solved': ['Privilege escalation', 'Solution bypass'],
            'discourse-assign': ['Assignment bypass', 'Notification spam']
        }
        
        for vuln_plugin, vulns in known_vulns.items():
            if vuln_plugin in plugin_name:
                for vuln in vulns:
                    vulnerability = {
                        'plugin': plugin_name,
                        'type': 'Known Vulnerability',
                        'description': vuln,
                        'severity': 'high'
                    }
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _test_plugin_file_access(self, plugin):
        """Test plugin file access vulnerabilities"""
        vulnerabilities = []
        plugin_name = plugin.get('name', '').lower().replace(' ', '-')
        
        # Test file access endpoints
        file_endpoints = [
            f'/plugins/{plugin_name}/files/',
            f'/plugins/{plugin_name}/assets/',
            f'/plugins/{plugin_name}/uploads/',
            f'/admin/plugins/{plugin_name}/files/'
        ]
        
        for endpoint in file_endpoints:
            try:
                url = urljoin(self.scanner.target_url, endpoint)
                response = self.scanner.make_request(url)
                
                if response and response.status_code == 200:
                    # Check if directory listing is enabled
                    if 'Index of' in response.text or '<title>Directory listing' in response.text:
                        vulnerability = {
                            'plugin': plugin_name,
                            'type': 'Directory Listing',
                            'endpoint': endpoint,
                            'description': f'Plugin directory listing exposed at {endpoint}',
                            'severity': 'medium'
                        }
                        vulnerabilities.append(vulnerability)
                
            except Exception:
                continue
        
        return vulnerabilities
    
    def _test_plugin_permissions(self, plugin):
        """Test plugin permission issues"""
        vulnerabilities = []
        plugin_name = plugin.get('name', '').lower().replace(' ', '-')
        
        # Test admin endpoints without authentication
        admin_endpoints = [
            f'/admin/plugins/{plugin_name}/settings',
            f'/admin/plugins/{plugin_name}/config',
            f'/admin/plugins/{plugin_name}/users'
        ]
        
        for endpoint in admin_endpoints:
            try:
                url = urljoin(self.scanner.target_url, endpoint)
                response = self.scanner.make_request(url)
                
                if response and response.status_code == 200:
                    vulnerability = {
                        'plugin': plugin_name,
                        'type': 'Permission Bypass',
                        'endpoint': endpoint,
                        'description': f'Plugin admin endpoint accessible without authentication: {endpoint}',
                        'severity': 'high'
                    }
                    vulnerabilities.append(vulnerability)
                
            except Exception:
                continue
        
        return vulnerabilities
    
    def _test_theme_injection(self, theme):
        """Test theme injection vulnerabilities"""
        vulnerabilities = []
        theme_id = theme.get('id', '')
        theme_name = theme.get('name', '')
        
        if not theme_id:
            return vulnerabilities
        
        # Test theme customization endpoints
        try:
            # Test theme CSS injection
            css_url = urljoin(self.scanner.target_url, f'/theme-javascripts/{theme_id}.js')
            response = self.scanner.make_request(css_url)
            
            if response and response.status_code == 200:
                # Check for potential XSS in theme JS
                dangerous_patterns = [
                    r'document\.write\(',
                    r'innerHTML\s*=',
                    r'eval\(',
                    r'setTimeout\(["\']',
                    r'setInterval\(["\']'
                ]
                
                for pattern in dangerous_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerability = {
                            'theme': theme_name,
                            'type': 'Theme XSS',
                            'pattern': pattern,
                            'description': f'Potential XSS pattern found in theme JavaScript: {pattern}',
                            'severity': 'high'
                        }
                        vulnerabilities.append(vulnerability)
            
        except Exception:
            pass
        
        return vulnerabilities
    
    def _test_theme_file_access(self, theme):
        """Test theme file access vulnerabilities"""
        vulnerabilities = []
        theme_id = theme.get('id', '')
        theme_name = theme.get('name', '')
        
        if not theme_id:
            return vulnerabilities
        
        # Test theme file endpoints
        file_endpoints = [
            f'/uploads/theme/{theme_id}/',
            f'/theme-uploads/{theme_id}/',
            f'/admin/themes/{theme_id}/assets/'
        ]
        
        for endpoint in file_endpoints:
            try:
                url = urljoin(self.scanner.target_url, endpoint)
                response = self.scanner.make_request(url)
                
                if response and response.status_code == 200:
                    # Check if directory listing is enabled
                    if 'Index of' in response.text or '<title>Directory listing' in response.text:
                        vulnerability = {
                            'theme': theme_name,
                            'type': 'Directory Listing',
                            'endpoint': endpoint,
                            'description': f'Theme directory listing exposed at {endpoint}',
                            'severity': 'medium'
                        }
                        vulnerabilities.append(vulnerability)
                
            except Exception:
                continue
        
        return vulnerabilities
    
    def check_outdated_plugins(self, plugins):
        """Check for outdated plugins"""
        outdated = []
        
        # This would typically check against a database of known versions
        # For now, we'll do basic checks
        for plugin in plugins:
            plugin_name = plugin.get('name', '')
            version = plugin.get('version', '')
            
            # Simple version check (in real implementation, this would be more sophisticated)
            if version and self._is_old_version(version):
                outdated_info = {
                    'plugin': plugin_name,
                    'current_version': version,
                    'issue': 'Potentially outdated version',
                    'severity': 'medium'
                }
                outdated.append(outdated_info)
        
        return outdated
    
    def _is_old_version(self, version):
        """Simple check for old version patterns"""
        # Very basic check - in reality this would be more sophisticated
        old_patterns = [
            r'^0\.',  # Version 0.x
            r'^1\.[0-5]',  # Version 1.0-1.5
            r'beta',
            r'alpha',
            r'dev'
        ]
        
        for pattern in old_patterns:
            if re.search(pattern, version, re.IGNORECASE):
                return True
        
        return False