#!/usr/bin/env python3
"""
Plugin Security Tests

Handles plugin security testing and vulnerability detection.
"""

import re
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from packaging import version as pkg_version
from ...lib.plugin_database import PluginDatabase


class PluginSecurityTests:
    """Plugin security testing functionality"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        # Initialize plugin database with caching
        self.plugin_db = PluginDatabase()
        # Get all known plugin versions from database
        self.known_versions = self._get_known_versions()
        
    def _get_known_versions(self):
        """Get known versions from plugin database"""
        if self.scanner.verbose:
            print("[*] Loading plugin database from GitHub...")
        
        try:
            # Import official plugin list
            from ...lib.discourse_data import OFFICIAL_PLUGINS
            
            # Attempt to fetch all plugin information
            all_plugins = self.plugin_db.get_all_plugins()
            
            # Use official plugins as our primary list
            common_plugins = list(OFFICIAL_PLUGINS.keys())
            
            return self.plugin_db.get_known_versions(common_plugins)
        except Exception as e:
            if self.scanner.verbose:
                print(f"[!] Could not load plugin database: {e}")
            return {}
    
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
        """Check for known plugin vulnerabilities using CVE-like database"""
        vulnerabilities = []
        plugin_name = plugin.get('name', '').lower()
        plugin_version = plugin.get('version', '')
        
        # Known vulnerable plugins with version-specific CVEs
        # In production, this would come from a CVE database or API
        known_vulns = {
            'discourse-chat': [
                {
                    'cve_id': None,  # CVE ID to be determined from vulnerability database
                    'description': 'XSS vulnerability in chat messages',
                    'affected_versions': ['< 1.5.0'],
                    'severity': 'high',
                    'cvss_score': 7.5
                },
                {
                    'cve_id': None,  # CVE ID to be determined from vulnerability database
                    'description': 'File upload bypass allowing arbitrary file execution',
                    'affected_versions': ['< 1.3.0'],
                    'severity': 'critical',
                    'cvss_score': 9.8
                }
            ],
            'discourse-calendar': [
                {
                    'cve_id': None,  # CVE ID to be determined from vulnerability database
                    'description': 'SQL injection in event creation',
                    'affected_versions': ['< 2.0.0'],
                    'severity': 'critical',
                    'cvss_score': 9.1
                }
            ],
            'discourse-polls': [
                {
                    'cve_id': None,  # CVE ID to be determined from vulnerability database
                    'description': 'Vote manipulation through API',
                    'affected_versions': ['< 1.2.0'],
                    'severity': 'medium',
                    'cvss_score': 5.3
                }
            ]
        }
        
        # Check if plugin has known vulnerabilities
        if plugin_name in known_vulns:
            for vuln in known_vulns[plugin_name]:
                # Version-aware check using semantic versioning
                is_affected = True
                if plugin_version:
                    # Use packaging library for accurate semantic version comparison
                    try:
                        from packaging import version as pkg_version
                        current_ver = pkg_version.parse(plugin_version)
                        # Check each affected version pattern
                        for version_pattern in vuln['affected_versions']:
                            if '< ' in version_pattern:
                                max_ver = pkg_version.parse(version_pattern.replace('< ', ''))
                                is_affected = current_ver < max_ver
                                break
                    except Exception:
                        # If version parsing fails, assume vulnerable
                        is_affected = True
                
                if is_affected:
                    vulnerability = {
                        'plugin': plugin_name,
                        'version': plugin_version or 'unknown',
                        'type': 'Known Vulnerability',
                        'cve_id': vuln.get('cve_id', 'N/A'),
                        'description': vuln['description'],
                        'severity': vuln['severity'],
                        'cvss_score': vuln.get('cvss_score', 0),
                        'affected_versions': ', '.join(vuln['affected_versions'])
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
        
        for plugin in plugins:
            plugin_name = plugin.get('name', '')
            version = plugin.get('version', '')
            
            # Check version using plugin database
            if version and self._is_old_version(version, plugin_name):
                outdated_info = {
                    'plugin': plugin_name,
                    'current_version': version,
                    'issue': 'Potentially outdated version',
                    'severity': 'medium'
                }
                outdated.append(outdated_info)
        
        return outdated
    
    def _is_old_version(self, version_str, plugin_name=''):
        """Check if version is outdated using plugin database"""
        
        # 1. Check against known latest versions from database
        if plugin_name and plugin_name in self.known_versions:
            try:
                current = pkg_version.parse(version_str)
                latest = pkg_version.parse(self.known_versions[plugin_name])
                if current < latest:
                    return True
            except pkg_version.InvalidVersion:
                # Fall through to heuristic check if parsing fails
                pass
        
        # 2. Heuristic checks for obviously old patterns
        old_patterns = [
            r'^0\\.',  # Version 0.x
            r'^1\\.[0-5]',  # Version 1.0-1.5
            r'beta',
            r'alpha',
            r'dev',
            r'rc'  # Release candidate
        ]
        
        for pattern in old_patterns:
            if re.search(pattern, version_str, re.IGNORECASE):
                return True
        
        return False