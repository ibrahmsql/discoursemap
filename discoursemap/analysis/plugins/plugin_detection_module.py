#!/usr/bin/env python3
"""
Discourse Plugin Detection Module (Refactored)

Modular plugin and technology detection using fingerprinting techniques.
Split from 1902 lines into manageable components.
"""

import re
import json
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style
from ...lib.discourse_utils import make_request
from .plugin_signatures import get_plugin_signatures, get_technology_patterns
from .plugin_vulnerabilities import get_plugin_vulnerabilities, check_plugin_vulnerabilities


class PluginDetectionModule:
    """Modular plugin and technology detection module"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Plugin Detection',
            'target': scanner.target_url,
            'detected_plugins': [],
            'detected_themes': [],
            'technology_stack': [],
            'javascript_libraries': [],
            'css_frameworks': [],
            'server_info': {},
            'meta_information': {},
            'fingerprints': [],
            'vulnerability_plugins': [],
            'plugin_endpoints': []
        }
        
        # Load signatures and vulnerabilities from external modules
        self.plugin_signatures = get_plugin_signatures()
        self.plugin_vulnerabilities = get_plugin_vulnerabilities()
        self.tech_patterns = get_technology_patterns()
    
    def run(self):
        """Execute plugin detection scan"""
        print(f"{Fore.CYAN}[*] Starting Plugin Detection Scan...{Style.RESET_ALL}")
        
        # Step 1: Detect plugins
        self._detect_plugins_from_html()
        self._detect_plugins_from_api()
        self._detect_plugins_from_paths()
        
        # Step 2: Detect technologies
        self._detect_javascript_libraries()
        self._detect_css_frameworks()
        self._detect_server_technologies()
        
        # Step 3: Check vulnerabilities
        self._check_plugin_vulnerabilities()
        
        # Step 4: Gather meta information
        self._gather_meta_information()
        
        print(f"{Fore.GREEN}[+] Plugin detection complete!{Style.RESET_ALL}")
        print(f"    Plugins found: {len(self.results['detected_plugins'])}")
        print(f"    Vulnerable plugins: {len(self.results['vulnerability_plugins'])}")
        
        return self.results
    
    def _detect_plugins_from_html(self):
        """Detect plugins from HTML source"""
        try:
            response = make_request(self.scanner.target_url, timeout=10)
            if not response:
                return
            
            html = response.text
            soup = BeautifulSoup(html, 'html.parser')
            
            # Check for plugin signatures in HTML
            for plugin_name, signature in self.plugin_signatures.items():
                for marker in signature.get('markers', []):
                    if marker in html:
                        self.results['detected_plugins'].append({
                            'name': plugin_name,
                            'detection_method': 'html_marker',
                            'marker': marker,
                            'category': signature.get('category', 'unknown'),
                            'risk_level': signature.get('risk_level', 'unknown')
                        })
                        break
        except Exception as e:
            print(f"{Fore.RED}[!] Error detecting plugins from HTML: {e}{Style.RESET_ALL}")
    
    def _detect_plugins_from_api(self):
        """Detect plugins using Discourse API"""
        try:
            # Try to get site info
            site_url = urljoin(self.scanner.target_url, '/site.json')
            response = make_request(site_url, timeout=10)
            
            if response and response.status_code == 200:
                site_data = response.json()
                
                # Extract plugin information if available
                if 'plugins' in site_data:
                    for plugin in site_data['plugins']:
                        self.results['detected_plugins'].append({
                            'name': plugin.get('name', 'Unknown'),
                            'version': plugin.get('version', 'Unknown'),
                            'detection_method': 'api',
                            'enabled': plugin.get('enabled', True)
                        })
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not detect plugins via API: {e}{Style.RESET_ALL}")
    
    def _detect_plugins_from_paths(self):
        """Detect plugins by probing common paths"""
        for plugin_name, signature in self.plugin_signatures.items():
            for path in signature.get('paths', []):
                try:
                    url = urljoin(self.scanner.target_url, path)
                    response = make_request(url, timeout=5)
                    
                    if response and response.status_code == 200:
                        self.results['detected_plugins'].append({
                            'name': plugin_name,
                            'detection_method': 'path_probe',
                            'path': path,
                            'category': signature.get('category', 'unknown')
                        })
                        break
                except Exception:
                    continue
    
    def _detect_javascript_libraries(self):
        """Detect JavaScript libraries"""
        try:
            response = make_request(self.scanner.target_url, timeout=10)
            if not response:
                return
            
            html = response.text
            
            for lib_name, patterns in self.tech_patterns.items():
                if patterns.get('category') == 'javascript-library' or \
                   patterns.get('category') == 'javascript-framework':
                    for pattern in patterns.get('js_patterns', []):
                        if re.search(pattern, html, re.IGNORECASE):
                            self.results['javascript_libraries'].append({
                                'name': lib_name,
                                'detection_method': 'pattern_match',
                                'pattern': pattern
                            })
                            break
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error detecting JS libraries: {e}{Style.RESET_ALL}")
    
    def _detect_css_frameworks(self):
        """Detect CSS frameworks"""
        try:
            response = make_request(self.scanner.target_url, timeout=10)
            if not response:
                return
            
            html = response.text
            
            for framework_name, patterns in self.tech_patterns.items():
                if patterns.get('category') == 'css-framework':
                    for pattern in patterns.get('css_patterns', []):
                        if re.search(pattern, html, re.IGNORECASE):
                            self.results['css_frameworks'].append({
                                'name': framework_name,
                                'detection_method': 'pattern_match',
                                'pattern': pattern
                            })
                            break
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error detecting CSS frameworks: {e}{Style.RESET_ALL}")
    
    def _detect_server_technologies(self):
        """Detect server-side technologies from headers"""
        try:
            response = make_request(self.scanner.target_url, timeout=10)
            if not response:
                return
            
            headers = response.headers
            
            # Server header
            if 'Server' in headers:
                self.results['server_info']['server'] = headers['Server']
            
            # Powered-by header
            if 'X-Powered-By' in headers:
                self.results['server_info']['powered_by'] = headers['X-Powered-By']
            
            # Discourse-specific headers
            for header, value in headers.items():
                if 'discourse' in header.lower():
                    self.results['server_info'][header] = value
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error detecting server technologies: {e}{Style.RESET_ALL}")
    
    def _check_plugin_vulnerabilities(self):
        """Check detected plugins for known vulnerabilities"""
        for plugin in self.results['detected_plugins']:
            plugin_name = plugin.get('name', '')
            plugin_version = plugin.get('version', None)
            
            # Check vulnerabilities
            vulns = check_plugin_vulnerabilities(plugin_name, plugin_version)
            
            if vulns:
                self.results['vulnerability_plugins'].append({
                    'plugin_name': plugin_name,
                    'version': plugin_version,
                    'vulnerabilities': vulns,
                    'vulnerability_count': len(vulns)
                })
    
    def _gather_meta_information(self):
        """Gather meta information about the site"""
        try:
            response = make_request(self.scanner.target_url, timeout=10)
            if not response:
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Collect meta tags
            meta_tags = soup.find_all('meta')
            for tag in meta_tags:
                name = tag.get('name', tag.get('property', ''))
                content = tag.get('content', '')
                if name and content:
                    self.results['meta_information'][name] = content
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error gathering meta information: {e}{Style.RESET_ALL}")
