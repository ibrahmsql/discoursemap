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
        """
        Initialize the PluginDetectionModule with a scanner and prepare internal state for detection.
        
        Sets the scanner reference, constructs the results scaffold (including target, detected items, technology lists, server and meta info, fingerprints, and vulnerability records), and loads plugin signatures, plugin vulnerability data, and technology detection patterns from external helpers.
        
        Parameters:
            scanner: Scanner-like object exposing `target_url`, used as the detection target and stored on the instance.
        """
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
        """
        Orchestrates the end-to-end plugin and technology detection workflow for the configured target.
        
        Performs plugin discovery (HTML markers, Site JSON API, and path probing), technology fingerprinting (JavaScript libraries, CSS frameworks, and server headers), vulnerability enrichment for detected plugins, and collection of page meta tags.
        
        Returns:
            results (dict): Aggregated detection payload containing detected plugins, technologies, library/framework findings, server information, plugin vulnerability details, meta information, and related metadata.
        """
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
        """
        Scan the target page HTML for known plugin markers and record any matches.
        
        Fetches the target URL, checks the page HTML for each configured plugin signature marker, and appends matching plugin entries to self.results['detected_plugins'] with the following fields: name, detection_method ('html_marker'), marker, category, and risk_level.
        """
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
        """
        Detect plugins advertised by the target site's Site JSON API.
        
        Queries the target's /site.json endpoint and, if a 200 response with a `plugins` list is returned, appends each plugin to `self.results['detected_plugins']` with keys: `name` (defaults to "Unknown"), `version` (defaults to "Unknown"), `detection_method` set to `"api"`, and `enabled` (defaults to True). If the API is unavailable or an error occurs, a warning is printed and detection is skipped.
        """
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
        """
        Probe common plugin paths on the target site and record any plugins found in self.results['detected_plugins'].
        
        Each successful probe (HTTP 200) appends a detection entry with keys: 'name', 'detection_method' ('path_probe'), 'path', and 'category' (defaults to 'unknown'). The method stops probing further paths for a plugin after the first successful hit and ignores individual probe errors.
        """
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
        """
        Detect JavaScript libraries and frameworks referenced by the target page and record matches to results.
        
        Scans the target page HTML for configured JavaScript detection patterns whose category is 'javascript-library' or 'javascript-framework'. For each pattern match, appends a record to self.results['javascript_libraries'] containing the library name, detection_method ('pattern_match'), and the matching pattern.
        """
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
        """
        Detects CSS frameworks used by the target site by matching known CSS patterns against the page HTML.
        
        Scans the target page HTML for patterns categorized as "css-framework" in the module's technology patterns and appends each detected framework to self.results['css_frameworks'] as a dictionary with keys: 'name', 'detection_method' (set to 'pattern_match'), and 'pattern'. If the target page cannot be retrieved, the method returns without modifying results. Exceptions are caught and logged; no exceptions are propagated.
        """
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
        """
        Populate self.results['server_info'] with server-side technology indicators discovered from HTTP response headers of the target URL.
        
        Specifically, if present the `Server` header is stored under `server`, the `X-Powered-By` header is stored under `powered_by`, and any header whose name contains "discourse" (case-insensitive) is stored using its header name as the key. If the HTTP request yields no response, `server_info` is left unchanged.
        """
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
        """
        Populate detected plugins with known vulnerability data.
        
        For each plugin in self.results['detected_plugins'], retrieve any known vulnerabilities and append an entry to self.results['vulnerability_plugins']. Each appended entry contains:
            - 'plugin_name': the plugin's name
            - 'version': the plugin's version (or None if unavailable)
            - 'vulnerabilities': a list of vulnerability records
            - 'vulnerability_count': number of vulnerabilities found
        """
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
        """
        Collect meta tag name/property and content pairs from the target page into the results payload.
        
        Parses the target page and stores each meta tag's identifier (prefers the `name` attribute, then `property`) mapped to its `content` in `self.results['meta_information']`. Only meta tags with both an identifier and non-empty content are recorded.
        """
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