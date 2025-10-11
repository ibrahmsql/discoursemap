#!/usr/bin/env python3
"""
Discourse Passive Scanner Module (Refactored)

Passive information gathering - split from 633 lines.
"""

from typing import Dict, Any
from colorama import Fore, Style
from urllib.parse import urljoin


class PassiveScannerModule:
    """Passive scanning (Refactored)"""
    
    def __init__(self, scanner):
        """
        Initialize the PassiveScannerModule and prepare its results container.
        
        Creates the module with a reference to the provided scanner and initializes `self.results` with keys:
        `module_name` (module identifier), `target` (the scanner's target_url), `headers` (dict for HTTP headers),
        `meta_info` (dict for site meta information), `technologies` (list of detected technologies), and `findings` (list of discovered issues).
        
        Parameters:
            scanner: An object that exposes a `target_url` attribute representing the target to scan.
        """
        self.scanner = scanner
        self.results = {
            'module_name': 'Passive Scanner',
            'target': scanner.target_url,
            'headers': {},
            'meta_info': {},
            'technologies': [],
            'findings': []
        }
    
    def run(self) -> Dict[str, Any]:
        """
        Run the module's passive scan and aggregate findings.
        
        Performs passive information gathering steps and accumulates results for the configured target.
        
        Returns:
            results (Dict[str, Any]): Aggregated scan data containing keys:
                - module_name: name of the module
                - target: scanned target URL
                - headers: collected HTTP headers (dict)
                - meta_info: discovered site metadata (dict)
                - technologies: detected technologies (list)
                - findings: recorded findings (list)
        """
        print(f"{Fore.CYAN}[*] Starting Passive Scan...{Style.RESET_ALL}")
        
        self._analyze_headers()
        self._gather_meta_info()
        
        print(f"{Fore.GREEN}[+] Passive scan complete{Style.RESET_ALL}")
        return self.results
    
    def _analyze_headers(self):
        """
        Analyze HTTP response headers for the target and record results.
        
        Populates self.results['headers'] with the response headers (if any) and appends a finding to self.results['findings'] for each missing important security header. The security headers checked are: `strict-transport-security`, `content-security-policy`, and `x-frame-options`. Exceptions during the request are suppressed and leave results unchanged.
        """
        try:
            import requests
            response = requests.get(self.scanner.target_url, timeout=10)
            
            if response:
                self.results['headers'] = dict(response.headers)
                
                # Check for security headers
                security_headers = [
                    'strict-transport-security',
                    'content-security-policy',
                    'x-frame-options'
                ]
                
                for header in security_headers:
                    if header not in response.headers:
                        self.results['findings'].append({
                            'type': 'Missing Security Header',
                            'header': header,
                            'severity': 'medium'
                        })
        except:
            pass
    
    def _gather_meta_info(self):
        """
        Retrieve site metadata from /site.json and store it in the module results.
        
        If a JSON document is successfully fetched with HTTP status 200, extracts the
        `title`, `version`, and `description` fields and stores them in
        `self.results['meta_info']`. Network, HTTP, or JSON parsing errors are silently
        ignored and leave `self.results['meta_info']` unchanged.
        """
        try:
            import requests
            site_url = urljoin(self.scanner.target_url, '/site.json')
            response = requests.get(site_url, timeout=10)
            
            if response and response.status_code == 200:
                data = response.json()
                self.results['meta_info'] = {
                    'title': data.get('title'),
                    'version': data.get('version'),
                    'description': data.get('description')
                }
        except:
            pass