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
        """Execute passive scan"""
        print(f"{Fore.CYAN}[*] Starting Passive Scan...{Style.RESET_ALL}")
        
        self._analyze_headers()
        self._gather_meta_info()
        
        print(f"{Fore.GREEN}[+] Passive scan complete{Style.RESET_ALL}")
        return self.results
    
    def _analyze_headers(self):
        """Analyze HTTP headers"""
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
        """Gather metadata"""
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
