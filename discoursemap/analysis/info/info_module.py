#!/usr/bin/env python3
"""
Discourse Info Module (Refactored)

Information gathering - split from 580 lines.
"""

from typing import Dict, Any
from colorama import Fore, Style
from urllib.parse import urljoin


class InfoModule:
    """Information gathering (Refactored)"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Information Gathering',
            'target': scanner.target_url,
            'site_info': {},
            'version': None,
            'plugins': [],
            'stats': {}
        }
    
    def run(self) -> Dict[str, Any]:
        """Execute info gathering"""
        print(f"{Fore.CYAN}[*] Starting Information Gathering...{Style.RESET_ALL}")
        
        self._gather_site_info()
        self._detect_version()
        self._enumerate_plugins()
        
        print(f"{Fore.GREEN}[+] Info gathering complete{Style.RESET_ALL}")
        return self.results
    
    def _gather_site_info(self):
        """Gather basic site information"""
        try:
            import requests
            site_url = urljoin(self.scanner.target_url, '/site.json')
            response = requests.get(site_url, timeout=10)
            
            if response and response.status_code == 200:
                data = response.json()
                self.results['site_info'] = {
                    'title': data.get('title'),
                    'description': data.get('description'),
                    'default_locale': data.get('default_locale')
                }
        except:
            pass
    
    def _detect_version(self):
        """Detect Discourse version"""
        try:
            import requests
            about_url = urljoin(self.scanner.target_url, '/about.json')
            response = requests.get(about_url, timeout=10)
            
            if response and response.status_code == 200:
                data = response.json()
                about_data = data.get('about', {})
                self.results['version'] = about_data.get('version')
        except:
            pass
    
    def _enumerate_plugins(self):
        """Enumerate installed plugins"""
        try:
            import requests
            site_url = urljoin(self.scanner.target_url, '/site.json')
            response = requests.get(site_url, timeout=10)
            
            if response and response.status_code == 200:
                data = response.json()
                plugins = data.get('plugins', [])
                self.results['plugins'] = plugins
        except:
            pass
