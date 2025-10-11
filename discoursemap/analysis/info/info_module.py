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
        """
        Initialize the InfoModule and prepare the results container.
        
        Parameters:
            scanner: Object providing the target_url and any scanning utilities used by the module. The instance's results dictionary is initialized with keys: module_name, target (from scanner.target_url), site_info, version, plugins, and stats.
        """
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
        """
        Run the information-gathering workflow for the configured scanner target.
        
        Collects site metadata, detects the Discourse version, and enumerates installed plugins, aggregating results into the module's results dictionary.
        
        Returns:
            dict: Aggregated results containing keys 'module_name', 'target', 'site_info', 'version', 'plugins', and 'stats'.
        """
        print(f"{Fore.CYAN}[*] Starting Information Gathering...{Style.RESET_ALL}")
        
        self._gather_site_info()
        self._detect_version()
        self._enumerate_plugins()
        
        print(f"{Fore.GREEN}[+] Info gathering complete{Style.RESET_ALL}")
        return self.results
    
    def _gather_site_info(self):
        """
        Gather basic site metadata from the target's /site.json and store it in self.results['site_info'].
        
        If the request succeeds with HTTP 200, extract 'title', 'description', and 'default_locale' from the JSON and assign them to results['site_info']. On any error or non-200 response, leave results['site_info'] unchanged.
        """
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
        """
        Detect the Discourse version of the target site and store it in self.results['version'].
        
        Fetches '/about.json' from the scanner target and, if the response contains an 'about.version' value, assigns it to self.results['version']. On network errors, parse errors, or if the value is missing, leaves self.results['version'] unchanged.
        """
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
        """
        Fetch and store the site's declared plugins.
        
        Attempts to GET the target site's /site.json and, if the response is HTTP 200 and contains a 'plugins' list, assigns that list to self.results['plugins']. Network, parsing, or other errors are caught and ignored, leaving results['plugins'] unchanged on failure.
        """
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