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
        Initialize the InfoModule with a scanner and prepare the default results structure.
        
        Stores the provided scanner on the instance and initializes `self.results` with the following keys:
        - `module_name`: "Information Gathering"
        - `target`: value taken from `scanner.target_url`
        - `site_info`: empty dict for site metadata
        - `version`: `None` until detected
        - `plugins`: empty list for discovered plugins
        - `stats`: empty dict for module statistics
        
        Parameters:
            scanner: An object providing a `target_url` attribute used as the scan target.
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
        Orchestrates collection of site metadata, Discourse version, and installed plugins for the configured target.
        
        Returns:
            results (Dict[str, Any]): Aggregated information with keys: `module_name`, `target`, `site_info`, `version`, `plugins`, and `stats`.
        """
        print(f"{Fore.CYAN}[*] Starting Information Gathering...{Style.RESET_ALL}")
        
        self._gather_site_info()
        self._detect_version()
        self._enumerate_plugins()
        
        print(f"{Fore.GREEN}[+] Info gathering complete{Style.RESET_ALL}")
        return self.results
    
    def _gather_site_info(self):
        """
        Gather basic site information from the target and populate self.results['site_info'].
        
        If the target exposes a `/site.json` with relevant fields, sets the keys
        `'title'`, `'description'`, and `'default_locale'` in `self.results['site_info']`.
        Errors during retrieval or parsing are silently ignored.
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
        Detects the Discourse version for the configured target and stores it in self.results['version'].
        
        If the target exposes an about.json with an `about.version` field, that value is stored; otherwise `self.results['version']` is left unchanged.
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
        Fetch the target's /site.json and populate self.results['plugins'] with the site's plugins list.
        
        Attempts a GET to the target's /site.json endpoint and, if a 200 response with JSON is returned, sets self.results['plugins'] to the value of the JSON `plugins` field (defaults to an empty list if missing). Any exceptions are suppressed and the method does not return a value.
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