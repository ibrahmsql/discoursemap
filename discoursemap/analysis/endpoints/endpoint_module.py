#!/usr/bin/env python3
"""
Discourse Endpoint Module (Refactored)

Endpoint discovery and testing - split from 943 lines.
"""

from typing import Dict, Any
from colorama import Fore, Style
from .endpoint_scanner import EndpointScanner


class EndpointModule:
    """Endpoint security module (Refactored)"""
    
    def __init__(self, scanner):
        """
        Initialize EndpointModule state using the provided scanner.
        
        Parameters:
            scanner: An object that provides `target_url`. Its `target_url` is used to create an EndpointScanner and to populate the module's `results['target']`. The initializer also stores the scanner on the instance, creates `self.endpoint_scanner`, and initializes `self.results` with default keys for discovered and accessible endpoints, vulnerabilities, and scan count.
        """
        self.scanner = scanner
        self.endpoint_scanner = EndpointScanner(scanner.target_url)
        self.results = {
            'module_name': 'Endpoint Discovery',
            'target': scanner.target_url,
            'endpoints_found': [],
            'accessible_endpoints': [],
            'vulnerabilities': [],
            'total_scanned': 0
        }
    
    def run(self) -> Dict[str, Any]:
        """
        Discover common Discourse endpoints on the target and collect scan results.
        
        Scans a predefined list of Discourse endpoints, records the scan responses, filters accessible endpoints, updates the total scanned count, and stores these in the module results.
        
        Returns:
            results (Dict[str, Any]): Module results containing keys:
                - 'module_name': name of the module
                - 'target': target URL
                - 'endpoints_found': list of scan result entries for each tested endpoint
                - 'accessible_endpoints': subset of `endpoints_found` marked as accessible
                - 'vulnerabilities': list of discovered vulnerabilities (may be empty)
                - 'total_scanned': number of endpoints tested
        """
        print(f"{Fore.CYAN}[*] Starting Endpoint Discovery...{Style.RESET_ALL}")
        
        # Common Discourse endpoints
        endpoints = [
            '/about.json', '/site.json', '/categories.json',
            '/badges.json', '/groups.json', '/users.json',
            '/admin', '/admin/users', '/admin/plugins',
            '/uploads', '/session', '/invites'
        ]
        
        results = self.endpoint_scanner.scan_multiple(endpoints)
        self.results['endpoints_found'] = results
        self.results['accessible_endpoints'] = [r for r in results if r.get('accessible')]
        self.results['total_scanned'] = len(endpoints)
        
        print(f"{Fore.GREEN}[+] Found {len(self.results['accessible_endpoints'])} accessible endpoints{Style.RESET_ALL}")
        
        return self.results