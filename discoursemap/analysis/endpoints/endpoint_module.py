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
        Initialize the EndpointModule with a scanner and prepare internal state for endpoint discovery.
        
        Parameters:
            scanner: An object providing a `target_url` attribute; used to target scans and create an internal EndpointScanner.
        
        Details:
            Sets instance attributes `scanner`, `endpoint_scanner`, and `results`. `results` is initialized with keys:
            `module_name`, `target`, `endpoints_found`, `accessible_endpoints`, `vulnerabilities`, and `total_scanned`.
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
        Perform a targeted scan of common Discourse endpoints and aggregate the findings.
        
        Returns:
            results (Dict[str, Any]): Dictionary containing:
                - module_name (str): Name of the module ("Endpoint Discovery").
                - target (str): Scanned target URL.
                - endpoints_found (list): Raw scan results for each probed endpoint.
                - accessible_endpoints (list): Subset of `endpoints_found` marked as accessible.
                - vulnerabilities (list): Collected vulnerabilities (may be empty).
                - total_scanned (int): Number of endpoints that were probed.
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