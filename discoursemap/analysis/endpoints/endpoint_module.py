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
        """Execute endpoint discovery"""
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
