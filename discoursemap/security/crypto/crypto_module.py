#!/usr/bin/env python3
"""
Discourse Cryptography Module (Refactored)

Cryptographic security testing.
Split from 971 lines into modular components.
"""

from typing import Dict, Any
from colorama import Fore, Style
from .ssl_tester import SSLTester


class CryptoModule:
    """Cryptography security module (Refactored)"""
    
    def __init__(self, scanner):
        """
        Initialize the CryptoModule with a scanner and prepare internal result containers.
        
        Stores the provided scanner, creates a results dictionary pre-populated with
        module metadata and empty structures for SSL configuration, encryption status,
        vulnerabilities, and recommendations, and instantiates an SSLTester for the scanner.
        
        Parameters:
            scanner: Scanner object containing target information (expects `target_url`).
        """
        self.scanner = scanner
        self.results = {
            'module_name': 'Cryptography',
            'target': scanner.target_url,
            'ssl_config': {},
            'encryption_status': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        self.ssl_tester = SSLTester(scanner)
    
    def run(self) -> Dict[str, Any]:
        """
        Run the module's cryptography/security checks and update the module results.
        
        Performs SSL/TLS testing via the module's SSL tester, aggregates any discovered vulnerabilities into self.results['vulnerabilities'], generates remediation recommendations, and emits progress messages to stdout.
        
        Returns:
            results (Dict[str, Any]): Aggregated scan results containing at least the keys
            `module_name`, `target`, `ssl_config`, `vulnerabilities`, and `recommendations`.
        """
        print(f"{Fore.CYAN}[*] Starting Cryptography Scan...{Style.RESET_ALL}")
        
        # Test SSL/TLS
        print(f"{Fore.YELLOW}[*] Testing SSL/TLS configuration...{Style.RESET_ALL}")
        self.results['ssl_config'] = self.ssl_tester.test_ssl_config()
        
        # Aggregate vulnerabilities
        if 'vulnerabilities' in self.results['ssl_config']:
            self.results['vulnerabilities'].extend(self.results['ssl_config']['vulnerabilities'])
        
        # Generate recommendations
        self._generate_recommendations()
        
        print(f"{Fore.GREEN}[+] Crypto scan complete!{Style.RESET_ALL}")
        print(f"    SSL/TLS: {'Enabled' if self.results['ssl_config'].get('https_enabled') else 'Disabled'}")
        print(f"    Vulnerabilities: {len(self.results['vulnerabilities'])}")
        
        return self.results
    
    def _generate_recommendations(self):
        """
        Add remediation recommendations based on the collected SSL/TLS configuration.
        
        If `https_enabled` in `self.results['ssl_config']` is falsy, append a critical recommendation to
        `self.results['recommendations']` with the keys `severity`, `issue`, and `recommendation`.
        The appended recommendation has:
        - `severity`: `'CRITICAL'`
        - `issue`: `'HTTPS not enabled'`
        - `recommendation`: `'Enable HTTPS immediately'`
        """
        if not self.results['ssl_config'].get('https_enabled'):
            self.results['recommendations'].append({
                'severity': 'CRITICAL',
                'issue': 'HTTPS not enabled',
                'recommendation': 'Enable HTTPS immediately'
            })