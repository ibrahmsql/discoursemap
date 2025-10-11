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
        """Execute crypto security tests"""
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
        """Generate crypto recommendations"""
        if not self.results['ssl_config'].get('https_enabled'):
            self.results['recommendations'].append({
                'severity': 'CRITICAL',
                'issue': 'HTTPS not enabled',
                'recommendation': 'Enable HTTPS immediately'
            })
