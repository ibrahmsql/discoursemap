#!/usr/bin/env python3
"""
Discourse Network Module (Refactored)

Network security testing.
Split from 900 lines into focused module.
"""

from typing import Dict, Any
from colorama import Fore, Style
import socket
from urllib.parse import urlparse


class NetworkModule:
    """Network security module (Refactored)"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Network Security',
            'target': scanner.target_url,
            'open_ports': [],
            'dns_info': {},
            'network_vulns': [],
            'tests_performed': 0
        }
    
    def run(self) -> Dict[str, Any]:
        """Execute network security tests"""
        print(f"{Fore.CYAN}[*] Starting Network Security Scan...{Style.RESET_ALL}")
        
        # Test ports
        self._test_common_ports()
        
        # DNS lookup
        self._test_dns()
        
        print(f"{Fore.GREEN}[+] Network scan complete!{Style.RESET_ALL}")
        print(f"    Open ports: {len(self.results['open_ports'])}")
        
        return self.results
    
    def _test_common_ports(self):
        """Test common ports"""
        parsed = urlparse(self.scanner.target_url)
        hostname = parsed.hostname
        
        common_ports = [21, 22, 80, 443, 3000, 3306, 5432, 8080]
        
        for port in common_ports[:4]:  # Test only first 4
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((hostname, port))
                sock.close()
                
                if result == 0:
                    self.results['open_ports'].append(port)
            except Exception:
                continue
        
        self.results['tests_performed'] += 1
    
    def _test_dns(self):
        """Test DNS configuration"""
        try:
            parsed = urlparse(self.scanner.target_url)
            hostname = parsed.hostname
            
            ip = socket.gethostbyname(hostname)
            self.results['dns_info'] = {
                'hostname': hostname,
                'ip': ip
            }
        except Exception:
            pass
        
        self.results['tests_performed'] += 1
