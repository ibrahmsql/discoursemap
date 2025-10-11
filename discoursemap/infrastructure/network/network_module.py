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
        """
        Initialize the NetworkModule with a scanner and prepare the default results structure.
        
        Parameters:
            scanner: An object that provides a `target_url` attribute; used as the scan target and stored on the instance.
        """
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
        """
        Run a set of network security checks and collect their findings.
        
        Returns:
            results (Dict[str, Any]): Scan results containing:
                - module_name: name of the module
                - target: original target URL
                - open_ports: list of discovered open TCP ports (ints)
                - dns_info: dict with keys 'hostname' and 'ip' (if resolved)
                - network_vulns: list of identified network vulnerabilities
                - tests_performed: count of tests executed (int)
        """
        print(f"{Fore.CYAN}[*] Starting Network Security Scan...{Style.RESET_ALL}")
        
        # Test ports
        self._test_common_ports()
        
        # DNS lookup
        self._test_dns()
        
        print(f"{Fore.GREEN}[+] Network scan complete!{Style.RESET_ALL}")
        print(f"    Open ports: {len(self.results['open_ports'])}")
        
        return self.results
    
    def _test_common_ports(self):
        """
        Scan a subset of common TCP ports on the module's target and record any that are open.
        
        Parses the hostname from self.scanner.target_url, attempts a TCP connection to ports 21, 22, 80, and 443, appends any successfully reached ports to self.results['open_ports'], and increments self.results['tests_performed'] by 1. Connection errors are ignored and do not interrupt the scan.
        """
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
        """
        Resolve the target hostname to an IP address and record DNS information.
        
        On success, stores a dictionary {'hostname': <hostname>, 'ip': <ip>} in self.results['dns_info']. If DNS resolution fails, leaves dns_info unchanged. Always increments self.results['tests_performed'] by 1.
        """
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