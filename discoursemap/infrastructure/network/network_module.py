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
        Initialize the NetworkModule with a scanner and prepare the initial results structure.
        
        Parameters:
            scanner: An object representing the scan controller; must provide a `target_url` attribute used to populate the results' `target` field.
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
        Run the network security checks for the configured scanner.
        
        Runs the module's common port checks and DNS lookup, updating the internal results store.
        Individual test failures are ignored and tests_performed is incremented for each attempted test.
        
        Returns:
            results (Dict[str, Any]): Result dictionary with keys `module_name`, `target`, `open_ports`,
            `dns_info`, `network_vulns`, and `tests_performed`.
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
        Check a subset of common TCP ports on the module's target hostname and record any that are open.
        
        This method parses the scanner's target URL to obtain the hostname, tests the first four ports from a predefined common-ports list, appends any open ports to `self.results['open_ports']`, and increments `self.results['tests_performed']` by 1.
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
        Resolve the target URL's hostname to an IP address and record DNS information.
        
        Parses the scanner's target_url to obtain the hostname, attempts DNS resolution, and stores a dictionary {'hostname': <hostname>, 'ip': <ip>} in self.results['dns_info'] if successful. If resolution fails, dns_info is left unchanged. In all cases, increments self.results['tests_performed'] by 1.
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