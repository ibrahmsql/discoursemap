#!/usr/bin/env python3
"""
Network Tools Module

Network utilities and connectivity testing tools.
"""

import socket
import requests
import time
import re
from typing import Dict, List, Optional, Any, Tuple
from colorama import Fore, Style
import subprocess
import platform


class NetworkTools:
    """Network connectivity and testing utilities"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def check_port_connectivity(self, host: str, ports: List[int], timeout: int = 5) -> Dict[str, Any]:
        """Check connectivity to specific ports"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking port connectivity for {host}...{Style.RESET_ALL}")
        
        results = {}
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                start_time = time.time()
                result = sock.connect_ex((host, port))
                end_time = time.time()
                
                sock.close()
                
                results[port] = {
                    'open': result == 0,
                    'response_time': end_time - start_time,
                    'status': 'open' if result == 0 else 'closed'
                }
                
            except Exception as e:
                results[port] = {
                    'open': False,
                    'error': str(e),
                    'status': 'error'
                }
        
        return {
            'host': host,
            'ports_tested': len(ports),
            'open_ports': len([p for p in results.values() if p.get('open', False)]),
            'results': results
        }
    
    def trace_route(self, target: str, max_hops: int = 30) -> Dict[str, Any]:
        """Perform traceroute to target"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Tracing route to {target}...{Style.RESET_ALL}")
        
        try:
            # Determine OS and use appropriate command
            system = platform.system().lower()
            
            if system == 'windows':
                cmd = ['tracert', '-h', str(max_hops), target]
            else:
                cmd = ['traceroute', '-m', str(max_hops), target]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=60
            )
            
            return {
                'target': target,
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }
            
        except subprocess.TimeoutExpired:
            return {
                'target': target,
                'success': False,
                'error': 'Traceroute timed out'
            }
        except Exception as e:
            return {
                'target': target,
                'success': False,
                'error': str(e)
            }
    
    def dns_lookup(self, hostname: str) -> Dict[str, Any]:
        """Perform DNS lookup"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Performing DNS lookup for {hostname}...{Style.RESET_ALL}")
        
        try:
            # Get IP address
            ip_address = socket.gethostbyname(hostname)
            
            # Try to get additional info
            try:
                host_info = socket.gethostbyaddr(ip_address)
                canonical_name = host_info[0]
                aliases = host_info[1]
            except (socket.herror, socket.gaierror, OSError):
                canonical_name = None
                aliases = []
            
            return {
                'hostname': hostname,
                'ip_address': ip_address,
                'canonical_name': canonical_name,
                'aliases': aliases,
                'success': True
            }
            
        except Exception as e:
            return {
                'hostname': hostname,
                'success': False,
                'error': str(e)
            }
    
    def check_ssl_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Check SSL certificate information"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking SSL certificate for {hostname}:{port}...{Style.RESET_ALL}")
        
        try:
            import ssl
            
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'hostname': hostname,
                        'port': port,
                        'valid': True,
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter']
                    }
                    
        except Exception as e:
            return {
                'hostname': hostname,
                'port': port,
                'valid': False,
                'error': str(e)
            }
    
    def bandwidth_test(self, url: str, test_duration: int = 10) -> Dict[str, Any]:
        """Simple bandwidth test"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Running bandwidth test to {url}...{Style.RESET_ALL}")
        
        try:
            start_time = time.time()
            total_bytes = 0
            
            session = requests.Session()
            
            while time.time() - start_time < test_duration:
                response = session.get(url, timeout=5)
                total_bytes += len(response.content)
            
            actual_duration = time.time() - start_time
            
            # Calculate bandwidth in various units
            bytes_per_second = total_bytes / actual_duration
            kilobytes_per_second = bytes_per_second / 1024
            megabytes_per_second = kilobytes_per_second / 1024
            
            return {
                'url': url,
                'test_duration': actual_duration,
                'total_bytes': total_bytes,
                'bytes_per_second': bytes_per_second,
                'kilobytes_per_second': kilobytes_per_second,
                'megabytes_per_second': megabytes_per_second,
                'success': True
            }
            
        except Exception as e:
            return {
                'url': url,
                'success': False,
                'error': str(e)
            }
    
    def ping_test(self, host: str, count: int = 4) -> Dict[str, Any]:
        """Perform ping test"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Pinging {host} ({count} times)...{Style.RESET_ALL}")
        
        try:
            system = platform.system().lower()
            
            if system == 'windows':
                cmd = ['ping', '-n', str(count), host]
            else:
                cmd = ['ping', '-c', str(count), host]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            
            # Parse ping results with advanced regex
            output_lines = result.stdout.split('\n')
            
            # Initialize stats
            stats = {
                'packets_sent': count,
                'packets_received': 0,
                'packet_loss_percent': 100.0,
                'latency_min': None,
                'latency_avg': None,
                'latency_max': None,
                'latency_stddev': None
            }
            
            # Platform-specific parsing
            if platform.system() == 'Windows':
                # Windows ping format
                for line in output_lines:
                    # Packet statistics: Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)
                    if 'Received' in line and 'Lost' in line:
                        match = re.search(r'Received\s*=\s*(\d+).*\((\d+)%', line)
                        if match:
                            stats['packets_received'] = int(match.group(1))
                            stats['packet_loss_percent'] = float(match.group(2))
                    
                    # Minimum = 1ms, Maximum = 2ms, Average = 1ms
                    if 'Minimum' in line and 'Average' in line:
                        match = re.search(r'Minimum\s*=\s*(\d+)ms.*Maximum\s*=\s*(\d+)ms.*Average\s*=\s*(\d+)ms', line)
                        if match:
                            stats['latency_min'] = float(match.group(1))
                            stats['latency_max'] = float(match.group(2))
                            stats['latency_avg'] = float(match.group(3))
            else:
                # macOS/Linux ping format
                for line in output_lines:
                    # 4 packets transmitted, 4 packets received, 0.0% packet loss
                    if 'packets transmitted' in line:
                        match = re.search(r'(\d+) packets transmitted, (\d+).*received.*?([\d.]+)% packet loss', line)
                        if match:
                            stats['packets_sent'] = int(match.group(1))
                            stats['packets_received'] = int(match.group(2))
                            stats['packet_loss_percent'] = float(match.group(3))
                    
                    # round-trip min/avg/max/stddev = 1.234/2.345/3.456/0.789 ms
                    if 'round-trip' in line or 'rtt' in line:
                        match = re.search(r'=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', line)
                        if match:
                            stats['latency_min'] = float(match.group(1))
                            stats['latency_avg'] = float(match.group(2))
                            stats['latency_max'] = float(match.group(3))
                            stats['latency_stddev'] = float(match.group(4))
            
            return {
                'host': host,
                'count': count,
                'success': result.returncode == 0 and stats['packets_received'] > 0,
                'statistics': stats,
                'output': result.stdout,
                'raw_output': output_lines
            }
            
        except Exception as e:
            return {
                'host': host,
                'count': count,
                'success': False,
                'error': str(e)
            }