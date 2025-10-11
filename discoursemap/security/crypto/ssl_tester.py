#!/usr/bin/env python3
"""SSL/TLS Security Tester"""

import ssl
import socket
from urllib.parse import urlparse


class SSLTester:
    """SSL/TLS configuration testing"""
    
    def __init__(self, scanner):
        self.scanner = scanner
    
    def test_ssl_config(self):
        """Test SSL/TLS configuration"""
        results = {
            'https_enabled': False,
            'ssl_version': None,
            'cipher_suite': None,
            'certificate_valid': False,
            'vulnerabilities': []
        }
        
        try:
            parsed = urlparse(self.scanner.target_url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            if parsed.scheme != 'https':
                results['vulnerabilities'].append({
                    'type': 'No HTTPS',
                    'severity': 'critical',
                    'description': 'Site not using HTTPS'
                })
                return results
            
            results['https_enabled'] = True
            
            # Test SSL connection
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    results['ssl_version'] = ssock.version()
                    results['cipher_suite'] = ssock.cipher()[0]
                    
                    # Check for weak protocols
                    if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                        results['vulnerabilities'].append({
                            'type': 'Weak SSL/TLS Protocol',
                            'severity': 'high',
                            'version': ssock.version(),
                            'description': f'Weak protocol in use: {ssock.version()}'
                        })
        
        except Exception:
            pass
        
        return results
