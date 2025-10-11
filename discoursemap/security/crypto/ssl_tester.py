#!/usr/bin/env python3
"""SSL/TLS Security Tester"""

import ssl
import socket
from urllib.parse import urlparse


class SSLTester:
    """SSL/TLS configuration testing"""
    
    def __init__(self, scanner):
        """
        Create an SSLTester bound to a scanner instance used to obtain target configuration and state.
        
        Parameters:
            scanner: An object that provides scanning context (must expose `target_url` and related scanning utilities).
        """
        self.scanner = scanner
    
    def test_ssl_config(self):
        """
        Check the target URL's HTTPS/TLS configuration and collect basic TLS metadata and detected issues.
        
        Performs a connection to the target host (if the target URL uses the https scheme) and records the negotiated TLS version, cipher suite, certificate validity flag, and any detected vulnerabilities.
        
        Returns:
            dict: A mapping with the following keys:
                https_enabled (bool): True if the target URL uses the https scheme.
                ssl_version (str or None): Negotiated TLS/SSL protocol version (e.g., "TLSv1.2"), or None if not obtained.
                cipher_suite (str or None): Name of the negotiated cipher suite, or None if not obtained.
                certificate_valid (bool): True if the certificate is considered valid (default False if not checked/obtained).
                vulnerabilities (list): List of vulnerability entries (each a dict). Typical entry keys:
                    - type (str): Short identifier of the issue (e.g., "No HTTPS", "Weak SSL/TLS Protocol").
                    - severity (str): Severity level (e.g., "critical", "high").
                    - description (str): Human-readable explanation of the issue.
                    - version (str, optional): Protocol version involved when applicable.
        """
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