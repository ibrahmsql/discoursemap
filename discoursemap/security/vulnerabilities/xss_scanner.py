#!/usr/bin/env python3
"""XSS Vulnerability Scanner"""

from urllib.parse import urljoin


class XSSScanner:
    """Cross-Site Scripting vulnerability scanner"""
    
    def __init__(self, scanner):
        """
        Initialize the XSS scanner with an external scanning client and prepare common XSS payloads.
        
        Parameters:
            scanner: An external scanner/client object used to perform HTTP requests and provide the target base URL. The object is expected to expose a `target` attribute (base URL string) and a `make_request(url, timeout=...)` method that returns a response with a `text` attribute.
        
        Details:
            Creates `self.xss_payloads`, a list of common reflected XSS payload strings used during scanning.
        """
        self.scanner = scanner
        self.xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            'javascript:alert(1)',
            '<iframe src="javascript:alert(1)">',
            '<body onload=alert(1)>',
            '{{7*7}}',
            '${7*7}',
            '<scr<script>ipt>alert(1)</scr</script>ipt>'
        ]
    
    def scan_xss(self):
        """
        Scan predefined endpoints for reflected XSS payloads and collect any positive findings.
        
        This method tests a set of common endpoints by injecting XSS payloads and records cases where a payload is reflected in the HTTP response.
        
        Returns:
            results (list[dict]): A list of findings where each entry contains:
                - 'type' (str): Vulnerability type, e.g. 'XSS (Reflected)'.
                - 'severity' (str): Severity level, e.g. 'high'.
                - 'endpoint' (str): The endpoint path that was tested.
                - 'payload' (str): The XSS payload that was reflected.
                - 'description' (str): Short description of the finding.
        """
        results = []
        
        test_endpoints = [
            '/search?q=',
            '/t/',
            '/users/',
            '/posts/'
        ]
        
        for endpoint in test_endpoints:
            for payload in self.xss_payloads[:3]:  # Test first 3
                try:
                    url = urljoin(self.scanner.target_url, endpoint + payload)
                    response = self.scanner.make_request(url, timeout=5)
                    
                    if response and payload in response.text:
                        results.append({
                            'type': 'XSS (Reflected)',
                            'severity': 'high',
                            'endpoint': endpoint,
                            'payload': payload,
                            'description': f'XSS payload reflected: {payload[:50]}'
                        })
                        break
                except Exception:
                    continue
        
        return results