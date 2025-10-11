#!/usr/bin/env python3
"""XSS Vulnerability Scanner"""

from urllib.parse import urljoin


class XSSScanner:
    """Cross-Site Scripting vulnerability scanner"""
    
    def __init__(self, scanner):
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
        """Scan for XSS vulnerabilities"""
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
