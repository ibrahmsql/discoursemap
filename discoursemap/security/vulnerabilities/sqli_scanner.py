#!/usr/bin/env python3
"""SQL Injection Scanner"""

from urllib.parse import urljoin


class SQLiScanner:
    """SQL Injection vulnerability scanner"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' OR '1'='1",
            "admin' --",
            "' UNION SELECT NULL--",
            "1 AND 1=1",
            "1 AND 1=2"
        ]
    
    def scan_sqli(self):
        """Scan for SQL injection vulnerabilities"""
        results = []
        
        test_endpoints = [
            '/search',
            '/users',
            '/t/',
            '/c/'
        ]
        
        for endpoint in test_endpoints:
            for payload in self.sqli_payloads[:3]:
                try:
                    url = urljoin(self.scanner.target_url, endpoint)
                    response = self.scanner.make_request(
                        url,
                        params={'q': payload},
                        timeout=5
                    )
                    
                    if response:
                        # Check for SQL errors
                        sql_errors = [
                            'sql syntax',
                            'mysql',
                            'postgresql',
                            'sqlite',
                            'database error',
                            'syntax error'
                        ]
                        
                        content_lower = response.text.lower()
                        for error in sql_errors:
                            if error in content_lower:
                                results.append({
                                    'type': 'SQL Injection',
                                    'severity': 'critical',
                                    'endpoint': endpoint,
                                    'payload': payload,
                                    'error': error,
                                    'description': f'SQL error detected: {error}'
                                })
                                break
                except Exception:
                    continue
        
        return results
