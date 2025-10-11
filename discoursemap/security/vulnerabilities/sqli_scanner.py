#!/usr/bin/env python3
"""SQL Injection Scanner"""

from urllib.parse import urljoin


class SQLiScanner:
    """SQL Injection vulnerability scanner"""
    
    def __init__(self, scanner):
        """
        Initialize the SQLiScanner with a request-capable scanner and preset SQL injection payloads.
        
        Parameters:
            scanner: An object used to perform HTTP requests and provide target base URL for scans.
        
        Attributes:
            scanner: The provided scanner instance used to make requests.
            sqli_payloads (list[str]): A list of SQL injection payload strings used during scanning.
        """
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
        """
        Check the target for SQL injection vulnerabilities across a set of endpoints.
        
        Sends requests using SQL injection payloads and inspects responses for common SQL error signatures. For each detected signature, a finding is recorded.
        
        Returns:
            results (list): List of finding dictionaries. Each dictionary contains:
                - 'type' (str): Vulnerability type, e.g. 'SQL Injection'.
                - 'severity' (str): Severity level, e.g. 'critical'.
                - 'endpoint' (str): The probed endpoint path.
                - 'payload' (str): The payload that triggered the finding.
                - 'error' (str): The matched SQL error signature.
                - 'description' (str): Human-readable description of the finding.
        """
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