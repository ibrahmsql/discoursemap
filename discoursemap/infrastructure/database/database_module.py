#!/usr/bin/env python3
"""
Discourse Database Module (Refactored)

Database security testing.
Split from 970 lines into focused module.
"""

from typing import Dict, Any
from colorama import Fore, Style
from urllib.parse import urljoin


class DatabaseModule:
    """Database security module (Refactored)"""
    
    def __init__(self, scanner):
        """
        Initialize the DatabaseModule with a scanner and prepare the results structure used to record tests and findings.
        
        Parameters:
            scanner: An object providing at least `target_url` (string) and `make_request` (callable) used by the module to perform HTTP requests for tests.
        """
        self.scanner = scanner
        self.results = {
            'module_name': 'Database Security',
            'target': scanner.target_url,
            'sql_injection': [],
            'nosql_injection': [],
            'database_exposure': [],
            'vulnerabilities': [],
            'tests_performed': 0
        }
    
    def run(self) -> Dict[str, Any]:
        """
        Run the module's database security checks and return the aggregated results.
        
        This method orchestrates the module's checks (SQL injection and database exposure),
        updates self.results with findings and the tests performed count, and returns the
        results dictionary.
        
        Returns:
            results (Dict[str, Any]): Aggregated scan results containing keys such as
            `module_name`, `target`, `sql_injection`, `nosql_injection`, `database_exposure`,
            `vulnerabilities`, and `tests_performed`.
        """
        print(f"{Fore.CYAN}[*] Starting Database Security Scan...{Style.RESET_ALL}")
        
        # Test for SQL injection
        self._test_sql_injection()
        
        # Test for database exposure
        self._test_database_exposure()
        
        print(f"{Fore.GREEN}[+] Database scan complete!{Style.RESET_ALL}")
        print(f"    Tests performed: {self.results['tests_performed']}")
        print(f"    Issues found: {len(self.results['vulnerabilities'])}")
        
        return self.results
    
    def _test_sql_injection(self):
        """
        Check configured endpoints for SQL injection by submitting common payloads and recording findings.
        
        Sends each of the first two payloads to each endpoint using the query parameter 'q'. When a response with HTTP status 500 is observed, appends a record to self.results['sql_injection'] with the endpoint and payload and adds a corresponding vulnerability entry (type: 'SQL Injection', severity: 'critical'). Increments self.results['tests_performed'] once after completing the checks.
        """
        payloads = ["' OR '1'='1", "1' OR '1'='1' --", "admin'--"]
        
        endpoints = ['/search', '/users', '/t/']
        
        for endpoint in endpoints:
            for payload in payloads[:2]:
                try:
                    url = urljoin(self.scanner.target_url, endpoint)
                    response = self.scanner.make_request(
                        url,
                        params={'q': payload},
                        timeout=5
                    )
                    
                    if response and response.status_code == 500:
                        self.results['sql_injection'].append({
                            'endpoint': endpoint,
                            'payload': payload
                        })
                        self.results['vulnerabilities'].append({
                            'type': 'SQL Injection',
                            'severity': 'critical',
                            'endpoint': endpoint
                        })
                        break
                except Exception:
                    continue
        
        self.results['tests_performed'] += 1
    
    def _test_database_exposure(self):
        """
        Check for publicly exposed database backup files on the target.
        
        For each common database file path, attempts an HTTP request to the target URL plus the path; if the response has status code 200, records the path in `self.results['database_exposure']` and adds a corresponding vulnerability entry with type "Database Exposure" and severity "critical". Network or request exceptions are suppressed and do not halt the scan. Increments `self.results['tests_performed']` by 1.
        """
        db_paths = [
            '/backup.sql',
            '/database.sql',
            '/db.sqlite',
            '/discourse.sql'
        ]
        
        for path in db_paths:
            try:
                url = urljoin(self.scanner.target_url, path)
                response = self.scanner.make_request(url, timeout=5)
                
                if response and response.status_code == 200:
                    self.results['database_exposure'].append({
                        'path': path
                    })
                    self.results['vulnerabilities'].append({
                        'type': 'Database Exposure',
                        'severity': 'critical',
                        'path': path
                    })
            except Exception:
                continue
        
        self.results['tests_performed'] += 1