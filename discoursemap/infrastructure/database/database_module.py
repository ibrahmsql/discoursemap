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
        Initialize the DatabaseModule with a scanner and prepare an empty results structure.
        
        Parameters:
            scanner: An object that provides a `target_url` attribute and a `make_request` method used to perform HTTP requests during tests. The module stores this scanner and initializes `self.results` with keys: 'module_name', 'target', 'sql_injection', 'nosql_injection', 'database_exposure', 'vulnerabilities', and 'tests_performed'.
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
        Coordinate and run database security checks against the configured target.
        
        Runs the module's SQL injection and database exposure tests, updates the instance results dictionary with findings and the tests performed count, and prints a brief summary to stdout.
        
        Returns:
            results (Dict[str, Any]): Scan results containing keys such as 'module_name', 'target', 'sql_injection', 'nosql_injection', 'database_exposure', 'vulnerabilities', and 'tests_performed'.
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
        Checks a set of endpoints for SQL injection indicators and records any findings in the instance results.
        
        Iterates over predefined endpoints and the first two SQL payloads; for each combination it issues a request and, when a response with HTTP status 500 is observed, records an entry in `self.results['sql_injection']` (with `endpoint` and `payload`) and a corresponding vulnerability entry in `self.results['vulnerabilities']` (type: "SQL Injection", severity: "critical"). Increments `self.results['tests_performed']` once after running the checks.
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
        Check the target for publicly accessible database dump or file paths.
        
        For each common database file path, issues a request and, when a path is accessible (HTTP 200), appends a record with the path to results['database_exposure'] and adds a vulnerability entry with type "Database Exposure" and severity "critical". Increments results['tests_performed'] by 1.
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