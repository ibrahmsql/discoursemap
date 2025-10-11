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
        """Execute database security tests"""
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
        """Test for SQL injection"""
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
        """Test for exposed database files"""
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
