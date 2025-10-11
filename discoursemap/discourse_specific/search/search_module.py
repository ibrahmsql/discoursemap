#!/usr/bin/env python3
"""
Discourse Search Security Module

Tests search functionality for information disclosure, injection, and DoS vulnerabilities.
"""

import requests
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin, quote


class SearchSecurityModule:
    """Search security testing for Discourse"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        """
                 Create a SearchSecurityModule configured for a target Discourse URL.
                 
                 Parameters:
                     target_url (str): Base URL of the target Discourse instance; trailing slash will be removed.
                     session (Optional[requests.Session]): Optional HTTP session to reuse for requests. If not provided, a new session will be created.
                     verbose (bool): If True, enable verbose console output for scan progress and findings.
                 
                 Notes:
                     Initializes an internal `results` container with keys: 'search_endpoints', 'information_disclosure',
                     'injection_vulnerabilities', 'dos_potential', and 'recommendations'.
                 """
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.results = {
            'search_endpoints': [],
            'information_disclosure': [],
            'injection_vulnerabilities': [],
            'dos_potential': [],
            'recommendations': []
        }
    
    def scan(self) -> Dict[str, Any]:
        """
        Run the full suite of security tests against the target Discourse search endpoints and aggregate the findings.
        
        This invokes the internal endpoint, injection, information disclosure, DoS, and filter tests, then generates recommendations based on discovered issues.
        
        Returns:
            results (Dict[str, Any]): Aggregated scan results containing the keys
            'search_endpoints', 'information_disclosure', 'injection_vulnerabilities',
            'dos_potential', and 'recommendations'; each key maps to a list of findings
            (which may be empty).
        """
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting search security scan...{Style.RESET_ALL}")
        
        self._test_search_endpoints()
        self._test_search_injection()
        self._test_information_disclosure()
        self._test_dos_vectors()
        self._test_search_filters()
        
        self._generate_recommendations()
        return self.results
    
    def _test_search_endpoints(self):
        """
        Check a set of common Discourse search-related endpoints and record their accessibility.
        
        For each endpoint tested, appends a dictionary to self.results['search_endpoints'] with the keys:
        - 'endpoint': the endpoint path tested (e.g., '/search.json')
        - 'status_code': HTTP status code received
        - 'accessible': `True` if status code is 200, `False` otherwise
        - 'response_size': length in bytes of the response content
        
        Errors encountered during individual endpoint requests are caught; when `self.verbose` is true, errors are printed but do not stop the overall test.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing search endpoints...{Style.RESET_ALL}")
        
        endpoints = [
            '/search',
            '/search.json',
            '/search/query',
            '/tags/search',
            '/u/search/users'
        ]
        
        for endpoint in endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url, params={'q': 'test'}, timeout=5)
                
                self.results['search_endpoints'].append({
                    'endpoint': endpoint,
                    'status_code': response.status_code,
                    'accessible': response.status_code == 200,
                    'response_size': len(response.content)
                })
                
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing {endpoint}: {e}{Style.RESET_ALL}")
    
    def _test_search_injection(self):
        """
        Tests the target's search endpoint for injection vulnerabilities and records findings in self.results['injection_vulnerabilities'].
        
        Sends crafted payloads as the search `q` parameter to `/search.json` and records discovered issues:
        - Server Error: when the response status code is 500; an entry is added with keys `payload`, `type` = 'Server Error', `severity` = 'MEDIUM', and `status_code`.
        - Reflected Input: when the payload appears verbatim in the response body; an entry is added with keys `payload`, `type` = 'Reflected Input', and `severity` = 'LOW'.
        
        Findings are appended to `self.results['injection_vulnerabilities']`. The method does not return a value.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing search injection...{Style.RESET_ALL}")
        
        injection_payloads = [
            "' OR '1'='1",
            '" OR "1"="1',
            '<script>alert(1)</script>',
            '${7*7}',
            '{{7*7}}',
            '%27%20OR%20%271%27%3D%271',
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32'
        ]
        
        search_url = urljoin(self.target_url, '/search.json')
        
        for payload in injection_payloads:
            try:
                response = self.session.get(
                    search_url,
                    params={'q': payload},
                    timeout=5
                )
                
                if response.status_code == 500:
                    self.results['injection_vulnerabilities'].append({
                        'payload': payload,
                        'type': 'Server Error',
                        'severity': 'MEDIUM',
                        'status_code': 500
                    })
                elif payload in response.text:
                    self.results['injection_vulnerabilities'].append({
                        'payload': payload,
                        'type': 'Reflected Input',
                        'severity': 'LOW'
                    })
                    
            except Exception:
                pass
    
    def _test_information_disclosure(self):
        """
        Detects potential information disclosure by querying the application's search API for common sensitive terms.
        
        For each sensitive term, performs a search against /search.json and, when the response contains posts or topics, records a finding in self.results['information_disclosure'] with keys: `query`, `results_found`, `severity` (set to "MEDIUM"), and `note`.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing information disclosure...{Style.RESET_ALL}")
        
        # Test searching for sensitive information
        sensitive_queries = [
            'password',
            'api_key',
            'secret',
            'token',
            'admin',
            'private',
            'confidential'
        ]
        
        search_url = urljoin(self.target_url, '/search.json')
        
        for query in sensitive_queries:
            try:
                response = self.session.get(
                    search_url,
                    params={'q': query},
                    timeout=5
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        results_count = len(data.get('posts', [])) + len(data.get('topics', []))
                        
                        if results_count > 0:
                            self.results['information_disclosure'].append({
                                'query': query,
                                'results_found': results_count,
                                'severity': 'MEDIUM',
                                'note': 'Sensitive terms found in search results'
                            })
                    except:
                        pass
                        
            except Exception:
                pass
    
    def _test_dos_vectors(self):
        """
        Detects search queries that may cause denial-of-service conditions.
        
        Sends a set of large or complex queries against the target's /search.json endpoint and records observations of slow responses or request timeouts into self.results['dos_potential'].
        
        Recorded entries:
        - Slow responses: an object with keys 'payload_type' ('Slow query'), 'time_taken' (seconds), 'severity' ('MEDIUM'), and 'description'. Slow responses are recorded when a request takes longer than 5 seconds.
        - Timeouts: an object with keys 'payload_type' ('Timeout'), 'severity' ('HIGH'), and 'description' when a request times out.
        
        Non-timeout exceptions are ignored to allow the scan to continue.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing DoS vectors...{Style.RESET_ALL}")
        
        dos_payloads = [
            '*' * 1000,  # Large wildcard
            'a' * 10000,  # Very long query
            ' OR '.join(['a'] * 100),  # Complex query
            '%' * 100  # Many wildcards
        ]
        
        search_url = urljoin(self.target_url, '/search.json')
        
        for payload in dos_payloads:
            try:
                import time
                start_time = time.time()
                
                response = self.session.get(
                    search_url,
                    params={'q': payload},
                    timeout=10
                )
                
                elapsed_time = time.time() - start_time
                
                if elapsed_time > 5:
                    self.results['dos_potential'].append({
                        'payload_type': 'Slow query',
                        'time_taken': elapsed_time,
                        'severity': 'MEDIUM',
                        'description': 'Search query causes significant delay'
                    })
                    
            except requests.exceptions.Timeout:
                self.results['dos_potential'].append({
                    'payload_type': 'Timeout',
                    'severity': 'HIGH',
                    'description': 'Search query causes timeout'
                })
            except Exception:
                pass
    
    def _test_search_filters(self):
        """
        Check whether various search filter parameters are accepted by the target's /search.json endpoint.
        
        Sends a series of requests using different filter parameter sets and, for each successful (HTTP 200) response,
        records an entry in `self.results['search_endpoints']` containing the `params`, `accessible` (True), and a short `note`.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing search filters...{Style.RESET_ALL}")
        
        # Test various search parameters
        search_params = [
            {'q': 'test', 'in': 'private'},
            {'q': 'test', 'status': 'deleted'},
            {'q': 'test', 'min_posts': '0'},
            {'q': 'test', 'category': '*'}
        ]
        
        search_url = urljoin(self.target_url, '/search.json')
        
        for params in search_params:
            try:
                response = self.session.get(search_url, params=params, timeout=5)
                
                if response.status_code == 200:
                    self.results['search_endpoints'].append({
                        'params': params,
                        'accessible': True,
                        'note': 'Filter parameters accepted'
                    })
                    
            except Exception:
                pass
    
    def _generate_recommendations(self):
        """
        Builds security recommendations based on scan findings and stores them in self.results['recommendations'].
        
        Generates prioritized recommendations when injection vulnerabilities, information disclosure findings, or DoS potentials are present; if none of the critical findings exist, adds an informational recommendation. The resulting list of recommendation dictionaries (each containing 'severity', 'issue', and 'recommendation') is assigned to self.results['recommendations'].
        """
        recommendations = []
        
        if self.results['injection_vulnerabilities']:
            recommendations.append({
                'severity': 'HIGH',
                'issue': 'Search injection vulnerabilities detected',
                'recommendation': 'Implement proper input validation and sanitization'
            })
        
        if self.results['information_disclosure']:
            recommendations.append({
                'severity': 'MEDIUM',
                'issue': 'Sensitive information accessible via search',
                'recommendation': 'Review search indexing and implement proper access controls'
            })
        
        if self.results['dos_potential']:
            recommendations.append({
                'severity': 'HIGH',
                'issue': 'DoS potential via search queries',
                'recommendation': 'Implement query complexity limits and rate limiting'
            })
        
        if not any([self.results['injection_vulnerabilities'],
                   self.results['dos_potential']]):
            recommendations.append({
                'severity': 'INFO',
                'issue': 'Search functionality appears secure',
                'recommendation': 'Continue monitoring and implement rate limiting'
            })
        
        self.results['recommendations'] = recommendations
    
    def print_results(self):
        """
        Print a formatted security scan report to standard output.
        
        The report includes:
        - A header with the scan title.
        - Count of tested search endpoints.
        - A list of injection vulnerabilities with severity, type, and a truncated payload.
        - A list of information-disclosure findings showing the query and number of results.
        - A list of DoS-related findings with severity and description.
        - Recommendations with severity, issue, and suggested remediation.
        
        Output is written to stdout and uses colorized formatting when available.
        """
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"Discourse Search Security Scan Results")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}[*] Search Endpoints Tested: {len(self.results['search_endpoints'])}{Style.RESET_ALL}")
        
        if self.results['injection_vulnerabilities']:
            print(f"\n{Fore.RED}[!] Injection Vulnerabilities: {len(self.results['injection_vulnerabilities'])}{Style.RESET_ALL}")
            for vuln in self.results['injection_vulnerabilities']:
                print(f"  [{vuln['severity']}] {vuln['type']} - {vuln.get('payload', '')[:50]}")
        
        if self.results['information_disclosure']:
            print(f"\n{Fore.YELLOW}[!] Information Disclosure: {len(self.results['information_disclosure'])}{Style.RESET_ALL}")
            for info in self.results['information_disclosure']:
                print(f"  • Query '{info['query']}': {info['results_found']} results")
        
        if self.results['dos_potential']:
            print(f"\n{Fore.RED}[!] DoS Potential: {len(self.results['dos_potential'])}{Style.RESET_ALL}")
            for dos in self.results['dos_potential']:
                print(f"  [{dos['severity']}] {dos['description']}")
        
        if self.results['recommendations']:
            print(f"\n{Fore.YELLOW}[*] Recommendations:{Style.RESET_ALL}")
            for rec in self.results['recommendations']:
                print(f"  [{rec['severity']}] {rec['issue']}")
                print(f"      → {rec['recommendation']}")