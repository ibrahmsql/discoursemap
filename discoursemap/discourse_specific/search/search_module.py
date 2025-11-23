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
                 Create a SearchSecurityModule configured for a specific Discourse target and initialize result buckets.
                 
                 Parameters:
                     target_url (str): Base URL of the target Discourse site; trailing slashes will be removed.
                     session (Optional[requests.Session]): Optional HTTP session to use for requests; a new Session is created if omitted.
                     verbose (bool): When True, enable verbose logging of scan progress.
                 
                 Initial state:
                     - target_url: normalized base URL without trailing slash
                     - session: requests.Session instance used for HTTP requests
                     - verbose: verbosity flag
                     - results: dictionary with keys 'search_endpoints', 'information_disclosure', 'injection_vulnerabilities', 'dos_potential', and 'recommendations', each initialized to an empty list.
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
    
    def run(self) -> Dict[str, Any]:
        """Run the search security scan (wrapper for scan method)"""
        return self.scan()
    
    def scan(self) -> Dict[str, Any]:
        """
        Run a comprehensive security assessment of the target's search functionality and collect findings.
        
        Performs a sequence of tests covering endpoint availability, injection vectors, information disclosure, denial-of-service vectors, and filter handling, then generates prioritized recommendations.
        
        Returns:
            results (Dict[str, Any]): Aggregated scan results with keys:
                - search_endpoints: list of endpoint test records (endpoint, status_code, accessible, response_size).
                - information_disclosure: list of disclosure findings (query, results_found, note).
                - injection_vulnerabilities: list of injection findings (payload, severity, type, details).
                - dos_potential: list of DoS-related findings (payload/description, severity, time_taken or timeout).
                - recommendations: list of recommended mitigations with severity and action.
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
        Probe common Discourse search-related endpoints and record accessibility and response size.
        
        Sends a GET request to each configured search endpoint using the query parameter `q='test'` (5s timeout) and appends a dictionary to `self.results['search_endpoints']` for each endpoint containing:
        - `endpoint`: the endpoint path tested
        - `status_code`: HTTP response status code
        - `accessible`: `True` if status code is 200, `False` otherwise
        - `response_size`: length in bytes of the response content
        
        Errors during individual endpoint requests are ignored to allow the scan to continue; when `self.verbose` is true, request errors are printed.
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
        Probe the target's search endpoint for common injection and reflected-input issues and record findings.
        
        Sends a set of crafted payloads to the site's /search.json?q=... endpoint and records detected issues in self.results['injection_vulnerabilities']. Records a MEDIUM-severity "Server Error" entry when a payload causes a 500 response and a LOW-severity "Reflected Input" entry when the payload appears verbatim in the response body.
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
        Scan the target site's search endpoint for possible information disclosure of sensitive terms.
        
        Performs searches for a set of sensitive query terms (e.g., "password", "api_key", "secret") against /search.json and records any nonzero result counts into self.results['information_disclosure'] with a MEDIUM severity, the triggering query, and the number of results found. Network errors and JSON parsing errors are ignored so the scan continues across queries.
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
                    except (ValueError, KeyError, TypeError):
                        pass
                        
            except Exception:
                pass
    
    def _test_dos_vectors(self):
        """
        Detect potential denial-of-service behavior in the target search endpoint by exercising it with long or complex queries.
        
        Sends a set of large or complex queries to the service's /search.json endpoint and records observations in self.results['dos_potential']. Entries appended include:
        - Slow query: recorded when a query takes longer than the module's performance threshold; entry includes `payload_type` ('Slow query'), `time_taken`, `severity` ('MEDIUM'), and `description`.
        - Timeout: recorded when a request times out; entry includes `payload_type` ('Timeout'), `severity` ('HIGH'), and `description`.
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
        Test how the target handles common search filter parameters and record which filters are accepted.
        
        Sends queries with several filter parameter sets to the target's /search.json endpoint and appends an entry to results['search_endpoints'] for each parameter set that returns HTTP 200 indicating the filter was accepted.
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
        Produce prioritized security recommendations based on the module's collected findings.
        
        This method examines the scan result categories on the instance (such as
        injection_vulnerabilities, information_disclosure, and dos_potential) and
        populates self.results['recommendations'] with a list of recommendation
        entries. Each entry is a dictionary containing:
        - 'severity': a severity label (e.g., 'HIGH', 'MEDIUM', 'INFO')
        - 'issue': a short description of the detected issue
        - 'recommendation': a suggested remediation action
        
        Recommendation selection:
        - Adds a HIGH-severity recommendation if search injection vulnerabilities are present.
        - Adds a MEDIUM-severity recommendation if sensitive information is discoverable via search.
        - Adds a HIGH-severity recommendation if DoS potential via search queries is detected.
        - Adds an INFO-level note indicating the search appears secure if neither injection nor DoS issues were found.
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
        Display a colorized, human-readable summary of the module's collected scan results to standard output.
        
        Prints counts and details for tested search endpoints and any findings grouped by category: injection vulnerabilities (severity, type, and payload preview), information disclosure (query and number of results), DoS potential (severity and description), and generated recommendations (severity, issue, and recommended action).
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