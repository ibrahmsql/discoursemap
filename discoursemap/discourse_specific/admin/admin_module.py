#!/usr/bin/env python3
"""
Discourse Admin Panel Security Module

Tests admin panel security, access controls, and configuration exposure.
"""

import requests
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin


class AdminPanelModule:
    """Admin panel security testing for Discourse"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        """
                 Create an AdminPanelModule for scanning a Discourse admin panel.
                 
                 Normalizes the provided target URL by stripping a trailing slash, uses the given
                 requests.Session (or creates a new one), sets the verbosity flag, and initializes
                 the results dictionary with the keys: 'admin_endpoints', 'accessible_endpoints',
                 'exposed_information', 'vulnerabilities', and 'recommendations'.
                 
                 Parameters:
                     target_url (str): Base URL of the target Discourse instance (trailing slash is optional).
                     session (Optional[requests.Session]): HTTP session to use for requests; a new session is created if None.
                     verbose (bool): If True, enable verbose output during scanning.
                 """
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.results = {
            'admin_endpoints': [],
            'accessible_endpoints': [],
            'exposed_information': [],
            'vulnerabilities': [],
            'recommendations': []
        }
    
    def scan(self) -> Dict[str, Any]:
        """
        Run the full suite of admin-panel security tests against the configured target and collect findings.
        
        This invokes the module's discovery and test methods in sequence and aggregates their outputs into the instance's results structure.
        
        Returns:
            results (Dict[str, Any]): Aggregated scan results containing keys:
                - admin_endpoints: list of discovered admin endpoint metadata
                - accessible_endpoints: list of endpoints accessible without proper restrictions
                - exposed_information: list of endpoints or data that expose sensitive information
                - vulnerabilities: list of discovered vulnerabilities
                - recommendations: list of generated security recommendations
        """
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting admin panel security scan...{Style.RESET_ALL}")
        
        self._discover_admin_endpoints()
        self._test_admin_access()
        self._check_admin_api()
        self._test_privilege_escalation()
        self._check_default_credentials()
        self._check_admin_logs()
        
        self._generate_recommendations()
        return self.results
    
    def _discover_admin_endpoints(self):
        """
        Discover common Discourse admin panel endpoints and record their accessibility.
        
        For each predefined admin-related path this method:
        - Performs an HTTP GET (no redirects) to determine status and redirect target.
        - Appends endpoint metadata to self.results['admin_endpoints'] with keys: path, status_code, accessible, redirect, redirect_location.
        - If the endpoint returns 200, adds the path to self.results['accessible_endpoints'] and records a HIGH-severity 'Exposed Admin Endpoint' entry in self.results['vulnerabilities'].
        
        Side effects:
        - Mutates self.results as described.
        - May print progress or errors when self.verbose is True.
        
        Exceptions raised by individual requests are caught and do not propagate.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Discovering admin endpoints...{Style.RESET_ALL}")
        
        admin_paths = [
            '/admin',
            '/admin/dashboard',
            '/admin/users',
            '/admin/site_settings',
            '/admin/customize',
            '/admin/api',
            '/admin/plugins',
            '/admin/backups',
            '/admin/logs',
            '/admin/flags',
            '/admin/email',
            '/admin/web_hooks',
            '/admin/badges',
            '/admin/embedding',
            '/admin/permalinks',
            '/admin/reports',
            '/admin/staff_action_logs',
            '/admin/screened_emails',
            '/admin/screened_ip_addresses',
            '/admin/screened_urls',
            '/admin/search_logs'
        ]
        
        for path in admin_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                endpoint_info = {
                    'path': path,
                    'status_code': response.status_code,
                    'accessible': response.status_code in [200, 301, 302],
                    'redirect': response.status_code in [301, 302],
                    'redirect_location': response.headers.get('Location', '')
                }
                
                self.results['admin_endpoints'].append(endpoint_info)
                
                if endpoint_info['accessible'] and response.status_code == 200:
                    self.results['accessible_endpoints'].append(path)
                    self.results['vulnerabilities'].append({
                        'type': 'Exposed Admin Endpoint',
                        'path': path,
                        'severity': 'HIGH',
                        'description': f'Admin endpoint accessible: {path}'
                    })
                    
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error checking {path}: {e}{Style.RESET_ALL}")
    
    def _test_admin_access(self):
        """
        Check whether the Discourse admin panel is accessible without authentication.
        
        Performs an HTTP GET to the target's /admin path and, if the response status is 200 and the response body does not contain the string "login" (case-insensitive), appends a CRITICAL "Missing Access Control" vulnerability entry to self.results['vulnerabilities'] indicating the admin panel is accessible without authentication.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing admin access controls...{Style.RESET_ALL}")
        
        try:
            admin_url = urljoin(self.target_url, '/admin')
            response = self.session.get(admin_url, timeout=10)
            
            # Check if redirected to login
            if response.status_code == 200:
                if 'login' not in response.text.lower():
                    self.results['vulnerabilities'].append({
                        'type': 'Missing Access Control',
                        'severity': 'CRITICAL',
                        'description': 'Admin panel accessible without authentication'
                    })
            
        except Exception:
            pass
    
    def _check_admin_api(self):
        """
        Check a set of Discourse admin API endpoints for public accessibility.
        
        Iterates the predefined admin API paths and, for any endpoint that returns HTTP 200, records an entry in self.results['exposed_information'] with keys 'endpoint' (the path), 'status' set to 'accessible', and 'severity' set to 'HIGH'. Network errors and other exceptions are suppressed and do not raise.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking admin API...{Style.RESET_ALL}")
        
        api_endpoints = [
            '/admin/users/list.json',
            '/admin/dashboard.json',
            '/admin/reports.json',
            '/admin/logs.json'
        ]
        
        for endpoint in api_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    self.results['exposed_information'].append({
                        'endpoint': endpoint,
                        'status': 'accessible',
                        'severity': 'HIGH'
                    })
                    
            except Exception:
                pass
    
    def _test_privilege_escalation(self):
        """
        Check for privilege escalation by attempting parameter-tampering HTTP PUT requests against common admin user endpoints.
        
        Sends PUT requests with an empty JSON body to /admin/users/1, /admin/users/1/grant_admin, and /admin/users/1/revoke_admin. If a request returns a status code other than 401, 403, or 404, records a CRITICAL "Privilege Escalation" entry in self.results['vulnerabilities'] containing the endpoint and the status_code. Network/request exceptions are ignored.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing privilege escalation...{Style.RESET_ALL}")
        
        # Test parameter tampering
        test_endpoints = [
            '/admin/users/1',
            '/admin/users/1/grant_admin',
            '/admin/users/1/revoke_admin'
        ]
        
        for endpoint in test_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.put(url, json={}, timeout=5)
                
                if response.status_code not in [401, 403, 404]:
                    self.results['vulnerabilities'].append({
                        'type': 'Privilege Escalation',
                        'endpoint': endpoint,
                        'severity': 'CRITICAL',
                        'status_code': response.status_code
                    })
                    
            except Exception:
                pass
    
    def _check_default_credentials(self):
        """
        Checks whether common default administrator credentials allow login to the target Discourse instance.
        
        Attempts a small set of common credential pairs against the instance's /session endpoint; if a login attempt returns HTTP 200 and the response body does not contain the word "error" (case-insensitive), a CRITICAL "Default Credentials" entry is appended to self.results['vulnerabilities'] containing the failing username and a short description.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking default credentials...{Style.RESET_ALL}")
        
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('administrator', 'administrator')
        ]
        
        login_url = urljoin(self.target_url, '/session')
        
        for username, password in default_creds:
            try:
                response = self.session.post(
                    login_url,
                    json={'login': username, 'password': password},
                    timeout=5
                )
                
                if response.status_code == 200 and 'error' not in response.text.lower():
                    self.results['vulnerabilities'].append({
                        'type': 'Default Credentials',
                        'severity': 'CRITICAL',
                        'username': username,
                        'description': 'Default admin credentials may be active'
                    })
                    
            except Exception:
                pass
    
    def _check_admin_logs(self):
        """
        Check whether common Discourse admin log endpoints are accessible and record any exposures.
        
        For each predefined admin log path, performs an HTTP GET and, when a 200 response is returned,
        appends an entry to self.results['exposed_information'] with keys:
        - 'type': 'Admin Logs'
        - 'endpoint': the checked path
        - 'accessible': True
        
        Exceptions during requests are ignored. If `self.verbose` is true, a progress message is printed.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking admin logs...{Style.RESET_ALL}")
        
        log_endpoints = [
            '/admin/logs/staff_action_logs',
            '/admin/logs/screened_emails',
            '/admin/logs/screened_ip_addresses'
        ]
        
        for endpoint in log_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    self.results['exposed_information'].append({
                        'type': 'Admin Logs',
                        'endpoint': endpoint,
                        'accessible': True
                    })
                    
            except Exception:
                pass
    
    def _generate_recommendations(self):
        """
        Assembles remediation recommendations based on collected scan results and stores them in self.results['recommendations'].
        
        Adds a HIGH-severity recommendation when admin endpoints were found accessible without authentication (includes the list of affected endpoints). Adds a HIGH-severity recommendation when sensitive admin information (APIs or logs) was discovered exposed. If no vulnerabilities were recorded, adds an INFO-severity recommendation noting no critical issues were detected.
        """
        recommendations = []
        
        if self.results['accessible_endpoints']:
            recommendations.append({
                'severity': 'HIGH',
                'issue': 'Admin endpoints accessible without proper authentication',
                'recommendation': 'Implement strict access controls and require admin authentication',
                'affected': self.results['accessible_endpoints']
            })
        
        if self.results['exposed_information']:
            recommendations.append({
                'severity': 'HIGH',
                'issue': 'Sensitive admin information exposed',
                'recommendation': 'Restrict access to admin API endpoints and logs'
            })
        
        if not self.results['vulnerabilities']:
            recommendations.append({
                'severity': 'INFO',
                'issue': 'No critical admin panel vulnerabilities detected',
                'recommendation': 'Continue monitoring and implement security best practices'
            })
        
        self.results['recommendations'] = recommendations
    
    def print_results(self):
        """
        Prints a formatted summary of the module's scan results to the console.
        
        Shows counts of discovered admin endpoints and accessible endpoints, lists any accessible endpoints, and prints found vulnerabilities (including severity and description when available) followed by remediation recommendations with severity and recommended actions.
        """
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"Discourse Admin Panel Security Scan Results")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}[*] Admin Endpoints Discovered: {len(self.results['admin_endpoints'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Accessible Endpoints: {len(self.results['accessible_endpoints'])}{Style.RESET_ALL}")
        
        if self.results['accessible_endpoints']:
            for endpoint in self.results['accessible_endpoints']:
                print(f"  • {endpoint}")
        
        if self.results['vulnerabilities']:
            print(f"\n{Fore.RED}[!] Vulnerabilities Found: {len(self.results['vulnerabilities'])}{Style.RESET_ALL}")
            for vuln in self.results['vulnerabilities']:
                print(f"  [{vuln['severity']}] {vuln['type']}")
                if 'description' in vuln:
                    print(f"      {vuln['description']}")
        
        if self.results['recommendations']:
            print(f"\n{Fore.YELLOW}[*] Recommendations:{Style.RESET_ALL}")
            for rec in self.results['recommendations']:
                print(f"  [{rec['severity']}] {rec['issue']}")
                print(f"      → {rec['recommendation']}")