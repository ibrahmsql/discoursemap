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
                 Create an AdminPanelModule for scanning a Discourse target for admin-panel exposures and related security issues.
                 
                 Parameters:
                     target_url (str): Base URL of the target; trailing slash will be removed.
                     verbose (bool): When True, print progress and diagnostic messages during scanning.
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
    
    def run(self) -> Dict[str, Any]:
        """Run the admin panel security scan (wrapper for scan method)"""
        return self.scan()
    
    def scan(self) -> Dict[str, Any]:
        """
        Run the module's full admin panel security scan and populate the instance results.
        
        Performs the configured set of admin-panel checks and updates self.results with findings.
        
        Returns:
            Dict[str, Any]: Results dictionary containing keys `admin_endpoints`, `accessible_endpoints`,
            `exposed_information`, `vulnerabilities`, and `recommendations`.
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
        Discover and record candidate Discourse admin endpoints for the configured target.
        
        Checks a predefined list of admin-related paths by issuing GET requests and appends per-endpoint dictionaries to self.results['admin_endpoints'] with keys: 'path', 'status_code', 'accessible' (true for 200/301/302), 'redirect' (true for 301/302), and 'redirect_location'. For endpoints that return status 200, adds the path to self.results['accessible_endpoints'] and records a HIGH-severity 'Exposed Admin Endpoint' entry in self.results['vulnerabilities']. Network or request exceptions are swallowed; when the module is verbose, errors are printed.
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
        Verify whether the admin panel at /admin is accessible without authentication.
        
        If the admin page returns a 200 response whose body does not indicate a login prompt, records a CRITICAL vulnerability entry `'Missing Access Control'` with description `'Admin panel accessible without authentication'` into self.results['vulnerabilities'].
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
        Scan a set of known admin API endpoints for public accessibility.
        
        Performs GET requests to several admin API paths; for any endpoint that returns HTTP 200, appends a discovery entry to self.results['exposed_information'] with keys: 'endpoint' (the path), 'status' set to 'accessible', and 'severity' set to 'HIGH'. Network errors and other exceptions are ignored.
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
        Checks admin-related endpoints for privilege escalation via parameter tampering.
        
        This method attempts PUT requests against a predefined set of admin user endpoints. If an endpoint responds with a status code other than 401, 403, or 404, it records a CRITICAL "Privilege Escalation" vulnerability entry containing the endpoint and the response status code.
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
        Attempts common default admin credential pairs against the application's session endpoint.
        
        For each credential pair (e.g., "admin"/"admin"), sends a POST to /session with JSON payload {'login': username, 'password': password}. If a response has HTTP status 200 and the response body does not contain the word "error" (case-insensitive), records a CRITICAL "Default Credentials" vulnerability entry containing the username and a short description. Network and other exceptions are swallowed and do not raise.
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
        Check whether common Discourse admin log endpoints are publicly accessible and record any exposures.
        
        For each known admin log path, if an HTTP 200 response is received this method appends a dictionary to self.results['exposed_information'] with keys: 'type' (set to 'Admin Logs'), 'endpoint', and 'accessible' (True). Network errors and non-200 responses are ignored.
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
        Compile remediation recommendations based on collected scan findings and store them in self.results['recommendations'].
        
        The method examines discovered accessible endpoints, exposed information, and recorded vulnerabilities to produce a list of recommendation entries. Each entry includes a severity level, a short issue summary, and a remediation suggestion; when applicable, affected endpoints are included. The resulting list is written to self.results['recommendations'].
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
        Print a formatted summary of the scan results to the console.
        
        Displays counts of discovered admin endpoints and accessible endpoints, lists each accessible endpoint, enumerates found vulnerabilities with severity and optional descriptions, and lists generated recommendations with severity, issue, and recommendation text.
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