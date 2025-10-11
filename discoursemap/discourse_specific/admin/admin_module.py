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
        """Initialize admin panel module"""
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
        """Perform admin panel security scan"""
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
        """Discover admin panel endpoints"""
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
        """Test admin access controls"""
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
        """Check admin API endpoints"""
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
        """Test for privilege escalation vulnerabilities"""
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
        """Check for default admin credentials"""
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
        """Check admin log exposure"""
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
        """Generate security recommendations"""
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
        """Print formatted results"""
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
