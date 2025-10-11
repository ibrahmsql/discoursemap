#!/usr/bin/env python3
"""
Discourse Authentication Module (Refactored)

Authentication security testing for Discourse forums.
Split from 1256 lines into modular components.
"""

from typing import Dict, Any
from colorama import Fore, Style
from .bypass_techniques import AuthBypassTester


class AuthModule:
    """Authentication security module (Refactored)"""
    
    def __init__(self, scanner):
        """
        Initialize the authentication security module and prepare its results container.
        
        Creates an AuthModule instance by storing the provided scanner and initializing the results dictionary used to aggregate findings (module_name, target, bypass_attempts, session_security, password_policy, mfa_status, oauth_security, vulnerabilities, recommendations). Also initializes the AuthBypassTester sub-module.
        
        Parameters:
            scanner: An object providing the target_url and request capabilities the module uses to interact with the target site.
        """
        self.scanner = scanner
        self.results = {
            'module_name': 'Authentication Security',
            'target': scanner.target_url,
            'bypass_attempts': [],
            'session_security': [],
            'password_policy': [],
            'mfa_status': {},
            'oauth_security': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Initialize sub-modules
        self.bypass_tester = AuthBypassTester(scanner)
    
    def run(self) -> Dict[str, Any]:
        """
        Run the full authentication security scan and aggregate findings.
        
        Performs bypass testing, session cookie inspection, password-policy checks, MFA discovery, and recommendation generation, then returns the compiled results.
        
        Returns:
            results (Dict[str, Any]): Aggregated scan results with keys:
                - module_name: module identifier
                - target: target URL
                - bypass_attempts: list of bypass test outcomes
                - session_security: list of cookie/session security observations
                - password_policy: list of password-policy test outcomes
                - mfa_status: dict with MFA availability/enforcement info
                - oauth_security: OAuth-related findings (may be empty)
                - vulnerabilities: list of discovered vulnerabilities (each includes type and severity)
                - recommendations: prioritized remediation suggestions
        """
        print(f"{Fore.CYAN}[*] Starting Authentication Security Scan...{Style.RESET_ALL}")
        
        # Test bypass techniques
        print(f"{Fore.YELLOW}[*] Testing authentication bypass techniques...{Style.RESET_ALL}")
        self.results['bypass_attempts'] = self.bypass_tester.test_all_bypasses()
        
        # Test session security
        self._test_session_security()
        
        # Test password policy
        self._test_password_policy()
        
        # Test MFA
        self._test_mfa()
        
        # Generate recommendations
        self._generate_recommendations()
        
        print(f"{Fore.GREEN}[+] Authentication scan complete!{Style.RESET_ALL}")
        print(f"    Bypass attempts: {len(self.results['bypass_attempts'])}")
        print(f"    Vulnerabilities: {len(self.results['vulnerabilities'])}")
        
        return self.results
    
    def _test_session_security(self):
        """
        Assess session cookie configuration and record findings.
        
        Inspects cookies from a request to the target site and appends each cookie's metadata to self.results['session_security']. If a cookie is missing the Secure flag, records a medium-severity vulnerability entry in self.results['vulnerabilities'] describing the insecure cookie.
        """
        try:
            from urllib.parse import urljoin
            
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if response:
                # Check session cookies
                for cookie in response.cookies:
                    cookie_info = {
                        'name': cookie.name,
                        'secure': cookie.secure,
                        'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                        'path': cookie.path
                    }
                    self.results['session_security'].append(cookie_info)
                    
                    if not cookie.secure:
                        self.results['vulnerabilities'].append({
                            'type': 'Insecure Cookie',
                            'severity': 'medium',
                            'cookie': cookie.name,
                            'description': 'Session cookie missing Secure flag'
                        })
        except Exception:
            pass
    
    def _test_password_policy(self):
        """
        Evaluate whether the target's registration accepts weak passwords.
        
        Attempts to register using a sample weak password; if the registration is accepted, records a
        'Weak Password Accepted' entry in self.results['password_policy'] and adds a 'Weak Password Policy'
        vulnerability to self.results['vulnerabilities']. Tests only one weak password sample and suppresses
        exceptions encountered during the check.
        """
        try:
            from urllib.parse import urljoin
            import time
            
            # Try weak passwords
            weak_passwords = ['123456', 'password', 'test']
            register_url = urljoin(self.scanner.target_url, '/u')
            
            for password in weak_passwords[:1]:  # Test only one
                try:
                    response = self.scanner.make_request(
                        register_url,
                        method='POST',
                        json={
                            'username': f'test_{int(time.time())}',
                            'email': f'test{int(time.time())}@example.com',
                            'password': password
                        },
                        timeout=5
                    )
                    
                    if response and response.status_code in [200, 201]:
                        self.results['password_policy'].append({
                            'type': 'Weak Password Accepted',
                            'severity': 'high',
                            'password': password,
                            'description': f'Weak password accepted: {password}'
                        })
                        
                        self.results['vulnerabilities'].append({
                            'type': 'Weak Password Policy',
                            'severity': 'high',
                            'description': 'System accepts weak passwords'
                        })
                except Exception:
                    continue
        except Exception:
            pass
    
    def _test_mfa(self):
        """
        Check whether the target site exposes Multi-Factor Authentication and record the outcome.
        
        Queries the target's /site.json for an `mfa_enabled` flag and updates self.results:
        - Sets self.results['mfa_status'] to a dict with keys:
          - 'available': `True` if MFA is reported enabled, `False` otherwise.
          - 'enforced': `False` (enforcement is not checked by this method).
        - If MFA is not available, appends a medium-severity "MFA Not Available" entry to self.results['vulnerabilities'].
        
        This method performs observable updates to the instance results and does not return a value.
        """
        try:
            from urllib.parse import urljoin
            
            # Check if MFA is available
            site_url = urljoin(self.scanner.target_url, '/site.json')
            response = self.scanner.make_request(site_url, timeout=10)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    # Check for MFA-related settings
                    mfa_enabled = data.get('mfa_enabled', False)
                    
                    self.results['mfa_status'] = {
                        'available': mfa_enabled,
                        'enforced': False  # Would need admin access to check
                    }
                    
                    if not mfa_enabled:
                        self.results['vulnerabilities'].append({
                            'type': 'MFA Not Available',
                            'severity': 'medium',
                            'description': 'Multi-Factor Authentication not available'
                        })
                except Exception:
                    pass
        except Exception:
            pass
    
    def _generate_recommendations(self):
        """
        Compile security recommendations from the module's collected results and store them in self.results['recommendations'].
        
        Scans self.results['vulnerabilities'] to add recommendations for critical and high-severity authentication issues, and adds a recommendation when MFA is not available. Each recommendation is a dict with keys: 'severity', 'issue', and 'recommendation'.
        """
        recommendations = []
        
        if self.results['vulnerabilities']:
            critical = len([v for v in self.results['vulnerabilities'] if v['severity'] == 'critical'])
            high = len([v for v in self.results['vulnerabilities'] if v['severity'] == 'high'])
            
            if critical > 0:
                recommendations.append({
                    'severity': 'CRITICAL',
                    'issue': f'{critical} critical authentication issues',
                    'recommendation': 'Fix immediately - authentication can be bypassed'
                })
            
            if high > 0:
                recommendations.append({
                    'severity': 'HIGH',
                    'issue': f'{high} high-severity authentication issues',
                    'recommendation': 'Address soon to prevent unauthorized access'
                })
        
        if not self.results['mfa_status'].get('available'):
            recommendations.append({
                'severity': 'MEDIUM',
                'issue': 'MFA not available',
                'recommendation': 'Enable Multi-Factor Authentication for enhanced security'
            })
        
        self.results['recommendations'] = recommendations