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
        """Execute authentication security tests"""
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
        """Test session management security"""
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
        """Test password policy strength"""
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
        """Test Multi-Factor Authentication"""
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
        """Generate security recommendations"""
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
