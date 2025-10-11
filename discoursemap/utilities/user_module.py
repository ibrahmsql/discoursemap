#!/usr/bin/env python3
"""
Discourse User Security Module (Refactored)

Main module that orchestrates user-related security testing.
Split from 1272 lines into modular components.
"""

from typing import Dict, Any
from colorama import Fore, Style
from .user_enumeration import UserEnumerator
from .user_auth_tester import UserAuthTester


class UserModule:
    """User security testing module for Discourse forums (Refactored)"""
    
    def __init__(self, scanner) -> None:
        """Initialize UserModule
        
        Args:
            scanner: DiscourseScanner instance
        """
        self.scanner = scanner
        self.results = {
            'module_name': 'User Security',
            'target': scanner.target_url,
            'user_enumeration': {},
            'discovered_users': [],
            'authentication_tests': {},
            'session_security': {},
            'privilege_escalation': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Initialize sub-modules
        self.enumerator = UserEnumerator(scanner)
        self.auth_tester = UserAuthTester(scanner)
    
    def run(self) -> Dict[str, Any]:
        """Execute user security tests
        
        Returns:
            Dictionary containing test results
        """
        print(f"{Fore.CYAN}[*] Starting User Security Scan...{Style.RESET_ALL}")
        
        # Phase 1: User Discovery & Enumeration
        self._test_user_enumeration()
        
        # Phase 2: Authentication Testing
        self._test_authentication()
        
        # Phase 3: Session Management
        self._test_session_management()
        
        # Phase 4: Privilege Escalation
        self._test_privilege_escalation()
        
        # Generate recommendations
        self._generate_recommendations()
        
        print(f"{Fore.GREEN}[+] User security scan complete!{Style.RESET_ALL}")
        print(f"    Users discovered: {len(self.results['discovered_users'])}")
        print(f"    Vulnerabilities: {len(self.results['vulnerabilities'])}")
        
        return self.results
    
    def _test_user_enumeration(self):
        """Test user enumeration vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Testing user enumeration...{Style.RESET_ALL}")
        
        # Discover users from public endpoints
        users = self.enumerator.discover_users_from_public_endpoints()
        users.extend(self.enumerator.discover_users_from_directory())
        users.extend(self.enumerator.discover_users_from_search())
        
        # Remove duplicates
        unique_users = {u['username']: u for u in users if u.get('username')}
        self.results['discovered_users'] = list(unique_users.values())
        
        # Test enumeration via login
        if unique_users:
            usernames = list(unique_users.keys())[:10]
            enum_results = self.enumerator.test_user_enumeration(usernames)
            
            self.results['user_enumeration']['login_enumeration'] = enum_results
            
            if enum_results:
                self.results['vulnerabilities'].append({
                    'type': 'User Enumeration',
                    'severity': 'MEDIUM',
                    'description': f'{len(enum_results)} users enumerable via login endpoint'
                })
        
        # Test via forgot password
        if unique_users:
            usernames = list(unique_users.keys())[:5]
            forgot_results = self.enumerator.test_forgot_password_enumeration(usernames)
            self.results['user_enumeration']['forgot_password'] = forgot_results
    
    def _test_authentication(self):
        """Test authentication mechanisms"""
        print(f"{Fore.YELLOW}[*] Testing authentication...{Style.RESET_ALL}")
        
        # Test weak passwords
        weak_pass_results = self.auth_tester.test_weak_passwords()
        self.results['authentication_tests']['weak_passwords'] = weak_pass_results
        
        if weak_pass_results.get('accepted_passwords'):
            self.results['vulnerabilities'].append({
                'type': 'Weak Password Acceptance',
                'severity': 'HIGH',
                'description': 'Weak passwords accepted during registration',
                'passwords': weak_pass_results['accepted_passwords']
            })
        
        # Test brute force protection
        bf_results = self.auth_tester.test_brute_force_protection()
        self.results['authentication_tests']['brute_force'] = bf_results
        
        if not bf_results.get('rate_limited'):
            self.results['vulnerabilities'].append({
                'type': 'Missing Brute Force Protection',
                'severity': 'HIGH',
                'description': 'No rate limiting detected on login endpoint'
            })
        
        # Test password reset
        reset_results = self.auth_tester.test_password_reset_flaws()
        self.results['authentication_tests']['password_reset'] = reset_results
        
        # Test registration
        reg_results = self.auth_tester.test_registration_flaws()
        self.results['authentication_tests']['registration'] = reg_results
    
    def _test_session_management(self):
        """Test session management security"""
        print(f"{Fore.YELLOW}[*] Testing session management...{Style.RESET_ALL}")
        
        session_results = self.auth_tester.test_session_management()
        self.results['session_security'] = session_results
        
        # Check for insecure cookies
        if not session_results.get('secure_flag'):
            self.results['vulnerabilities'].append({
                'type': 'Insecure Cookie',
                'severity': 'MEDIUM',
                'description': 'Session cookies missing Secure flag'
            })
        
        if not session_results.get('httponly_flag'):
            self.results['vulnerabilities'].append({
                'type': 'Insecure Cookie',
                'severity': 'MEDIUM',
                'description': 'Session cookies missing HttpOnly flag'
            })
    
    def _test_privilege_escalation(self):
        """Test for privilege escalation"""
        print(f"{Fore.YELLOW}[*] Testing privilege escalation...{Style.RESET_ALL}")
        
        priv_results = self.auth_tester.test_privilege_escalation()
        self.results['privilege_escalation'] = priv_results
        
        if priv_results.get('privilege_escalation_possible'):
            self.results['vulnerabilities'].append({
                'type': 'Privilege Escalation',
                'severity': 'CRITICAL',
                'description': 'Admin endpoints accessible without authentication',
                'endpoints': priv_results['admin_endpoints_accessible']
            })
    
    def _generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = []
        
        if len(self.results['discovered_users']) > 100:
            recommendations.append({
                'severity': 'INFO',
                'issue': 'Large number of users discoverable',
                'recommendation': 'Consider limiting public user directory access'
            })
        
        if self.results['vulnerabilities']:
            recommendations.append({
                'severity': 'HIGH',
                'issue': f"{len(self.results['vulnerabilities'])} vulnerabilities found",
                'recommendation': 'Address critical authentication and session issues'
            })
        
        self.results['recommendations'] = recommendations
