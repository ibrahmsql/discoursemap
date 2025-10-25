#!/usr/bin/env python3
"""
Authentication Security Tester

Tests authentication mechanisms for security vulnerabilities.
"""

import requests
import hashlib
import time
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin


class AuthenticationTester:
    """Tests authentication security"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.common_passwords = [
            'password', '123456', 'admin', 'root', 'test',
            'guest', 'user', 'demo', 'default', 'qwerty'
        ]
        self.common_usernames = [
            'admin', 'administrator', 'root', 'user', 'test',
            'guest', 'demo', 'sa', 'operator', 'manager'
        ]
    
    def test_all_auth_vulnerabilities(self) -> Dict[str, Any]:
        """Test all authentication vulnerabilities"""
        results = {
            'weak_credentials': self.test_weak_credentials(),
            'brute_force_protection': self.test_brute_force_protection(),
            'password_policy': self.test_password_policy(),
            'session_management': self.test_session_management(),
            'multi_factor_auth': self.test_mfa_bypass(),
            'oauth_vulnerabilities': self.test_oauth_vulnerabilities()
        }
        
        return results
    
    def test_weak_credentials(self) -> Dict[str, Any]:
        """Test for weak default credentials"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing weak credentials...{Style.RESET_ALL}")
        
        login_endpoint = urljoin(self.target_url, '/session')
        weak_credentials = []
        
        # Test common username/password combinations
        for username in self.common_usernames:
            for password in self.common_passwords:
                try:
                    response = self.session.post(
                        login_endpoint,
                        json={'login': username, 'password': password},
                        timeout=10
                    )
                    
                    # Check for successful login indicators
                    if (response.status_code == 200 and 
                        ('success' in response.text.lower() or 
                         'dashboard' in response.text.lower() or
                         'welcome' in response.text.lower())):
                        
                        weak_credentials.append({
                            'username': username,
                            'password': password,
                            'status_code': response.status_code,
                            'severity': 'CRITICAL'
                        })
                    
                    time.sleep(0.5)  # Avoid triggering rate limits
                    
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.RED}[!] Error testing {username}:{password}: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'weak_credentials_found': len(weak_credentials),
            'credentials': weak_credentials
        }
    
    def test_brute_force_protection(self) -> Dict[str, Any]:
        """Test brute force protection mechanisms"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing brute force protection...{Style.RESET_ALL}")
        
        login_endpoint = urljoin(self.target_url, '/session')
        attempts = []
        
        # Perform multiple failed login attempts
        for i in range(20):
            try:
                start_time = time.time()
                response = self.session.post(
                    login_endpoint,
                    json={'login': 'testuser', 'password': f'wrongpass{i}'},
                    timeout=10
                )
                end_time = time.time()
                
                attempts.append({
                    'attempt': i + 1,
                    'status_code': response.status_code,
                    'response_time': end_time - start_time,
                    'blocked': response.status_code == 429
                })
                
                # If we get rate limited, that's good
                if response.status_code == 429:
                    break
                
                time.sleep(0.1)
                
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error in brute force test: {e}{Style.RESET_ALL}")
                break
        
        # Analyze results
        blocked_attempts = [a for a in attempts if a['blocked']]
        protection_enabled = len(blocked_attempts) > 0
        
        return {
            'tested': True,
            'protection_enabled': protection_enabled,
            'total_attempts': len(attempts),
            'blocked_attempts': len(blocked_attempts),
            'attempts': attempts,
            'severity': 'HIGH' if not protection_enabled else 'LOW'
        }
    
    def test_password_policy(self) -> Dict[str, Any]:
        """Test password policy enforcement"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing password policy...{Style.RESET_ALL}")
        
        register_endpoint = urljoin(self.target_url, '/users')
        weak_passwords = [
            '123',
            'password',
            'abc',
            '111111',
            'qwerty',
            'test'
        ]
        
        policy_tests = []
        
        for password in weak_passwords:
            try:
                response = self.session.post(
                    register_endpoint,
                    json={
                        'name': 'testuser',
                        'username': 'testuser123',
                        'email': 'test@example.com',
                        'password': password
                    },
                    timeout=10
                )
                
                # Check if weak password was accepted
                accepted = response.status_code in [200, 201]
                
                policy_tests.append({
                    'password': password,
                    'accepted': accepted,
                    'status_code': response.status_code,
                    'response': response.text[:200]
                })
                
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing password policy: {e}{Style.RESET_ALL}")
        
        weak_accepted = [t for t in policy_tests if t['accepted']]
        
        return {
            'tested': True,
            'weak_passwords_accepted': len(weak_accepted),
            'policy_tests': policy_tests,
            'severity': 'HIGH' if weak_accepted else 'LOW'
        }
    
    def test_session_management(self) -> Dict[str, Any]:
        """Test session management security"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing session management...{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        # Test session fixation
        session1 = requests.Session()
        initial_cookies = {c.name: c.value for c in session1.cookies}
        
        try:
            # Attempt login
            login_endpoint = urljoin(self.target_url, '/session')
            response = session1.post(
                login_endpoint,
                json={'login': 'test', 'password': 'test'},
                timeout=10
            )
            
            after_login_cookies = {c.name: c.value for c in session1.cookies}
            
            # Check if session ID changed
            session_changed = False
            for cookie_name in initial_cookies:
                if cookie_name in after_login_cookies:
                    if initial_cookies[cookie_name] != after_login_cookies[cookie_name]:
                        session_changed = True
                        break
            
            if not session_changed:
                vulnerabilities.append({
                    'type': 'session_fixation',
                    'severity': 'HIGH',
                    'description': 'Session ID not regenerated after login'
                })
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error testing session management: {e}{Style.RESET_ALL}")
        
        # Test concurrent sessions
        try:
            session2 = requests.Session()
            session3 = requests.Session()
            
            # Try to establish multiple sessions
            for session in [session2, session3]:
                session.get(self.target_url, timeout=10)
            
            # This is a basic test - in practice you'd need valid credentials
            vulnerabilities.append({
                'type': 'concurrent_sessions',
                'severity': 'MEDIUM',
                'description': 'Multiple concurrent sessions may be allowed',
                'note': 'Requires valid credentials for full test'
            })
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error testing concurrent sessions: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    def test_mfa_bypass(self) -> Dict[str, Any]:
        """Test multi-factor authentication bypass"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing MFA bypass...{Style.RESET_ALL}")
        
        mfa_endpoints = [
            '/session/2fa',
            '/users/second_factor',
            '/auth/totp',
            '/mfa/verify'
        ]
        
        bypass_attempts = []
        
        for endpoint in mfa_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            # Test various bypass techniques
            bypass_tests = [
                {'code': '000000'},  # Common default
                {'code': '123456'},  # Sequential
                {'code': ''},        # Empty
                {'bypass': 'true'},  # Parameter manipulation
                {'admin': 'true'}    # Privilege escalation
            ]
            
            for test_data in bypass_tests:
                try:
                    response = self.session.post(url, json=test_data, timeout=10)
                    
                    if response.status_code in [200, 302]:
                        bypass_attempts.append({
                            'endpoint': endpoint,
                            'payload': test_data,
                            'status_code': response.status_code,
                            'severity': 'HIGH'
                        })
                
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.RED}[!] Error testing MFA bypass: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'bypass_attempts_successful': len(bypass_attempts),
            'attempts': bypass_attempts
        }
    
    def test_oauth_vulnerabilities(self) -> Dict[str, Any]:
        """Test OAuth implementation vulnerabilities"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing OAuth vulnerabilities...{Style.RESET_ALL}")
        
        oauth_endpoints = [
            '/auth/google_oauth2',
            '/auth/facebook',
            '/auth/github',
            '/auth/twitter',
            '/oauth/authorize'
        ]
        
        vulnerabilities = []
        
        for endpoint in oauth_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            try:
                # Test for OAuth vulnerabilities
                response = self.session.get(url, timeout=10)
                
                # Check for common OAuth issues
                if response.status_code == 200:
                    response_text = response.text.lower()
                    
                    # Check for missing state parameter
                    if 'state=' not in response_text and 'oauth' in response_text:
                        vulnerabilities.append({
                            'endpoint': endpoint,
                            'type': 'missing_state_parameter',
                            'severity': 'MEDIUM',
                            'description': 'OAuth flow may be missing CSRF protection'
                        })
                    
                    # Check for redirect_uri validation
                    test_redirect = f"{url}?redirect_uri=http://evil.com"
                    redirect_response = self.session.get(test_redirect, timeout=10)
                    
                    if 'evil.com' in redirect_response.text:
                        vulnerabilities.append({
                            'endpoint': endpoint,
                            'type': 'open_redirect',
                            'severity': 'HIGH',
                            'description': 'OAuth redirect_uri not properly validated'
                        })
            
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing OAuth {endpoint}: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }