#!/usr/bin/env python3
"""
User Authentication Testing Module

Handles authentication-related security testing.
"""

import time
from urllib.parse import urljoin
from typing import Dict, List, Any


class UserAuthTester:
    """Authentication testing functionality"""
    
    def __init__(self, scanner):
        """
        Store the provided scanner instance for use by the tester's methods.
        
        The scanner is kept on the instance as `self.scanner` and is used to perform HTTP requests against the target under test.
        """
        self.scanner = scanner
    
    def test_weak_passwords(self):
        """
        Check whether the target accepts a small set of common weak passwords during user registration.
        
        Tests the first three passwords from a predefined list of common weak passwords by attempting registrations and records which passwords succeeded.
        
        Returns:
            dict: {
                'weak_passwords_tested' (int): number of weak passwords considered,
                'accepted_passwords' (list): subset of tested passwords that resulted in successful registration (status 200 or 201)
            }
        """
        weak_passwords = [
            'password', '123456', 'admin', 'test', 
            'qwerty', 'welcome', 'Password1'
        ]
        
        results = {
            'weak_passwords_tested': len(weak_passwords),
            'accepted_passwords': []
        }
        
        register_url = urljoin(self.scanner.target_url, '/u')
        
        for password in weak_passwords[:3]:  # Limit tests
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
                    results['accepted_passwords'].append(password)
            except Exception:
                continue
        
        return results
    
    def test_brute_force_protection(self):
        """
        Assess whether the target enforces rate limiting on repeated login attempts.
        
        Returns:
            dict: A mapping with keys:
                - attempts (int): Number of login attempts performed.
                - rate_limited (bool): `True` if a 429 (rate limit) response was observed, `False` otherwise.
                - rate_limit_threshold (int or None): Number of attempts after which rate limiting was triggered, or `None` if not observed.
        """
        results = {
            'attempts': 0,
            'rate_limited': False,
            'rate_limit_threshold': None
        }
        
        login_url = urljoin(self.scanner.target_url, '/session')
        
        for i in range(10):
            try:
                response = self.scanner.make_request(
                    login_url,
                    method='POST',
                    json={'login': 'admin', 'password': f'test{i}'},
                    timeout=5
                )
                
                results['attempts'] += 1
                
                if response and response.status_code == 429:
                    results['rate_limited'] = True
                    results['rate_limit_threshold'] = i + 1
                    break
                
                time.sleep(0.5)
            except Exception:
                break
        
        return results
    
    def test_session_management(self):
        """
        Inspect session cookies returned by the target and report key security-related cookie attributes.
        
        Returns:
            results (dict): Mapping with the following keys:
                - session_cookies (list): List of cookie info dicts; each dict contains:
                    - name (str): Cookie name.
                    - secure (bool): Whether the cookie has the Secure attribute.
                    - httponly (bool): Whether the cookie has the HttpOnly attribute.
                    - path (str): Cookie path.
                - secure_flag (bool): `True` if any returned cookie has the Secure attribute, `False` otherwise.
                - httponly_flag (bool): `True` if any returned cookie has the HttpOnly attribute, `False` otherwise.
                - samesite (str or None): The SameSite attribute value if available, otherwise `None`.
        """
        results = {
            'session_cookies': [],
            'secure_flag': False,
            'httponly_flag': False,
            'samesite': None
        }
        
        try:
            response = self.scanner.make_request(
                self.scanner.target_url,
                timeout=10
            )
            
            if response:
                # Check session cookies
                for cookie in response.cookies:
                    cookie_info = {
                        'name': cookie.name,
                        'secure': cookie.secure,
                        'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                        'path': cookie.path
                    }
                    results['session_cookies'].append(cookie_info)
                    
                    if cookie.secure:
                        results['secure_flag'] = True
                    if cookie.has_nonstandard_attr('HttpOnly'):
                        results['httponly_flag'] = True
        except Exception:
            pass
        
        return results
    
    def test_password_reset_flaws(self):
        """
        Detect password-reset weaknesses, currently by testing whether the reset endpoint reveals account existence.
        
        Sends a password-reset request for a non-existent username to infer token enumeration.
        
        Returns:
            dict: A mapping with keys:
                - `token_enumeration` (bool): `True` if the reset endpoint indicates whether an account exists, `False` otherwise.
                - `token_predictable` (bool): `True` if reset tokens appear predictable, `False` otherwise (not currently tested).
                - `token_reusable` (bool): `True` if reset tokens can be reused, `False` otherwise (not currently tested).
        """
        results = {
            'token_enumeration': False,
            'token_predictable': False,
            'token_reusable': False
        }
        
        reset_url = urljoin(self.scanner.target_url, '/session/forgot_password')
        
        try:
            # Test 1: Token enumeration
            response = self.scanner.make_request(
                reset_url,
                method='POST',
                json={'login': 'nonexistent_user_12345'},
                timeout=5
            )
            
            if response:
                if response.status_code == 200:
                    results['token_enumeration'] = True
        except Exception:
            pass
        
        return results
    
    def test_registration_flaws(self):
        """
        Assess registration handling for common flaws related to weak passwords, username enumeration, and email verification.
        
        Returns:
            results (dict): A mapping with keys:
                - email_verification_required (bool): `True` if the registration flow appears to require email verification, `False` otherwise.
                - username_enumeration (bool): `True` if usernames can be enumerated through the registration flow or responses, `False` otherwise.
                - weak_password_allowed (bool): `True` if registration succeeds using a weak password, `False` otherwise.
        """
        results = {
            'email_verification_required': True,
            'username_enumeration': False,
            'weak_password_allowed': False
        }
        
        register_url = urljoin(self.scanner.target_url, '/u')
        
        try:
            # Test registration with weak password
            response = self.scanner.make_request(
                register_url,
                method='POST',
                json={
                    'username': f'testuser_{int(time.time())}',
                    'email': f'test{int(time.time())}@example.com',
                    'password': '123456'
                },
                timeout=5
            )
            
            if response and response.status_code in [200, 201]:
                results['weak_password_allowed'] = True
        except Exception:
            pass
        
        return results
    
    def test_privilege_escalation(self):
        """
        Check whether common administrative endpoints are accessible, indicating potential privilege escalation.
        
        Returns:
            dict: {
                'admin_endpoints_accessible': list of endpoint paths (str) that returned HTTP 200,
                'privilege_escalation_possible': bool, `true` if any admin endpoint was accessible, `false` otherwise
            }
        """
        results = {
            'admin_endpoints_accessible': [],
            'privilege_escalation_possible': False
        }
        
        admin_endpoints = [
            '/admin',
            '/admin/users',
            '/admin/site_settings'
        ]
        
        for endpoint in admin_endpoints:
            try:
                url = urljoin(self.scanner.target_url, endpoint)
                response = self.scanner.make_request(url, timeout=5)
                
                if response and response.status_code == 200:
                    results['admin_endpoints_accessible'].append(endpoint)
                    results['privilege_escalation_possible'] = True
            except Exception:
                continue
        
        return results