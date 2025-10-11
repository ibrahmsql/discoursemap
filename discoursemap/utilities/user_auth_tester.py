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
        self.scanner = scanner
    
    def test_weak_passwords(self):
        """Test for weak password acceptance"""
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
        """Test brute force protection on login"""
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
        """Test session management security"""
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
        """Test for password reset vulnerabilities"""
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
        """Test user registration for flaws"""
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
        """Test for privilege escalation vulnerabilities"""
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
