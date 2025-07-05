#!/usr/bin/env python3
"""
Discourse Security Scanner - User Security Module

Tests user-related security issues including authentication and authorization
"""

import re
import time
import json
import random
import string
from urllib.parse import urljoin, quote
from bs4 import BeautifulSoup
from .utils import extract_csrf_token

class UserModule:
    """User security testing module for Discourse forums"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'User Security Testing',
            'target': scanner.target_url,
            'user_enumeration': [],
            'weak_passwords': [],
            'brute_force_results': [],
            'session_issues': [],
            'password_reset_issues': [],
            'registration_issues': [],
            'privilege_escalation': [],
            'tests_performed': 0,
            'scan_time': 0
        }
        self.start_time = time.time()
        self.discovered_users = []
    
    def run(self):
        """Run user security testing module"""
        self.scanner.log("Starting user security testing...")
        
        # User enumeration
        self._test_user_enumeration()
        
        # Weak password testing
        self._test_weak_passwords()
        
        # Brute force testing (limited)
        self._test_brute_force_protection()
        
        # Session management testing
        self._test_session_management()
        
        # Password reset testing
        self._test_password_reset_flaws()
        
        # Registration testing
        self._test_registration_flaws()
        
        # Privilege escalation testing
        self._test_privilege_escalation()
        
        self.results['scan_time'] = time.time() - self.start_time
        return self.results
    
    def _test_user_enumeration(self):
        """Test for user enumeration vulnerabilities"""
        self.scanner.log("Testing user enumeration...", 'debug')
        
        # Common usernames to test
        common_usernames = [
            'admin', 'administrator', 'root', 'user', 'test',
            'guest', 'demo', 'support', 'moderator', 'mod',
            'staff', 'owner', 'webmaster', 'discourse',
            'system', 'service', 'api', 'bot'
        ]
        
        # Test user enumeration via different endpoints
        enumeration_endpoints = [
            '/u/{username}',
            '/u/{username}.json',
            '/users/{username}',
            '/users/{username}.json',
            '/users/by-external/{username}'
        ]
        
        valid_users = []
        
        for username in common_usernames:
            for endpoint_template in enumeration_endpoints:
                endpoint = endpoint_template.format(username=username)
                url = urljoin(self.scanner.target_url, endpoint)
                
                response = self.scanner.make_request(url)
                
                if response:
                    if response.status_code == 200:
                        # User exists
                        user_info = {
                            'username': username,
                            'endpoint': endpoint,
                            'status': 'exists',
                            'method': 'direct_access'
                        }
                        
                        # Try to extract additional info
                        if endpoint.endswith('.json'):
                            try:
                                user_data = response.json()
                                if 'user' in user_data:
                                    user_info.update({
                                        'name': user_data['user'].get('name'),
                                        'trust_level': user_data['user'].get('trust_level'),
                                        'last_seen': user_data['user'].get('last_seen_at'),
                                        'post_count': user_data['user'].get('post_count')
                                    })
                            except json.JSONDecodeError:
                                pass
                        
                        valid_users.append(user_info)
                        self.scanner.log(f"User found: {username}", 'success')
                        break
                    
                    elif response.status_code == 404:
                        # User doesn't exist - this is normal
                        pass
                    
                    elif response.status_code == 403:
                        # User exists but access denied
                        user_info = {
                            'username': username,
                            'endpoint': endpoint,
                            'status': 'exists_protected',
                            'method': 'access_denied'
                        }
                        valid_users.append(user_info)
                        self.scanner.log(f"Protected user found: {username}", 'info')
                
                self.results['tests_performed'] += 1
                time.sleep(0.1)
        
        # Test login enumeration
        self._test_login_enumeration(common_usernames)
        
        # Test forgot password enumeration
        self._test_forgot_password_enumeration(common_usernames)
        
        self.results['user_enumeration'] = valid_users
        self.discovered_users = [user['username'] for user in valid_users]
    
    def _test_login_enumeration(self, usernames):
        """Test user enumeration via login responses"""
        self.scanner.log("Testing login enumeration...", 'debug')
        
        login_url = urljoin(self.scanner.target_url, '/session')
        
        # Get CSRF token first
        login_page = self.scanner.make_request(urljoin(self.scanner.target_url, '/login'))
        csrf_token = None
        if login_page:
            csrf_token = extract_csrf_token(login_page.text)
        
        for username in usernames[:5]:  # Limit to avoid too many requests
            login_data = {
                'login': username,
                'password': 'invalid_password_12345',
            }
            
            if csrf_token:
                login_data['authenticity_token'] = csrf_token
            
            response = self.scanner.make_request(login_url, method='POST', data=login_data)
            
            if response:
                # Analyze response for enumeration indicators
                response_text = response.text.lower()
                
                if 'invalid username' in response_text or 'user not found' in response_text:
                    # Username doesn't exist
                    pass
                elif 'invalid password' in response_text or 'incorrect password' in response_text:
                    # Username exists, password wrong
                    enum_result = {
                        'username': username,
                        'method': 'login_response',
                        'status': 'exists',
                        'indicator': 'password_error_message'
                    }
                    self.results['user_enumeration'].append(enum_result)
                    self.scanner.log(f"User enumerated via login: {username}", 'warning')
            
            self.results['tests_performed'] += 1
            time.sleep(0.5)  # Longer delay for login attempts
    
    def _test_forgot_password_enumeration(self, usernames):
        """Test user enumeration via forgot password responses"""
        self.scanner.log("Testing forgot password enumeration...", 'debug')
        
        forgot_url = urljoin(self.scanner.target_url, '/session/forgot_password')
        
        # Get CSRF token
        forgot_page = self.scanner.make_request(urljoin(self.scanner.target_url, '/password-reset'))
        csrf_token = None
        if forgot_page:
            csrf_token = extract_csrf_token(forgot_page.text)
        
        for username in usernames[:3]:  # Very limited to avoid spam
            forgot_data = {
                'login': username
            }
            
            if csrf_token:
                forgot_data['authenticity_token'] = csrf_token
            
            response = self.scanner.make_request(forgot_url, method='POST', data=forgot_data)
            
            if response:
                response_text = response.text.lower()
                
                # Look for different responses that might indicate user existence
                if 'email sent' in response_text or 'check your email' in response_text:
                    enum_result = {
                        'username': username,
                        'method': 'forgot_password',
                        'status': 'likely_exists',
                        'indicator': 'email_sent_message'
                    }
                    self.results['user_enumeration'].append(enum_result)
                    self.scanner.log(f"User likely exists (forgot password): {username}", 'info')
            
            self.results['tests_performed'] += 1
            time.sleep(1.0)  # Long delay for forgot password
    
    def _test_weak_passwords(self):
        """Test for weak passwords on discovered users"""
        self.scanner.log("Testing for weak passwords...", 'debug')
        
        if not self.discovered_users:
            return
        
        # Common weak passwords
        weak_passwords = [
            'password', '123456', 'admin', 'password123',
            'qwerty', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'shadow', 'football'
        ]
        
        # Add username-based passwords
        for user in self.discovered_users[:3]:  # Limit users
            weak_passwords.extend([
                user,
                user + '123',
                user + '2023',
                user + '2024',
                user.lower(),
                user.upper()
            ])
        
        login_url = urljoin(self.scanner.target_url, '/session')
        
        for username in self.discovered_users[:2]:  # Very limited
            for password in weak_passwords[:10]:  # Limited passwords
                
                # Get fresh CSRF token
                login_page = self.scanner.make_request(urljoin(self.scanner.target_url, '/login'))
                csrf_token = None
                if login_page:
                    csrf_token = extract_csrf_token(login_page.text)
                
                login_data = {
                    'login': username,
                    'password': password
                }
                
                if csrf_token:
                    login_data['authenticity_token'] = csrf_token
                
                response = self.scanner.make_request(login_url, method='POST', data=login_data)
                
                if response:
                    # Check for successful login indicators
                    if (response.status_code == 200 and 
                        ('dashboard' in response.text.lower() or 
                         'logout' in response.text.lower() or
                         'welcome' in response.text.lower())):
                        
                        weak_pass_result = {
                            'username': username,
                            'password': password,
                            'severity': 'critical',
                            'description': f'Weak password found for user {username}'
                        }
                        self.results['weak_passwords'].append(weak_pass_result)
                        self.scanner.log(f"Weak password found: {username}:{password}", 'error')
                        break  # Stop testing this user
                
                self.results['tests_performed'] += 1
                time.sleep(2.0)  # Long delay between login attempts
    
    def _test_brute_force_protection(self):
        """Test brute force protection mechanisms"""
        self.scanner.log("Testing brute force protection...", 'debug')
        
        if not self.discovered_users:
            return
        
        login_url = urljoin(self.scanner.target_url, '/session')
        test_user = self.discovered_users[0] if self.discovered_users else 'admin'
        
        # Perform multiple failed login attempts
        failed_attempts = 0
        max_attempts = 5  # Limited to avoid actual brute force
        
        for attempt in range(max_attempts):
            # Get CSRF token
            login_page = self.scanner.make_request(urljoin(self.scanner.target_url, '/login'))
            csrf_token = None
            if login_page:
                csrf_token = extract_csrf_token(login_page.text)
            
            login_data = {
                'login': test_user,
                'password': f'invalid_password_{attempt}'
            }
            
            if csrf_token:
                login_data['authenticity_token'] = csrf_token
            
            start_time = time.time()
            response = self.scanner.make_request(login_url, method='POST', data=login_data)
            response_time = time.time() - start_time
            
            if response:
                if response.status_code == 429:
                    # Rate limiting detected
                    bf_result = {
                        'protection': 'rate_limiting',
                        'attempts_before_block': attempt + 1,
                        'status': 'protected',
                        'description': 'Rate limiting protection detected'
                    }
                    self.results['brute_force_results'].append(bf_result)
                    self.scanner.log("Brute force protection detected (rate limiting)", 'success')
                    break
                
                elif 'captcha' in response.text.lower():
                    # CAPTCHA protection
                    bf_result = {
                        'protection': 'captcha',
                        'attempts_before_captcha': attempt + 1,
                        'status': 'protected',
                        'description': 'CAPTCHA protection detected'
                    }
                    self.results['brute_force_results'].append(bf_result)
                    self.scanner.log("Brute force protection detected (CAPTCHA)", 'success')
                    break
                
                elif response_time > 3.0:
                    # Possible delay-based protection
                    bf_result = {
                        'protection': 'delay_based',
                        'response_time': response_time,
                        'status': 'possible_protection',
                        'description': f'Slow response detected ({response_time:.2f}s)'
                    }
                    self.results['brute_force_results'].append(bf_result)
                
                failed_attempts += 1
            
            self.results['tests_performed'] += 1
            time.sleep(1.0)
        
        # If no protection detected after max attempts
        if failed_attempts == max_attempts:
            bf_result = {
                'protection': 'none_detected',
                'attempts_tested': max_attempts,
                'status': 'vulnerable',
                'severity': 'medium',
                'description': 'No brute force protection detected in limited testing'
            }
            self.results['brute_force_results'].append(bf_result)
            self.scanner.log("No brute force protection detected", 'warning')
    
    def _test_session_management(self):
        """Test session management security"""
        self.scanner.log("Testing session management...", 'debug')
        
        # Test session fixation
        session_url = urljoin(self.scanner.target_url, '/session')
        
        # Get initial session
        response1 = self.scanner.make_request(self.scanner.target_url)
        if response1:
            initial_cookies = response1.cookies
            
            # Attempt login (will fail but might change session)
            login_data = {
                'login': 'testuser',
                'password': 'testpass'
            }
            
            response2 = self.scanner.make_request(session_url, method='POST', 
                                                data=login_data, cookies=initial_cookies)
            
            if response2:
                final_cookies = response2.cookies
                
                # Check if session ID changed
                session_changed = False
                for cookie_name in initial_cookies.keys():
                    if (cookie_name in final_cookies and 
                        initial_cookies[cookie_name] != final_cookies[cookie_name]):
                        session_changed = True
                        break
                
                if not session_changed:
                    session_issue = {
                        'issue': 'session_fixation_possible',
                        'severity': 'medium',
                        'description': 'Session ID does not change after login attempt'
                    }
                    self.results['session_issues'].append(session_issue)
                    self.scanner.log("Possible session fixation vulnerability", 'warning')
        
        # Test session cookie security
        response = self.scanner.make_request(self.scanner.target_url)
        if response:
            for cookie_name, cookie_value in response.cookies.items():
                cookie_obj = response.cookies.get(cookie_name)
                
                issues = []
                if not cookie_obj.secure:
                    issues.append('not_secure')
                if not cookie_obj.get('httponly'):
                    issues.append('not_httponly')
                if not cookie_obj.get('samesite'):
                    issues.append('no_samesite')
                
                if issues:
                    session_issue = {
                        'issue': 'insecure_cookie_attributes',
                        'cookie_name': cookie_name,
                        'problems': issues,
                        'severity': 'low',
                        'description': f'Cookie {cookie_name} has security issues: {issues}'
                    }
                    self.results['session_issues'].append(session_issue)
        
        self.results['tests_performed'] += 1
    
    def _test_password_reset_flaws(self):
        """Test password reset functionality for flaws"""
        self.scanner.log("Testing password reset flaws...", 'debug')
        
        # Test password reset token in URL
        reset_endpoints = [
            '/password-reset',
            '/users/password/new',
            '/session/forgot_password'
        ]
        
        for endpoint in reset_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                # Check if reset form is accessible
                if 'password' in response.text.lower() and 'reset' in response.text.lower():
                    # Look for potential issues in the form
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Check for token in URL parameters
                    if 'token=' in response.url or 'reset_token=' in response.url:
                        reset_issue = {
                            'issue': 'token_in_url',
                            'endpoint': endpoint,
                            'severity': 'medium',
                            'description': 'Password reset token exposed in URL'
                        }
                        self.results['password_reset_issues'].append(reset_issue)
                        self.scanner.log("Password reset token in URL detected", 'warning')
                    
                    # Check for missing CSRF protection
                    csrf_token = extract_csrf_token(response.text)
                    if not csrf_token:
                        reset_issue = {
                            'issue': 'missing_csrf_protection',
                            'endpoint': endpoint,
                            'severity': 'medium',
                            'description': 'Password reset form lacks CSRF protection'
                        }
                        self.results['password_reset_issues'].append(reset_issue)
            
            self.results['tests_performed'] += 1
            time.sleep(0.1)
    
    def _test_registration_flaws(self):
        """Test user registration for security flaws"""
        self.scanner.log("Testing registration flaws...", 'debug')
        
        signup_url = urljoin(self.scanner.target_url, '/u')
        signup_page_url = urljoin(self.scanner.target_url, '/signup')
        
        # Check if registration is open
        response = self.scanner.make_request(signup_page_url)
        
        if response and response.status_code == 200:
            if 'signup' in response.text.lower() or 'register' in response.text.lower():
                # Registration appears to be available
                
                # Test for missing CSRF protection
                csrf_token = extract_csrf_token(response.text)
                if not csrf_token:
                    reg_issue = {
                        'issue': 'missing_csrf_protection',
                        'severity': 'medium',
                        'description': 'Registration form lacks CSRF protection'
                    }
                    self.results['registration_issues'].append(reg_issue)
                
                # Test for weak username validation
                test_usernames = ['admin2', 'administrator2', 'root2', 'test123']
                
                for username in test_usernames[:2]:  # Limited testing
                    reg_data = {
                        'username': username,
                        'email': f'{username}@example.com',
                        'password': 'TestPassword123!'
                    }
                    
                    if csrf_token:
                        reg_data['authenticity_token'] = csrf_token
                    
                    reg_response = self.scanner.make_request(signup_url, method='POST', data=reg_data)
                    
                    if reg_response:
                        if reg_response.status_code == 200 and 'success' in reg_response.text.lower():
                            reg_issue = {
                                'issue': 'weak_username_validation',
                                'username': username,
                                'severity': 'low',
                                'description': f'Potentially sensitive username {username} allowed'
                            }
                            self.results['registration_issues'].append(reg_issue)
                    
                    self.results['tests_performed'] += 1
                    time.sleep(1.0)
        
        self.results['tests_performed'] += 1
    
    def _test_privilege_escalation(self):
        """Test for privilege escalation vulnerabilities"""
        self.scanner.log("Testing privilege escalation...", 'debug')
        
        # Test parameter manipulation for privilege escalation
        admin_endpoints = [
            '/admin/users',
            '/admin/dashboard',
            '/admin/site_settings'
        ]
        
        # Test with various privilege escalation parameters
        escalation_params = {
            'admin': 'true',
            'is_admin': '1',
            'role': 'admin',
            'trust_level': '4',
            'moderator': 'true',
            'staff': 'true'
        }
        
        for endpoint in admin_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            
            # Test direct access first
            response = self.scanner.make_request(url)
            if response and response.status_code == 200:
                # Already accessible - not a privilege escalation issue
                continue
            
            # Test with escalation parameters
            for param, value in escalation_params.items():
                test_url = f"{url}?{param}={value}"
                response = self.scanner.make_request(test_url)
                
                if response and response.status_code == 200:
                    if 'admin' in response.text.lower() or 'dashboard' in response.text.lower():
                        priv_issue = {
                            'issue': 'parameter_based_privilege_escalation',
                            'endpoint': endpoint,
                            'parameter': f'{param}={value}',
                            'severity': 'critical',
                            'description': f'Privilege escalation via {param} parameter'
                        }
                        self.results['privilege_escalation'].append(priv_issue)
                        self.scanner.log(f"Privilege escalation found: {param}={value}", 'error')
                
                self.results['tests_performed'] += 1
                time.sleep(0.1)