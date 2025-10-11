#!/usr/bin/env python3
"""
Authentication Bypass Techniques

Various authentication bypass testing methods.
"""

import base64
from urllib.parse import urljoin


class AuthBypassTester:
    """Authentication bypass testing"""
    
    def __init__(self, scanner):
        """
        Initialize the AuthBypassTester with a scanner client and prepare an empty results list.
        
        Parameters:
            scanner: Scanner client used to perform HTTP requests and inspect responses during bypass tests. The instance is stored on the object as `self.scanner`. An empty list `self.results` is created to collect findings from each test.
        """
        self.scanner = scanner
        self.results = []
    
    def test_all_bypasses(self):
        """
        Run the full suite of authentication-bypass checks and collect findings.
        
        Executes SQL injection, default credentials, session fixation, JWT exposure, and OAuth CSRF checks in sequence and aggregates their findings.
        
        Returns:
            results (list): Collected findings from all tests (each entry is a finding dictionary).
        """
        self.test_sql_injection_bypass()
        self.test_default_credentials()
        self.test_session_fixation()
        self.test_jwt_vulnerabilities()
        self.test_oauth_flaws()
        
        return self.results
    
    def test_sql_injection_bypass(self):
        """
        Detects authentication bypass by submitting common SQL injection payloads to the target's /session endpoint.
        
        When a response indicates a session was established (HTTP 200 and the response body contains "session"), a finding is appended to self.results. Each finding is a dict with keys: 'type' ("SQL Injection Bypass"), 'severity' ("critical"), 'payload', and 'description'.
        """
        payloads = [
            "admin' OR '1'='1",
            "admin'--",
            "' OR 1=1--",
            "admin' OR 'x'='x"
        ]
        
        login_url = urljoin(self.scanner.target_url, '/session')
        
        for payload in payloads:
            try:
                response = self.scanner.make_request(
                    login_url,
                    method='POST',
                    json={'login': payload, 'password': 'test'},
                    timeout=5
                )
                
                if response and response.status_code == 200:
                    if 'session' in response.text.lower():
                        self.results.append({
                            'type': 'SQL Injection Bypass',
                            'severity': 'critical',
                            'payload': payload,
                            'description': 'Potential SQL injection bypass detected'
                        })
            except Exception:
                continue
    
    def test_default_credentials(self):
        """
        Check the target for active default authentication credentials.
        
        Attempts a set of common username/password pairs against the target's /session endpoint; if a response indicates a likely successful login (HTTP 200 and the response body does not contain the word "error"), appends a critical "Default Credentials" finding to self.results with the tested username. Checks are limited to the first two credential pairs.
        """
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('administrator', 'administrator')
        ]
        
        login_url = urljoin(self.scanner.target_url, '/session')
        
        for username, password in default_creds[:2]:  # Limit tests
            try:
                response = self.scanner.make_request(
                    login_url,
                    method='POST',
                    json={'login': username, 'password': password},
                    timeout=5
                )
                
                if response and response.status_code == 200:
                    if 'error' not in response.text.lower():
                        self.results.append({
                            'type': 'Default Credentials',
                            'severity': 'critical',
                            'username': username,
                            'description': f'Default credentials may be active: {username}'
                        })
            except Exception:
                continue
    
    def test_session_fixation(self):
        """
        Detect whether a session fixation vulnerability exists.
        
        Checks the initial session cookie named "_t", performs a login using that cookie, and if the session ID remains unchanged appends a high-severity "Session Fixation" finding to self.results. Exceptions and request failures are suppressed.
        """
        try:
            # Get initial session
            response1 = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if not response1:
                return
            
            session_cookie1 = response1.cookies.get('_t')
            
            # Try to login with same session
            login_url = urljoin(self.scanner.target_url, '/session')
            response2 = self.scanner.make_request(
                login_url,
                method='POST',
                json={'login': 'test', 'password': 'test'},
                cookies={'_t': session_cookie1} if session_cookie1 else None,
                timeout=5
            )
            
            if response2:
                session_cookie2 = response2.cookies.get('_t')
                
                if session_cookie1 and session_cookie2 and session_cookie1 == session_cookie2:
                    self.results.append({
                        'type': 'Session Fixation',
                        'severity': 'high',
                        'description': 'Session ID not regenerated after login'
                    })
        except Exception:
            pass
    
    def test_jwt_vulnerabilities(self):
        """
        Detects JWT-like tokens in the target's root HTTP response and records a finding if any are present.
        
        If one or more JWT-like tokens are found in the response body, a result with type "JWT Token Exposure", severity "medium", and the found token count is appended to self.results.
        """
        try:
            # Check for JWT tokens in responses
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if response:
                # Look for JWT pattern
                import re
                jwt_pattern = r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
                tokens = re.findall(jwt_pattern, response.text)
                
                if tokens:
                    self.results.append({
                        'type': 'JWT Token Exposure',
                        'severity': 'medium',
                        'token_count': len(tokens),
                        'description': f'JWT tokens found in response: {len(tokens)}'
                    })
        except Exception:
            pass
    
    def test_oauth_flaws(self):
        """
        Detects OAuth CSRF risks by checking common OAuth endpoints for a missing state parameter.
        
        For each common OAuth endpoint that returns status 200 or 302, appends a high-severity finding to self.results when the response does not contain a `state` parameter. Each finding is a dict with keys: `type` (set to "OAuth CSRF"), `severity` (set to "high"), `endpoint`, and `description`.
        """
        oauth_endpoints = [
            '/auth/google_oauth2',
            '/auth/facebook',
            '/auth/github',
            '/auth/twitter'
        ]
        
        for endpoint in oauth_endpoints:
            try:
                url = urljoin(self.scanner.target_url, endpoint)
                response = self.scanner.make_request(url, timeout=5)
                
                if response and response.status_code in [200, 302]:
                    # Check for missing state parameter
                    if 'state=' not in response.text:
                        self.results.append({
                            'type': 'OAuth CSRF',
                            'severity': 'high',
                            'endpoint': endpoint,
                            'description': 'OAuth flow missing state parameter - CSRF possible'
                        })
            except Exception:
                continue