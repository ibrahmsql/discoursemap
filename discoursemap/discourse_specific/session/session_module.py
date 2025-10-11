#!/usr/bin/env python3
"""
Discourse Session Security Module

Tests session management, cookie security, CSRF protection, and session fixation vulnerabilities.
"""

import requests
import hashlib
import time
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin
from http.cookies import SimpleCookie


class SessionSecurityModule:
    """Session security testing for Discourse"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        """
                 Create a SessionSecurityModule configured for the given Discourse target and initialize its internal state.
                 
                 Parameters:
                     target_url: Base URL of the Discourse instance (trailing slash will be removed).
                     session: Optional requests.Session to use for HTTP interactions; a new session is created if omitted.
                     verbose: Enable verbose logging of test progress and errors.
                 
                 Notes:
                     Initializes the `results` dictionary with keys for cookie_security, csrf_protection,
                     session_fixation, session_timeout, vulnerabilities, and recommendations.
                 """
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.results = {
            'cookie_security': {},
            'csrf_protection': {},
            'session_fixation': {},
            'session_timeout': {},
            'vulnerabilities': [],
            'recommendations': []
        }
    
    def scan(self) -> Dict[str, Any]:
        """
        Run the module's suite of session security tests and collect their findings.
        
        Returns:
            results (dict): Scan results containing keys:
                - 'cookie_security': details and issues found for cookies
                - 'csrf_protection': detected CSRF indicators and protected endpoints
                - 'session_fixation': whether session IDs are regenerated after login
                - 'session_timeout': cookies with expiry information and timeouts
                - 'concurrent_sessions': notes about concurrent session testing
                - 'session_regeneration': notes about session regeneration on privilege changes
                - 'vulnerabilities': list of detected vulnerabilities with severity and descriptions
                - 'recommendations': actionable remediation suggestions based on findings
        """
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting Discourse session security scan...{Style.RESET_ALL}")
        
        self._test_cookie_security()
        self._test_csrf_protection()
        self._test_session_fixation()
        self._test_session_timeout()
        self._test_concurrent_sessions()
        self._test_session_regeneration()
        self._check_secure_cookies()
        
        self._generate_recommendations()
        
        return self.results
    
    def _test_cookie_security(self):
        """
        Analyze cookies returned by the target site for missing security attributes.
        
        Inspects cookies in the current session for the Secure flag, HttpOnly attribute, and SameSite attribute and records any issues found. Populates self.results['cookie_security'] with 'cookies_found' and a detailed 'cookies' list, and appends 'Insecure Cookie' entries to self.results['vulnerabilities'] for cookies that lack required attributes.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing cookie security...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            cookies_analysis = []
            for cookie in self.session.cookies:
                cookie_info = {
                    'name': cookie.name,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                    'samesite': cookie.get_nonstandard_attr('SameSite', None),
                    'domain': cookie.domain,
                    'path': cookie.path
                }
                
                # Check for security issues
                issues = []
                if not cookie.secure:
                    issues.append('Missing Secure flag')
                if not cookie_info['httponly']:
                    issues.append('Missing HttpOnly flag')
                if not cookie_info['samesite']:
                    issues.append('Missing SameSite attribute')
                
                cookie_info['issues'] = issues
                cookies_analysis.append(cookie_info)
                
                if issues:
                    self.results['vulnerabilities'].append({
                        'type': 'Insecure Cookie',
                        'cookie': cookie.name,
                        'issues': issues,
                        'severity': 'MEDIUM'
                    })
            
            self.results['cookie_security'] = {
                'cookies_found': len(cookies_analysis),
                'cookies': cookies_analysis
            }
            
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error testing cookies: {e}{Style.RESET_ALL}")
    
    def _test_csrf_protection(self):
        """
        Check whether the target site enforces CSRF protections and record findings in self.results.
        
        Performs a GET of the target page and inspects the response and session cookies for CSRF tokens, then attempts unauthenticated POST requests to common endpoints to infer whether CSRF enforcement is required. Results are stored in self.results['csrf_protection'] with the keys:
        - `tokens_found`: list of detected CSRF indicators (e.g., meta tag or cookie names)
        - `protected_endpoints`: list of endpoints that appear to require CSRF protection
        - `protection_enabled`: boolean indicating whether any CSRF indicators were detected
        
        If no CSRF indicators are found, a vulnerability entry of type "Missing CSRF Protection" (severity "HIGH") is appended to self.results['vulnerabilities'].
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing CSRF protection...{Style.RESET_ALL}")
        
        csrf_tokens = []
        
        try:
            # Check main page for CSRF token
            response = self.session.get(self.target_url, timeout=10)
            
            # Look for CSRF token in meta tags
            if 'csrf-token' in response.text.lower():
                csrf_tokens.append('Meta tag CSRF token found')
            
            # Check if CSRF token is in cookies
            csrf_cookie = None
            for cookie in self.session.cookies:
                if 'csrf' in cookie.name.lower():
                    csrf_cookie = cookie.name
                    csrf_tokens.append(f'CSRF cookie: {cookie.name}')
            
            # Test POST without CSRF token
            test_endpoints = [
                '/session',
                '/posts',
                '/topics'
            ]
            
            csrf_required = []
            for endpoint in test_endpoints:
                try:
                    url = urljoin(self.target_url, endpoint)
                    # Create new session without CSRF token
                    test_session = requests.Session()
                    resp = test_session.post(url, json={'test': 'data'}, timeout=5)
                    
                    if resp.status_code == 403 or 'csrf' in resp.text.lower():
                        csrf_required.append(endpoint)
                except Exception:
                    pass
            
            self.results['csrf_protection'] = {
                'tokens_found': csrf_tokens,
                'protected_endpoints': csrf_required,
                'protection_enabled': len(csrf_tokens) > 0
            }
            
            if not csrf_tokens:
                self.results['vulnerabilities'].append({
                    'type': 'Missing CSRF Protection',
                    'severity': 'HIGH',
                    'description': 'No CSRF tokens detected'
                })
                
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error testing CSRF: {e}{Style.RESET_ALL}")
    
    def _test_session_fixation(self):
        """
        Detect whether the session identifier is regenerated following an authentication attempt.
        
        Performs a login request and compares cookies before and after the attempt to determine if the session ID changed. Records results in self.results['session_fixation'] with keys:
        - `session_regenerated` (bool): True if a session cookie value changed after the login attempt.
        - `vulnerable` (bool): True if session regeneration was not observed.
        
        If regeneration is not observed, appends a HIGH-severity vulnerability entry to self.results['vulnerabilities'] describing a potential session fixation issue.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing session fixation...{Style.RESET_ALL}")
        
        try:
            # Get initial session
            session1 = requests.Session()
            resp1 = session1.get(self.target_url, timeout=10)
            initial_cookies = {c.name: c.value for c in session1.cookies}
            
            # Simulate login (will fail but we check if session changes)
            login_url = urljoin(self.target_url, '/session')
            resp2 = session1.post(
                login_url,
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
            
            self.results['session_fixation'] = {
                'session_regenerated': session_changed,
                'vulnerable': not session_changed
            }
            
            if not session_changed:
                self.results['vulnerabilities'].append({
                    'type': 'Session Fixation',
                    'severity': 'HIGH',
                    'description': 'Session ID not regenerated after login attempt'
                })
                
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error testing session fixation: {e}{Style.RESET_ALL}")
    
    def _test_session_timeout(self):
        """
        Collects session cookie expiry information and records whether session timeouts are configured.
        
        Scans the current session's cookies for those that include an `expires` attribute, computes the remaining time until expiry in seconds and hours for each such cookie, and stores the findings in `self.results['session_timeout']` as a dict with:
        - `cookies_with_timeout`: list of dicts each containing `cookie` (name), `expires_in_seconds`, and `expires_in_hours`.
        - `configured`: boolean indicating whether any expiring cookies were found.
        
        On failure the method does not populate `self.results['session_timeout']` (errors are surfaced when verbose mode is enabled).
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing session timeout...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Check for session cookies with expiry
            timeout_info = []
            for cookie in self.session.cookies:
                if cookie.expires:
                    duration = cookie.expires - time.time()
                    timeout_info.append({
                        'cookie': cookie.name,
                        'expires_in_seconds': duration,
                        'expires_in_hours': duration / 3600
                    })
            
            self.results['session_timeout'] = {
                'cookies_with_timeout': timeout_info,
                'configured': len(timeout_info) > 0
            }
            
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error testing timeout: {e}{Style.RESET_ALL}")
    
    def _test_concurrent_sessions(self):
        """
        Determine whether multiple concurrent sessions for a single account are permitted.
        
        This method is a placeholder that records that credentialed testing is required and does not perform authentication. It sets self.results['concurrent_sessions'] to indicate the test was not executed and that valid credentials are needed for a full concurrent-session test.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing concurrent sessions...{Style.RESET_ALL}")
        
        # This would require valid credentials, so we just document the test
        self.results['concurrent_sessions'] = {
            'tested': False,
            'note': 'Requires valid credentials for full test'
        }
    
    def _test_session_regeneration(self):
        """
        Record that session regeneration testing was only partially executed because authenticated access is required.
        
        This sets self.results['session_regeneration'] to indicate a partial test and includes a note that a full verification of session ID regeneration on privilege escalation requires authenticated credentials.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing session regeneration...{Style.RESET_ALL}")
        
        self.results['session_regeneration'] = {
            'tested': 'partial',
            'note': 'Full test requires authenticated access'
        }
    
    def _check_secure_cookies(self):
        """
        Determine whether the target site enforces HTTPS for cookie transmission.
        
        If the target URL does not start with "https://", appends a CRITICAL "Insecure Transmission" vulnerability entry to self.results['vulnerabilities'].
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking secure cookie transmission...{Style.RESET_ALL}")
        
        # Check if HTTPS is enforced
        secure_transmission = self.target_url.startswith('https://')
        
        if not secure_transmission:
            self.results['vulnerabilities'].append({
                'type': 'Insecure Transmission',
                'severity': 'CRITICAL',
                'description': 'Site not using HTTPS'
            })
    
    def _generate_recommendations(self):
        """
        Populate self.results['recommendations'] with actionable remediation entries based on the scan findings.
        
        This method inspects the module's accumulated results and constructs a list of recommendations reflecting detected issues. It adds:
        - a MEDIUM-severity recommendation listing cookies with missing Secure/HttpOnly/SameSite attributes,
        - a HIGH-severity recommendation if CSRF protection was not detected,
        - a HIGH-severity recommendation if a session fixation vulnerability was identified.
        The resulting list is stored in self.results['recommendations'], replacing any previous value.
        """
        recommendations = []
        
        # Cookie security recommendations
        if self.results['cookie_security'].get('cookies'):
            insecure_cookies = [c for c in self.results['cookie_security']['cookies'] 
                              if c.get('issues')]
            if insecure_cookies:
                recommendations.append({
                    'severity': 'MEDIUM',
                    'issue': 'Insecure cookie attributes detected',
                    'recommendation': 'Set Secure, HttpOnly, and SameSite flags on all cookies',
                    'affected': [c['name'] for c in insecure_cookies]
                })
        
        # CSRF recommendations
        if not self.results['csrf_protection'].get('protection_enabled'):
            recommendations.append({
                'severity': 'HIGH',
                'issue': 'CSRF protection not detected',
                'recommendation': 'Implement CSRF tokens for all state-changing operations'
            })
        
        # Session fixation recommendations
        if self.results['session_fixation'].get('vulnerable'):
            recommendations.append({
                'severity': 'HIGH',
                'issue': 'Potential session fixation vulnerability',
                'recommendation': 'Regenerate session ID after authentication'
            })
        
        self.results['recommendations'] = recommendations
    
    def print_results(self):
        """
        Output a formatted summary of the module's scan results to standard output.
        
        The summary includes sections for cookie security (per-cookie issues and counts), CSRF protection status, enumerated vulnerabilities with severity and descriptions, and actionable recommendations.
        """
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"Discourse Session Security Scan Results")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        # Cookie security
        if self.results['cookie_security']:
            print(f"{Fore.YELLOW}[*] Cookie Security:{Style.RESET_ALL}")
            print(f"  Cookies found: {self.results['cookie_security'].get('cookies_found', 0)}")
            
            for cookie in self.results['cookie_security'].get('cookies', []):
                status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if not cookie['issues'] else f"{Fore.RED}✗{Style.RESET_ALL}"
                print(f"  {status} {cookie['name']}")
                if cookie['issues']:
                    for issue in cookie['issues']:
                        print(f"      • {issue}")
        
        # CSRF protection
        print(f"\n{Fore.YELLOW}[*] CSRF Protection:{Style.RESET_ALL}")
        csrf_status = "ENABLED" if self.results['csrf_protection'].get('protection_enabled') else "DISABLED"
        color = Fore.GREEN if csrf_status == "ENABLED" else Fore.RED
        print(f"  Status: {color}{csrf_status}{Style.RESET_ALL}")
        
        # Vulnerabilities
        if self.results['vulnerabilities']:
            print(f"\n{Fore.RED}[!] Vulnerabilities Found: {len(self.results['vulnerabilities'])}{Style.RESET_ALL}")
            for vuln in self.results['vulnerabilities']:
                print(f"  [{vuln['severity']}] {vuln['type']}")
                if 'description' in vuln:
                    print(f"      {vuln['description']}")
        
        # Recommendations
        if self.results['recommendations']:
            print(f"\n{Fore.YELLOW}[*] Recommendations:{Style.RESET_ALL}")
            for rec in self.results['recommendations']:
                print(f"  [{rec['severity']}] {rec['issue']}")
                print(f"      → {rec['recommendation']}")