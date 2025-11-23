#!/usr/bin/env python3
"""
Discourse Session Security Module

Orchestrates session security tests using specialized sub-modules.
"""

import requests
from typing import Dict, Any, Optional
from colorama import Fore, Style

from .cookie_security import CookieSecurity
from .csrf_tests import CSRFTests
from .session_checks import SessionChecks


class SessionSecurityModule:
    """Session security testing for Discourse"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.results = {
            'cookie_security': {},
            'csrf_protection': {},
            'session_fixation': {},
            'session_timeout': {},
            'concurrent_sessions': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Initialize sub-modules
        self.cookie_tester = CookieSecurity(self.target_url, self.session, self.verbose)
        self.csrf_tester = CSRFTests(self.target_url, self.session, self.verbose)
        self.session_checker = SessionChecks(self.target_url, self.session, self.verbose)
    
    def run(self) -> Dict[str, Any]:
        """Run the session security scan (wrapper for scan method)"""
        return self.scan()
    
    def scan(self) -> Dict[str, Any]:
        """Run the session security scan"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting Discourse session security scan...{Style.RESET_ALL}")
        
        # Run sub-modules
        self.results['cookie_security'] = self.cookie_tester.test_cookie_security()
        self.results['csrf_protection'] = self.csrf_tester.test_csrf_protection()
        
        # Run advanced checks
        self.results['session_fixation'] = self.session_checker.test_session_fixation()
        self.results['session_timeout'] = self.session_checker.test_session_timeout()
        self.results['concurrent_sessions'] = self.session_checker.test_concurrent_sessions()
        self.results['session_regeneration'] = self.session_checker.test_session_regeneration()
        
        # Check secure transmission
        self._check_secure_cookies()
        
        # Collect vulnerabilities
        self._collect_vulnerabilities()
        
        # Generate recommendations
        self._generate_recommendations()
        
        return self.results
    
    def _check_secure_cookies(self):
        """Check if HTTPS is used"""
        if not self.target_url.startswith('https://'):
            self.results['vulnerabilities'].append({
                'type': 'Insecure Transmission',
                'severity': 'CRITICAL',
                'description': 'Site not using HTTPS'
            })

    def _collect_vulnerabilities(self):
        """Aggregate vulnerabilities from all sub-modules"""
        # Cookie vulnerabilities
        if 'issues' in self.results['cookie_security']:
            for issue in self.results['cookie_security']['issues']:
                self.results['vulnerabilities'].append({
                    'type': 'Insecure Cookie',
                    'description': issue.get('description', issue.get('issue')),
                    'severity': issue.get('severity', 'MEDIUM').upper()
                })

        # CSRF vulnerabilities
        if 'issues' in self.results['csrf_protection']:
            for issue in self.results['csrf_protection']['issues']:
                self.results['vulnerabilities'].append({
                    'type': 'CSRF Issue',
                    'description': issue.get('description', issue.get('issue')),
                    'severity': issue.get('severity', 'HIGH').upper()
                })
        
        if 'csrf_bypass_attempts' in self.results['csrf_protection']:
            for bypass in self.results['csrf_protection']['csrf_bypass_attempts']:
                self.results['vulnerabilities'].append({
                    'type': 'CSRF Bypass',
                    'description': bypass.get('description'),
                    'severity': bypass.get('severity', 'HIGH').upper()
                })

        # Session Check vulnerabilities
        for check in ['session_fixation', 'concurrent_sessions']:
            if 'issues' in self.results[check]:
                for issue in self.results[check]['issues']:
                    self.results['vulnerabilities'].append(issue)

    def _generate_recommendations(self):
        """Generate recommendations based on findings"""
        recommendations = []
        
        # Cookie recommendations
        if self.results['cookie_security'].get('issues'):
            recommendations.append({
                'severity': 'MEDIUM',
                'issue': 'Insecure cookie attributes detected',
                'recommendation': 'Set Secure, HttpOnly, and SameSite flags on all cookies'
            })
        
        # CSRF recommendations
        if not self.results['csrf_protection'].get('csrf_token_present'):
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
