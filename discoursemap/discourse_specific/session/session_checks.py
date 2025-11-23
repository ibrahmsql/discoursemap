#!/usr/bin/env python3
"""
Session Checks

Handles session fixation, timeout, and concurrency tests.
"""

import requests
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin
from colorama import Fore, Style


class SessionChecks:
    """Advanced session security checks"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None, verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
    
    def test_session_fixation(self) -> Dict[str, Any]:
        """Test for session fixation vulnerabilities"""
        results = {
            'session_regenerated': False,
            'vulnerable': False,
            'issues': [],
            'note': 'Test requires authenticated session to verify fixation'
        }
        
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing session fixation...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Skipping simulated login check (auth required){Style.RESET_ALL}")
        
        return results

    def test_session_timeout(self) -> Dict[str, Any]:
        """Test session timeout configuration"""
        results = {
            'cookies_with_timeout': [],
            'configured': False,
            'issues': []
        }
        
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing session timeout...{Style.RESET_ALL}")
        
        try:
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
            
            results['cookies_with_timeout'] = timeout_info
            results['configured'] = len(timeout_info) > 0
            
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error testing timeout: {e}{Style.RESET_ALL}")
        
        return results

    def test_concurrent_sessions(self) -> Dict[str, Any]:
        """Test concurrent session handling"""
        results = {
            'tested': False,
            'sessions_established': 0,
            'unique_sessions': 0,
            'concurrent_allowed': False,
            'issues': []
        }
        
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing concurrent sessions...{Style.RESET_ALL}")
        
        try:
            # Create multiple sessions
            sessions = [requests.Session() for _ in range(3)]
            session_ids = []
            
            # Establish sessions
            for session in sessions:
                try:
                    response = session.get(self.target_url, timeout=10)
                    # Extract session cookie if exists
                    for cookie in session.cookies:
                        if 'session' in cookie.name.lower() or '_t' in cookie.name:
                            session_ids.append({
                                'cookie_name': cookie.name,
                                'value': cookie.value
                            })
                except Exception:
                    continue
            
            # Analyze results
            unique_sessions = len(set(s['value'] for s in session_ids))
            concurrent_allowed = unique_sessions > 1
            
            results.update({
                'tested': True,
                'sessions_established': len(session_ids),
                'unique_sessions': unique_sessions,
                'concurrent_allowed': concurrent_allowed
            })
            
            if concurrent_allowed and unique_sessions > 1:
                results['issues'].append({
                    'type': 'Concurrent Sessions Allowed',
                    'severity': 'MEDIUM',
                    'description': f'Multiple concurrent sessions detected ({unique_sessions} unique)'
                })
                
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error testing concurrent sessions: {e}{Style.RESET_ALL}")
            results['error'] = str(e)
            
        return results

    def test_session_regeneration(self) -> Dict[str, Any]:
        """Test session regeneration (partial check)"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing session regeneration...{Style.RESET_ALL}")
        
        return {
            'tested': 'partial',
            'note': 'Full test requires authenticated access'
        }
