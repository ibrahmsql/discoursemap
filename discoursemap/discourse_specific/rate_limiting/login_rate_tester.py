#!/usr/bin/env python3
"""
Login Rate Limiting Tester

Specialized module for testing rate limits on authentication endpoints.
"""

import time
import requests
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin


class LoginRateTester:
    """Tests rate limiting on login/authentication endpoints"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
    
    def test_login_rate_limit(self) -> Dict[str, Any]:
        """Test rate limiting on login endpoint"""
        endpoint = urljoin(self.target_url, '/session')
        
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing login rate limit...{Style.RESET_ALL}")
        
        attempts = 0
        rate_limited = False
        result = {}
        
        for i in range(10):
            try:
                response = self.session.post(
                    endpoint,
                    json={'login': 'testuser', 'password': 'testpass'},
                    timeout=10
                )
                attempts += 1
                
                if response.status_code == 429:
                    rate_limited = True
                    result = {
                        'endpoint': '/session',
                        'type': 'login',
                        'triggered_after': attempts,
                        'status_code': 429,
                        'headers': dict(response.headers),
                        'rate_limited': True
                    }
                    break
                    
                time.sleep(0.3)
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing login rate limit: {e}{Style.RESET_ALL}")
                break
        
        if not rate_limited:
            result = {
                'endpoint': '/session',
                'rate_limited': False,
                'attempts': attempts,
                'severity': 'HIGH',
                'issue': 'No rate limiting detected on login endpoint'
            }
        
        return result
    
    def test_password_reset_rate_limit(self) -> Dict[str, Any]:
        """Test rate limiting on password reset endpoint"""
        endpoint = urljoin(self.target_url, '/session/forgot_password')
        
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing password reset rate limit...{Style.RESET_ALL}")
        
        attempts = 0
        rate_limited = False
        result = {}
        
        for i in range(5):
            try:
                response = self.session.post(
                    endpoint,
                    json={'login': 'test@example.com'},
                    timeout=10
                )
                attempts += 1
                
                if response.status_code == 429:
                    rate_limited = True
                    result = {
                        'endpoint': '/session/forgot_password',
                        'type': 'password_reset',
                        'triggered_after': attempts,
                        'status_code': 429,
                        'headers': dict(response.headers),
                        'rate_limited': True
                    }
                    break
                    
                time.sleep(0.5)
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing password reset rate limit: {e}{Style.RESET_ALL}")
                break
        
        if not rate_limited:
            result = {
                'endpoint': '/session/forgot_password',
                'rate_limited': False,
                'attempts': attempts,
                'severity': 'MEDIUM',
                'issue': 'No rate limiting detected on password reset'
            }
        
        return result