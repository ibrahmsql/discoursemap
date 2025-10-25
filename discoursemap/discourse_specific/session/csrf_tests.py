#!/usr/bin/env python3
"""
CSRF Protection Tests

Handles CSRF protection testing functionality.
"""

import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style


class CSRFTests:
    """CSRF protection testing functionality"""
    
    def __init__(self, target_url, session=None, verbose=False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
    
    def test_csrf_protection(self):
        """Test CSRF protection mechanisms"""
        results = {
            'csrf_token_present': False,
            'csrf_validation': False,
            'csrf_bypass_attempts': [],
            'issues': []
        }
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing CSRF protection...{Style.RESET_ALL}")
        
        try:
            # Get main page to check for CSRF tokens
            response = self.session.get(self.target_url, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check for CSRF token in meta tags
                csrf_meta = soup.find('meta', {'name': 'csrf-token'})
                if csrf_meta:
                    results['csrf_token_present'] = True
                    csrf_token = csrf_meta.get('content')
                    
                    if self.verbose:
                        print(f"  CSRF token found: {csrf_token[:20]}...")
                    
                    # Test CSRF validation
                    results['csrf_validation'] = self._test_csrf_validation(csrf_token)
                else:
                    results['issues'].append({
                        'issue': 'No CSRF token found',
                        'severity': 'high',
                        'description': 'CSRF token not present in page meta tags'
                    })
                
                # Test CSRF bypass attempts
                results['csrf_bypass_attempts'] = self._test_csrf_bypass()
            
        except Exception as e:
            if self.verbose:
                print(f"  Error testing CSRF: {e}")
        
        return results
    
    def _test_csrf_validation(self, csrf_token):
        """Test if CSRF token is properly validated"""
        if self.verbose:
            print(f"  Testing CSRF validation...")
        
        try:
            # Test with valid token
            test_url = urljoin(self.target_url, '/session')
            headers = {'X-CSRF-Token': csrf_token}
            response = self.session.post(test_url, headers=headers, timeout=5)
            
            # Test with invalid token
            invalid_headers = {'X-CSRF-Token': 'invalid_token_123'}
            invalid_response = self.session.post(test_url, headers=invalid_headers, timeout=5)
            
            # If both succeed, CSRF validation might be weak
            if response.status_code == invalid_response.status_code:
                return False
            
            return True
            
        except Exception:
            return False
    
    def _test_csrf_bypass(self):
        """Test various CSRF bypass techniques"""
        bypass_attempts = []
        
        if self.verbose:
            print(f"  Testing CSRF bypass techniques...")
        
        # CSRF bypass methods
        bypass_methods = [
            {'method': 'No token', 'headers': {}},
            {'method': 'Empty token', 'headers': {'X-CSRF-Token': ''}},
            {'method': 'Wrong header name', 'headers': {'X-XSRF-Token': 'test'}},
            {'method': 'Double submit', 'headers': {'X-CSRF-Token': 'test'}, 'cookies': {'csrf_token': 'test'}},
            {'method': 'Null byte', 'headers': {'X-CSRF-Token': 'test\x00'}},
            {'method': 'Case manipulation', 'headers': {'x-csrf-token': 'test'}}
        ]
        
        for method in bypass_methods:
            try:
                test_url = urljoin(self.target_url, '/posts')
                test_data = {'title': 'Test', 'raw': 'Test content', 'category': 1}
                
                kwargs = {
                    'data': test_data,
                    'timeout': 5
                }
                
                if 'headers' in method:
                    kwargs['headers'] = method['headers']
                if 'cookies' in method:
                    for name, value in method['cookies'].items():
                        self.session.cookies.set(name, value)
                
                response = self.session.post(test_url, **kwargs)
                
                if response.status_code in [200, 201]:
                    bypass_attempt = {
                        'method': method['method'],
                        'success': True,
                        'severity': 'high',
                        'description': f'CSRF bypass via {method["method"]}'
                    }
                    bypass_attempts.append(bypass_attempt)
                    
                    if self.verbose:
                        print(f"    CSRF bypass: {method['method']}")
                
                # Clean up cookies
                if 'cookies' in method:
                    for name in method['cookies']:
                        self.session.cookies.pop(name, None)
                
            except Exception:
                continue
        
        return bypass_attempts