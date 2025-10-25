#!/usr/bin/env python3
"""
Cookie Security Tests

Handles cookie security testing functionality.
"""

import requests
from urllib.parse import urljoin
from http.cookies import SimpleCookie
from colorama import Fore, Style


class CookieSecurity:
    """Cookie security testing functionality"""
    
    def __init__(self, target_url, session=None, verbose=False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
    
    def test_cookie_security(self):
        """Test cookie security attributes"""
        results = {
            'secure_flag': False,
            'httponly_flag': False,
            'samesite_attribute': None,
            'session_cookies': [],
            'persistent_cookies': [],
            'issues': []
        }
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing cookie security...{Style.RESET_ALL}")
        
        try:
            # Make request to get cookies
            response = self.session.get(self.target_url, timeout=10)
            
            if response.status_code == 200:
                # Analyze cookies from response
                for cookie_header in response.headers.get_list('Set-Cookie') or []:
                    cookie = SimpleCookie()
                    cookie.load(cookie_header)
                    
                    for key, morsel in cookie.items():
                        cookie_info = {
                            'name': key,
                            'value': morsel.value,
                            'secure': morsel.get('secure', False),
                            'httponly': morsel.get('httponly', False),
                            'samesite': morsel.get('samesite', None),
                            'expires': morsel.get('expires', None),
                            'max_age': morsel.get('max-age', None)
                        }
                        
                        # Categorize cookies
                        if cookie_info['expires'] or cookie_info['max_age']:
                            results['persistent_cookies'].append(cookie_info)
                        else:
                            results['session_cookies'].append(cookie_info)
                        
                        # Check security attributes
                        if not cookie_info['secure']:
                            results['issues'].append({
                                'cookie': key,
                                'issue': 'Missing Secure flag',
                                'severity': 'medium',
                                'description': f'Cookie {key} lacks Secure flag'
                            })
                        
                        if not cookie_info['httponly']:
                            results['issues'].append({
                                'cookie': key,
                                'issue': 'Missing HttpOnly flag',
                                'severity': 'medium',
                                'description': f'Cookie {key} lacks HttpOnly flag'
                            })
                        
                        if not cookie_info['samesite']:
                            results['issues'].append({
                                'cookie': key,
                                'issue': 'Missing SameSite attribute',
                                'severity': 'low',
                                'description': f'Cookie {key} lacks SameSite attribute'
                            })
                
                # Set overall flags
                results['secure_flag'] = all(c.get('secure', False) for c in results['session_cookies'])
                results['httponly_flag'] = all(c.get('httponly', False) for c in results['session_cookies'])
                
                if self.verbose:
                    print(f"  Found {len(results['session_cookies'])} session cookies")
                    print(f"  Found {len(results['persistent_cookies'])} persistent cookies")
                    print(f"  Security issues: {len(results['issues'])}")
            
        except Exception as e:
            if self.verbose:
                print(f"  Error testing cookies: {e}")
        
        return results
    
    def test_cookie_manipulation(self):
        """Test cookie manipulation vulnerabilities"""
        manipulation_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing cookie manipulation...{Style.RESET_ALL}")
        
        # Test various cookie manipulation techniques
        manipulation_tests = [
            {'name': 'admin', 'value': 'true'},
            {'name': 'user_id', 'value': '1'},
            {'name': 'trust_level', 'value': '4'},
            {'name': 'moderator', 'value': 'true'},
            {'name': 'staff', 'value': 'true'}
        ]
        
        for test in manipulation_tests:
            try:
                # Set malicious cookie
                self.session.cookies.set(test['name'], test['value'])
                
                # Test access to admin area
                admin_url = urljoin(self.target_url, '/admin')
                response = self.session.get(admin_url, timeout=5)
                
                if response.status_code == 200 and 'admin' in response.text.lower():
                    issue = {
                        'cookie_name': test['name'],
                        'cookie_value': test['value'],
                        'issue': 'Cookie manipulation bypass',
                        'severity': 'critical',
                        'description': f'Admin access gained via {test["name"]} cookie manipulation'
                    }
                    manipulation_issues.append(issue)
                    
                    if self.verbose:
                        print(f"  Cookie manipulation success: {test['name']}")
                
                # Clean up
                self.session.cookies.pop(test['name'], None)
                
            except Exception:
                continue
        
        return manipulation_issues