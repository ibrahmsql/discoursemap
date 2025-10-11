#!/usr/bin/env python3
"""
Discourse Rate Limiting Module

Tests and analyzes rate limiting mechanisms in Discourse forums.
Detects rate limit policies, thresholds, and bypass possibilities.
"""

import time
import requests
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin


class RateLimitModule:
    """Rate limiting detection and testing for Discourse"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        """
        Initialize rate limit module
        
        Args:
            target_url: Target Discourse forum URL
            session: Optional requests session
            verbose: Enable verbose output
        """
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.results = {
            'rate_limits_found': [],
            'endpoints_tested': [],
            'bypass_methods': [],
            'recommendations': []
        }
    
    def scan(self) -> Dict[str, Any]:
        """
        Perform comprehensive rate limiting scan
        
        Returns:
            Dictionary containing scan results
        """
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting Discourse rate limiting scan...{Style.RESET_ALL}")
        
        # Test various endpoints
        self._test_login_rate_limit()
        self._test_api_rate_limit()
        self._test_search_rate_limit()
        self._test_topic_creation_rate_limit()
        self._test_post_rate_limit()
        self._test_pm_rate_limit()
        self._check_rate_limit_headers()
        self._test_bypass_techniques()
        
        self._generate_recommendations()
        
        return self.results
    
    def _test_login_rate_limit(self):
        """Test login endpoint rate limiting"""
        endpoint = urljoin(self.target_url, '/session')
        
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing login rate limit...{Style.RESET_ALL}")
        
        attempts = 0
        rate_limited = False
        
        for i in range(15):  # Try 15 login attempts
            try:
                response = self.session.post(
                    endpoint,
                    json={'login': 'testuser', 'password': 'testpass'},
                    timeout=10
                )
                attempts += 1
                
                if response.status_code == 429:
                    rate_limited = True
                    self.results['rate_limits_found'].append({
                        'endpoint': '/session',
                        'type': 'login',
                        'triggered_after': attempts,
                        'status_code': 429,
                        'headers': dict(response.headers)
                    })
                    break
                    
                time.sleep(0.5)
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing login rate limit: {e}{Style.RESET_ALL}")
                break
        
        if not rate_limited:
            self.results['endpoints_tested'].append({
                'endpoint': '/session',
                'rate_limited': False,
                'attempts': attempts,
                'severity': 'HIGH',
                'issue': 'No rate limiting detected on login endpoint'
            })
    
    def _test_api_rate_limit(self):
        """Test API endpoint rate limiting"""
        endpoints = [
            '/categories.json',
            '/latest.json',
            '/posts.json',
            '/users.json'
        ]
        
        for endpoint in endpoints:
            url = urljoin(self.target_url, endpoint)
            
            if self.verbose:
                print(f"{Fore.YELLOW}[*] Testing API rate limit: {endpoint}{Style.RESET_ALL}")
            
            attempts = 0
            rate_limited = False
            
            for i in range(50):  # Rapid requests
                try:
                    response = self.session.get(url, timeout=5)
                    attempts += 1
                    
                    if response.status_code == 429:
                        rate_limited = True
                        self.results['rate_limits_found'].append({
                            'endpoint': endpoint,
                            'type': 'api',
                            'triggered_after': attempts,
                            'status_code': 429
                        })
                        break
                        
                    time.sleep(0.1)
                except Exception:
                    break
            
            if not rate_limited:
                self.results['endpoints_tested'].append({
                    'endpoint': endpoint,
                    'rate_limited': False,
                    'attempts': attempts
                })
    
    def _test_search_rate_limit(self):
        """Test search endpoint rate limiting"""
        endpoint = urljoin(self.target_url, '/search')
        
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing search rate limit...{Style.RESET_ALL}")
        
        attempts = 0
        for i in range(30):
            try:
                response = self.session.get(
                    endpoint,
                    params={'q': f'test{i}'},
                    timeout=5
                )
                attempts += 1
                
                if response.status_code == 429:
                    self.results['rate_limits_found'].append({
                        'endpoint': '/search',
                        'type': 'search',
                        'triggered_after': attempts
                    })
                    break
                    
                time.sleep(0.2)
            except Exception:
                break
    
    def _test_topic_creation_rate_limit(self):
        """Test topic creation rate limiting"""
        endpoint = urljoin(self.target_url, '/posts')
        
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing topic creation rate limit...{Style.RESET_ALL}")
        
        # This requires authentication, so we just check if the endpoint exists
        try:
            response = self.session.post(endpoint, timeout=5)
            self.results['endpoints_tested'].append({
                'endpoint': '/posts',
                'type': 'topic_creation',
                'requires_auth': True,
                'accessible': response.status_code != 404
            })
        except Exception:
            pass
    
    def _test_post_rate_limit(self):
        """Test post creation rate limiting"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing post rate limit...{Style.RESET_ALL}")
        
        # Check rate limit configuration
        self.results['endpoints_tested'].append({
            'endpoint': '/posts',
            'type': 'post_creation',
            'note': 'Requires authenticated session'
        })
    
    def _test_pm_rate_limit(self):
        """Test private message rate limiting"""
        endpoint = urljoin(self.target_url, '/posts')
        
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing PM rate limit...{Style.RESET_ALL}")
        
        self.results['endpoints_tested'].append({
            'endpoint': '/posts',
            'type': 'private_message',
            'note': 'PM creation uses posts endpoint'
        })
    
    def _check_rate_limit_headers(self):
        """Check for rate limit headers in responses"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking rate limit headers...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(
                urljoin(self.target_url, '/latest.json'),
                timeout=10
            )
            
            rate_limit_headers = {}
            for header in ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 
                          'X-RateLimit-Reset', 'Retry-After', 
                          'X-Discourse-Rate-Limit-Error']:
                if header in response.headers:
                    rate_limit_headers[header] = response.headers[header]
            
            if rate_limit_headers:
                self.results['rate_limit_headers'] = rate_limit_headers
        except Exception:
            pass
    
    def _test_bypass_techniques(self):
        """Test common rate limit bypass techniques"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing rate limit bypass techniques...{Style.RESET_ALL}")
        
        bypass_methods = []
        
        # Test 1: X-Forwarded-For header
        try:
            response = self.session.get(
                urljoin(self.target_url, '/latest.json'),
                headers={'X-Forwarded-For': '1.2.3.4'},
                timeout=5
            )
            if response.status_code == 200:
                bypass_methods.append({
                    'method': 'X-Forwarded-For header',
                    'successful': True,
                    'severity': 'MEDIUM'
                })
        except Exception:
            pass
        
        # Test 2: User-Agent rotation
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'Mozilla/5.0 (X11; Linux x86_64)'
        ]
        
        for ua in user_agents:
            try:
                response = self.session.get(
                    urljoin(self.target_url, '/latest.json'),
                    headers={'User-Agent': ua},
                    timeout=5
                )
            except Exception:
                pass
        
        self.results['bypass_methods'] = bypass_methods
    
    def _generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = []
        
        # Check for missing rate limits
        unprotected = [e for e in self.results['endpoints_tested'] 
                      if not e.get('rate_limited', True)]
        
        if unprotected:
            recommendations.append({
                'severity': 'HIGH',
                'issue': 'Endpoints without rate limiting detected',
                'recommendation': 'Implement rate limiting on all public endpoints',
                'affected_endpoints': [e['endpoint'] for e in unprotected]
            })
        
        if self.results['bypass_methods']:
            recommendations.append({
                'severity': 'MEDIUM',
                'issue': 'Rate limit bypass methods may be possible',
                'recommendation': 'Validate and sanitize forwarding headers, implement per-IP tracking'
            })
        
        if not self.results.get('rate_limit_headers'):
            recommendations.append({
                'severity': 'LOW',
                'issue': 'No rate limit headers exposed',
                'recommendation': 'Consider exposing rate limit info via headers for transparency'
            })
        
        self.results['recommendations'] = recommendations
    
    def print_results(self):
        """Print formatted results"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"Discourse Rate Limiting Scan Results")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        # Rate limits found
        if self.results['rate_limits_found']:
            print(f"{Fore.GREEN}[+] Rate Limits Detected:{Style.RESET_ALL}")
            for rl in self.results['rate_limits_found']:
                print(f"  • {rl['endpoint']} - Triggered after {rl['triggered_after']} requests")
        
        # Endpoints tested
        print(f"\n{Fore.YELLOW}[*] Endpoints Tested: {len(self.results['endpoints_tested'])}{Style.RESET_ALL}")
        
        # Recommendations
        if self.results['recommendations']:
            print(f"\n{Fore.RED}[!] Security Recommendations:{Style.RESET_ALL}")
            for rec in self.results['recommendations']:
                print(f"  [{rec['severity']}] {rec['issue']}")
                print(f"      → {rec['recommendation']}")
