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
                 Create a RateLimitModule for scanning a Discourse site and initialize its state.
                 
                 Parameters:
                     target_url (str): Base URL of the target Discourse forum; trailing slash is removed.
                     session (Optional[requests.Session]): HTTP session to use for requests; a new session is created if not provided.
                     verbose (bool): When True, enable verbose console output.
                 
                 Notes:
                     Initializes an internal `results` dictionary to collect findings with keys:
                     'rate_limits_found', 'endpoints_tested', 'bypass_methods', and 'recommendations'.
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
        Perform a full rate limiting assessment against the configured Discourse site.
        
        Runs a suite of endpoint-specific checks (login, API, search, topic/post/PM behavior), inspects response headers, tests common bypass techniques, and generates remediation recommendations.
        
        Returns:
            results (Dict[str, Any]): Collected scan results containing:
                - rate_limits_found: list of detected rate limit records.
                - endpoints_tested: list of tested endpoint summaries.
                - bypass_methods: list of discovered bypass technique findings.
                - recommendations: list of generated security recommendations.
                - rate_limit_headers (optional): mapping of any rate-limit-related headers observed.
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
        """
        Probe the forum's login endpoint to determine whether request rate limiting is enforced.
        
        Performs up to 15 login attempts against /session to detect an HTTP 429 response. On detecting a 429 it records a rate-limit finding in self.results['rate_limits_found'] including the endpoint, type 'login', the number of attempts required to trigger the limit, the status code, and response headers. If no 429 is observed after the attempts, it appends an entry to self.results['endpoints_tested'] indicating the login endpoint appears not rate-limited and includes the attempted count. Stops testing early on exceptions and preserves the number of attempts performed.
        """
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
        """
        Probe common Discourse API endpoints to detect rate limiting and record findings in self.results.
        
        Performs rapid requests against a set of API endpoints and records a rate limit finding when a 429 response is observed. Updates self.results by appending:
        - to 'rate_limits_found': dicts with keys 'endpoint', 'type' (set to 'api'), 'triggered_after' (number of attempts), and 'status_code'.
        - to 'endpoints_tested': dicts with keys 'endpoint', 'rate_limited' (False when no 429 observed), and 'attempts' (number of requests made).
        
        No return value.
        """
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
        """
        Probe the forum's /search endpoint for rate limiting and record any trigger point.
        
        Performs repeated GET requests to /search with varying query parameters and, upon receiving an HTTP 429 response, appends a finding to self.results['rate_limits_found'] with keys 'endpoint' (set to '/search'), 'type' (set to 'search'), and 'triggered_after' (the number of requests made before the 429). Stops probing when a rate limit is detected or when a request error occurs.
        """
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
        """
        Check whether the topic-creation endpoint exists and record its accessibility and authentication requirement.
        
        If the posts endpoint responds (or errors), an entry is appended to self.results['endpoints_tested'] with:
        - 'endpoint': '/posts'
        - 'type': 'topic_creation'
        - 'requires_auth': True
        - 'accessible': True if the response status code is not 404, False otherwise
        """
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
        """
        Record metadata about the forum's post-creation endpoint with respect to rate limiting and authentication.
        
        Appends an entry to self.results['endpoints_tested'] describing the '/posts' endpoint with type 'post_creation' and a note indicating that an authenticated session is required.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing post rate limit...{Style.RESET_ALL}")
        
        # Check rate limit configuration
        self.results['endpoints_tested'].append({
            'endpoint': '/posts',
            'type': 'post_creation',
            'note': 'Requires authenticated session'
        })
    
    def _test_pm_rate_limit(self):
        """
        Record a test entry indicating private-message rate limiting is associated with the posts endpoint.
        
        Adds an entry to self.results['endpoints_tested'] for '/posts' with type 'private_message' and a note that PM creation uses the posts endpoint. When verbose mode is enabled, prints a brief progress message.
        """
        endpoint = urljoin(self.target_url, '/posts')
        
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing PM rate limit...{Style.RESET_ALL}")
        
        self.results['endpoints_tested'].append({
            'endpoint': '/posts',
            'type': 'private_message',
            'note': 'PM creation uses posts endpoint'
        })
    
    def _check_rate_limit_headers(self):
        """
        Collect common rate-limit headers from the forum's /latest.json response and store them in the module results.
        
        Checks the response for the headers `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`, and `X-Discourse-Rate-Limit-Error`. If any are present, stores a mapping of header names to values in `self.results['rate_limit_headers']`. Network or parsing errors are ignored.
        """
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
        """
        Assess common techniques that may bypass server-side rate limits.
        
        Performs simple checks against the /latest.json endpoint — testing an X-Forwarded-For header and a small set of User-Agent values — and records any observed bypass methods in self.results['bypass_methods'] as a list of dictionaries with keys like `method`, `successful`, and `severity`.
        """
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
        """
        Assembles security recommendations based on collected rate-limit test results.
        
        Populates self.results['recommendations'] with a list of recommendation dicts. Adds:
        - A HIGH-severity recommendation listing endpoints from self.results['endpoints_tested'] that are not rate limited.
        - A MEDIUM-severity recommendation if self.results['bypass_methods'] contains any findings.
        - A LOW-severity recommendation if no rate limit headers were captured in self.results['rate_limit_headers'].
        """
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
        """
        Prints the accumulated scan results in a human-readable, colorized format.
        
        Displays the module's collected findings from self.results, including detected rate limits (rate_limits_found), the count of endpoints tested (endpoints_tested), and any generated security recommendations (recommendations). Output is written to standard output in a formatted layout for quick review.
        """
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