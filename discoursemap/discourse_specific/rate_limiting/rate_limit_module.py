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
                 Create a RateLimitModule for analyzing rate limits on a Discourse forum.
                 
                 Parameters:
                     target_url (str): Base URL of the target Discourse forum; any trailing slash is removed.
                     session (Optional[requests.Session]): Optional requests session to use for HTTP requests. A new session is created if omitted.
                     verbose (bool): If True, enable verbose console output.
                 
                 Attributes:
                     target_url (str): Normalized target URL without a trailing slash.
                     session (requests.Session): HTTP session used for requests.
                     verbose (bool): Verbosity flag.
                     results (dict): Aggregated findings with keys 'rate_limits_found', 'endpoints_tested', 'bypass_methods', and 'recommendations'.
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
        Run a full set of rate limiting tests against the target Discourse instance and collect findings.
        
        Performs tests for login, several API endpoints, search, topic/post/PM behavior, header inspection, and bypass techniques, then generates recommendations.
        
        Returns:
            results (dict): Aggregated scan results with keys:
                - 'rate_limits_found' (list): Detected rate limit events and metadata.
                - 'endpoints_tested' (list): Records of endpoints exercised and their test outcomes.
                - 'bypass_methods' (list): Discovered bypass techniques.
                - 'recommendations' (list): Generated security recommendations.
                - 'rate_limit_headers' (dict, optional): Observed rate-limit-related response headers, if any.
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
        Check the target's login endpoint (/session) for rate limiting and record the result in self.results.
        
        Performs repeated POST attempts to /session (up to 15). If an HTTP 429 response is observed, records a rate limit event in `self.results['rate_limits_found']` with the endpoint, type ('login'), number of attempts when triggered, status code, and response headers. If no rate limit is detected after the attempts, appends an entry to `self.results['endpoints_tested']` indicating the endpoint was tested, the number of attempts, a HIGH severity, and an issue message stating no rate limiting was detected. On exceptions the test stops early; verbose mode prints the error.
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
        Check a set of common Discourse API endpoints for rate limiting and record findings in self.results.
        
        Per endpoint, issues up to 50 rapid GET requests and stops the test for that endpoint when a 429 response is observed or an exception occurs. On a 429 response, records a rate limit event in `self.results['rate_limits_found']` with the endpoint, type "api", the number of requests that triggered the limit, and the status code. If no rate limit is observed, appends an entry to `self.results['endpoints_tested']` with the endpoint, `rate_limited: False`, and the number of attempts performed.
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
        Check the forum /search endpoint for rate limiting and record any detected limit.
        
        Performs up to 30 GET requests to /search with incremental query parameters. If a 429 response is observed, appends an entry to self.results['rate_limits_found'] with keys 'endpoint' (set to '/search'), 'type' (set to 'search'), and 'triggered_after' (the number of attempts that triggered the limit), then stops. The test also stops early on any request exception.
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
        Check whether the forum's topic-creation endpoint is reachable and record its accessibility.
        
        Performs a request to the forum's posts endpoint and appends a test record to self.results['endpoints_tested'] with these keys: 'endpoint' (path), 'type' ('topic_creation'), 'requires_auth' (True), and 'accessible' (True if the endpoint did not return 404, False otherwise). Exceptions raised during the check are suppressed.
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
        Record a post-creation endpoint test indicating that authentication is required.
        
        Appends a test entry for the '/posts' endpoint to self.results['endpoints_tested'] with type 'post_creation' and a note that an authenticated session is required. If verbose mode is enabled, prints a brief status message to the console.
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
        Record a test entry for private message rate limiting on the posts endpoint.
        
        Appends an entry to self.results['endpoints_tested'] indicating that private message creation uses the '/posts' endpoint. When verbose mode is enabled, prints a short status message to the console.
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
        Check the target for common rate-limit response headers and store any found values.
        
        Performs a GET request to the forum's /latest.json endpoint and, if present,
        collects these headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset,
        Retry-After, and X-Discourse-Rate-Limit-Error. When any of those headers are found,
        their names and values are stored in self.results['rate_limit_headers'].
        Exceptions during the request are suppressed.
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
        Probe the target for common rate-limit bypass techniques and record any successful methods.
        
        Performs two checks: sending an X-Forwarded-For header and rotating common User-Agent strings. Successful bypasses are appended to self.results['bypass_methods']; the method suppresses individual request errors and may print progress when verbose mode is enabled.
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
        Builds security recommendations based on the module's scanning results and stores them in self.results['recommendations'].
        
        The method inspects tested endpoints, discovered bypass techniques, and presence of rate-limit headers to produce severity-tagged recommendations (e.g., require rate limiting on unprotected endpoints, validate forwarding headers and use per-IP tracking if bypasses were found, and consider exposing rate-limit headers when absent).
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
        Display a formatted summary of the scan results to standard output.
        
        Prints detected rate limits, the number of endpoints tested, and security recommendations from the module's aggregated results. Uses ANSI-colored output for readability and does not return a value.
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