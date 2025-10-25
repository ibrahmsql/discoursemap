#!/usr/bin/env python3
"""
Discourse Cache Security Module

Tests caching mechanisms, cache poisoning, and cache configuration.
"""

import requests
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin


class CacheSecurityModule:
    """Cache security testing for Discourse"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        """
                 Create a CacheSecurityModule for scanning cache-related security issues against a target URL.
                 
                 Parameters:
                     target_url (str): Base URL of the target; trailing slash is removed.
                     session (Optional[requests.Session]): HTTP session to use for requests. If omitted, a new session is created.
                     verbose (bool): Enable verbose logging.
                 
                 Initializes:
                     target_url (str), session (requests.Session), verbose (bool), and a `results` dictionary with keys:
                     'cache_headers', 'cache_poisoning', 'cdn_detection', 'vulnerabilities', and 'recommendations'.
                 """
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.results = {
            'cache_headers': {},
            'cache_poisoning': [],
            'cdn_detection': {},
            'vulnerabilities': [],
            'recommendations': []
        }
    
    def scan(self) -> Dict[str, Any]:
        """
        Orchestrates the cache security scan for the target and aggregates findings into the instance results.
        
        Populates the instance `results` dictionary by running header checks, cache-poisoning tests, CDN detection, cache-key tests, and then generates recommendations.
        
        Returns:
            results (Dict[str, Any]): Aggregated scan findings including `cache_headers`, `cache_poisoning`, `cdn_detection`, `vulnerabilities`, and `recommendations`.
        """
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting cache security scan...{Style.RESET_ALL}")
        
        self._check_cache_headers()
        self._test_cache_poisoning()
        self._detect_cdn()
        self._test_cache_keys()
        
        self._generate_recommendations()
        return self.results
    
    def _check_cache_headers(self):
        """
        Retrieve cache-related HTTP headers from the target URL and record them in the module results.
        
        Collects a predefined set of cache-related response headers (e.g., Cache-Control, ETag, Vary, CF-Cache-Status) and stores any found values in self.results['cache_headers']. If the Cache-Control header indicates public caching (contains "public" and does not contain "private"), appends a LOW-severity vulnerability entry of type "Public Caching" to self.results['vulnerabilities']. Network or request errors are caught; when verbose is enabled an error message is printed.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking cache headers...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            cache_headers = {}
            relevant_headers = [
                'Cache-Control', 'Pragma', 'Expires', 'ETag',
                'Last-Modified', 'Vary', 'X-Cache', 'CF-Cache-Status',
                'X-Fastly-Request-ID', 'X-Varnish'
            ]
            
            for header in relevant_headers:
                if header in response.headers:
                    cache_headers[header] = response.headers[header]
            
            self.results['cache_headers'] = cache_headers
            
            # Check for insecure caching
            cache_control = cache_headers.get('Cache-Control', '')
            if 'public' in cache_control and 'private' not in cache_control:
                self.results['vulnerabilities'].append({
                    'type': 'Public Caching',
                    'severity': 'LOW',
                    'description': 'Content marked as publicly cacheable'
                })
                
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error checking cache headers: {e}{Style.RESET_ALL}")
    
    def _test_cache_poisoning(self):
        """
        Assess whether certain forwarded or rewrite HTTP headers are reflected in responses, indicating a cache poisoning risk.
        
        Sends requests with common forwarding/rewrite header manipulations and, when a header value is observed in the response body, appends a HIGH-severity finding to self.results['cache_poisoning']. Each finding is a dict with keys: 'header' (header name), 'value' (injected value), 'reflected' (True), and 'severity' ('HIGH'). Network errors are suppressed; a progress message is printed when verbose mode is enabled.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing cache poisoning...{Style.RESET_ALL}")
        
        poisoning_headers = [
            ('X-Forwarded-Host', 'evil.com'),
            ('X-Forwarded-Proto', 'http'),
            ('X-Original-URL', '/admin'),
            ('X-Rewrite-URL', '/admin')
        ]
        
        for header_name, header_value in poisoning_headers:
            try:
                response = self.session.get(
                    self.target_url,
                    headers={header_name: header_value},
                    timeout=5
                )
                
                if header_value in response.text:
                    self.results['cache_poisoning'].append({
                        'header': header_name,
                        'value': header_value,
                        'reflected': True,
                        'severity': 'HIGH'
                    })
                    
            except Exception:
                pass
    
    def _detect_cdn(self):
        """
        Detects CDN providers used by the target and records the findings.
        
        Performs an HTTP request to the configured target and checks response headers and cookies for known CDN indicators. Updates self.results['cdn_detection'] with:
            - 'detected' (bool): True if any CDN indicators were found.
            - 'cdns' (list): Unique names of detected CDNs.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Detecting CDN...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            cdn_indicators = {
                'Cloudflare': ['CF-RAY', 'cf-cache-status', '__cfduid'],
                'Fastly': ['X-Fastly-Request-ID', 'Fastly-SSL'],
                'Akamai': ['X-Akamai-Transformed', 'Akamai-GRN'],
                'AWS CloudFront': ['X-Amz-Cf-Id', 'X-Amz-Cf-Pop'],
                'Varnish': ['X-Varnish', 'Via']
            }
            
            detected_cdns = []
            for cdn_name, indicators in cdn_indicators.items():
                for indicator in indicators:
                    if indicator in response.headers or indicator in response.cookies:
                        detected_cdns.append(cdn_name)
                        break
            
            self.results['cdn_detection'] = {
                'detected': len(detected_cdns) > 0,
                'cdns': list(set(detected_cdns))
            }
            
        except Exception:
            pass
    
    def _test_cache_keys(self):
        """
        Check whether specific query parameters affect caching behavior for the target URL.
        
        Sends GET requests to the target URL with a set of test query parameters (callback, utm_source, ref, _).
        For each parameter that returns HTTP 200, records an entry in self.results['cache_headers'] with key
        `test_param_<param>` and value `'tested'`.
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing cache keys...{Style.RESET_ALL}")
        
        # Test if query parameters affect caching
        test_params = ['callback', 'utm_source', 'ref', '_']
        
        for param in test_params:
            try:
                url = f"{self.target_url}?{param}=test"
                response = self.session.get(url, timeout=5)
                
                # Check if response is different
                if response.status_code == 200:
                    self.results['cache_headers'][f'test_param_{param}'] = 'tested'
                    
            except Exception:
                pass
    
    def _generate_recommendations(self):
        """
        Populate self.results['recommendations'] with remediation suggestions derived from collected findings.
        
        Adds:
        - A HIGH-severity recommendation to mitigate cache poisoning if any cache-poisoning findings exist.
        - A MEDIUM-severity recommendation to add Cache-Control directives if no Cache-Control header was observed.
        - An INFO-severity recommendation listing detected CDNs and advising secure CDN configuration if any CDNs were detected.
        
        The assembled list is stored in self.results['recommendations'].
        """
        recommendations = []
        
        if self.results['cache_poisoning']:
            recommendations.append({
                'severity': 'HIGH',
                'issue': 'Cache poisoning vulnerabilities detected',
                'recommendation': 'Sanitize forwarding headers and implement proper cache key generation'
            })
        
        if not self.results['cache_headers'].get('Cache-Control'):
            recommendations.append({
                'severity': 'MEDIUM',
                'issue': 'Missing Cache-Control headers',
                'recommendation': 'Implement proper caching directives'
            })
        
        if self.results['cdn_detection'].get('detected'):
            recommendations.append({
                'severity': 'INFO',
                'issue': f"CDN detected: {', '.join(self.results['cdn_detection']['cdns'])}",
                'recommendation': 'Ensure CDN configuration follows security best practices'
            })
        
        self.results['recommendations'] = recommendations
    
    def print_results(self):
        """
        Print a concise, formatted summary of the accumulated scan results to standard output.
        
        Displays detected CDNs (if any); the total number of cache-related headers and up to five header samples; a list of detected cache-poisoning findings showing each finding's severity and header; and any generated recommendations showing their severity, the issue title, and the recommended action.
        """
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"Discourse Cache Security Scan Results")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        if self.results['cdn_detection'].get('detected'):
            print(f"{Fore.GREEN}[+] CDN Detected: {', '.join(self.results['cdn_detection']['cdns'])}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}[*] Cache Headers: {len(self.results['cache_headers'])}{Style.RESET_ALL}")
        for header, value in list(self.results['cache_headers'].items())[:5]:
            print(f"  • {header}: {value}")
        
        if self.results['cache_poisoning']:
            print(f"\n{Fore.RED}[!] Cache Poisoning Vulnerabilities: {len(self.results['cache_poisoning'])}{Style.RESET_ALL}")
            for poison in self.results['cache_poisoning']:
                print(f"  [{poison['severity']}] Header: {poison['header']}")
        
        if self.results['recommendations']:
            print(f"\n{Fore.YELLOW}[*] Recommendations:{Style.RESET_ALL}")
            for rec in self.results['recommendations']:
                print(f"  [{rec['severity']}] {rec['issue']}")
                print(f"      → {rec['recommendation']}")