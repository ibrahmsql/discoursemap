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
                 Create a CacheSecurityModule for assessing cache-related security of a target URL.
                 
                 Parameters:
                     target_url (str): The target URL to scan; trailing slash will be removed.
                     session (Optional[requests.Session]): Optional HTTP session to use for requests. If omitted, a new session is created.
                     verbose (bool): Enable verbose progress and error output.
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
        Run the configured cache security checks against the target URL and compile findings into a results dictionary.
        
        The returned dictionary contains aggregated information about cache headers, cache poisoning probes, CDN detection, identified vulnerabilities, and remediation recommendations.
        
        Returns:
            results (Dict[str, Any]): Mapping with keys:
                - cache_headers: dict of discovered cache-related response headers
                - cache_poisoning: list of detected cache poisoning reflections
                - cdn_detection: dict describing detected CDN presence and names
                - vulnerabilities: list of identified vulnerability records
                - recommendations: list of remediation suggestions
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
        Collect cache-related response headers from the target URL and record findings.
        
        Performs an HTTP GET to the configured target and stores any discovered cache-related headers in self.results['cache_headers']. If the `Cache-Control` header contains "public" and does not contain "private", appends a LOW-severity "Public Caching" entry to self.results['vulnerabilities']. Network errors are caught; when verbose is enabled an error message is printed.
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
        Probe the target for header-based cache poisoning and record any reflections.
        
        Sends GET requests to the target URL with a set of common poisoning headers. If an injected header value is observed in the response body, appends a detection record to self.results['cache_poisoning'] containing the header name, value, reflected=True, and severity='HIGH'. Network errors during probing are suppressed.
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
        Detect common CDNs by inspecting response headers and cookies.
        
        Checks the target URL for known header and cookie indicators of common CDN providers
        (e.g., Cloudflare, Fastly, Akamai, AWS CloudFront, Varnish) and records the findings
        in self.results['cdn_detection'] as a dict with keys:
            - 'detected': True if any CDN indicators were found, False otherwise
            - 'cdns': unique list of detected CDN names
        
        Network errors and exceptions during detection are suppressed; no exception is raised.
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
        Checks whether specific query parameters influence caching by requesting the target URL with each parameter set to "test". For each parameter that yields an HTTP 200 response, records an entry in self.results['cache_headers'] under the key "test_param_<param>" with the value "tested". Network errors and other exceptions are suppressed.
        
        Tests the following query parameter names: 'callback', 'utm_source', 'ref', '_'.
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
        Compile remediation recommendations based on previously collected scan findings and store them in self.results.
        
        Adds a list of recommendation dictionaries to self.results['recommendations']. Each recommendation contains the keys:
        - 'severity': severity level string (e.g., 'HIGH', 'MEDIUM', 'INFO')
        - 'issue': short description of the detected issue
        - 'recommendation': actionable remediation guidance
        
        Behavior:
        - Adds a HIGH-severity recommendation if any cache poisoning entries are present.
        - Adds a MEDIUM-severity recommendation if no Cache-Control header was recorded.
        - Adds an INFO-severity recommendation when a CDN was detected, listing detected CDN names.
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
        Prints a formatted summary of the cache security scan results to standard output.
        
        The output includes detected CDNs, a summary of discovered cache-related headers, any cache-poisoning findings, and remediation recommendations. Intended for human-readable console display; does not return a value.
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