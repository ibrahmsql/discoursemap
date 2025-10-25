#!/usr/bin/env python3
"""
Rate Limit Header Analyzer

Analyzes HTTP response headers for rate limiting information.
"""

import requests
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin


class HeaderAnalyzer:
    """Analyzes rate limiting headers in HTTP responses"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'X-Rate-Limit-Limit',
            'X-Rate-Limit-Remaining',
            'X-Rate-Limit-Reset',
            'RateLimit-Limit',
            'RateLimit-Remaining',
            'RateLimit-Reset',
            'Retry-After',
            'X-Retry-After'
        ]
    
    def analyze_headers(self) -> Dict[str, Any]:
        """Analyze rate limiting headers from various endpoints"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Analyzing rate limit headers...{Style.RESET_ALL}")
        
        endpoints = [
            '/',
            '/categories.json',
            '/latest.json',
            '/session'
        ]
        
        header_analysis = {
            'headers_found': [],
            'endpoints_analyzed': [],
            'rate_limit_info': {}
        }
        
        for endpoint in endpoints:
            url = urljoin(self.target_url, endpoint)
            
            try:
                response = self.session.get(url, timeout=10)
                endpoint_headers = {}
                
                for header in self.rate_limit_headers:
                    if header in response.headers:
                        endpoint_headers[header] = response.headers[header]
                        if header not in header_analysis['headers_found']:
                            header_analysis['headers_found'].append(header)
                
                if endpoint_headers:
                    header_analysis['endpoints_analyzed'].append({
                        'endpoint': endpoint,
                        'headers': endpoint_headers,
                        'status_code': response.status_code
                    })
                
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error analyzing {endpoint}: {e}{Style.RESET_ALL}")
        
        # Parse rate limit information
        if header_analysis['headers_found']:
            header_analysis['rate_limit_info'] = self._parse_rate_limit_info(
                header_analysis['endpoints_analyzed']
            )
        
        return header_analysis
    
    def _parse_rate_limit_info(self, endpoints_data: List[Dict]) -> Dict[str, Any]:
        """Parse rate limit information from headers"""
        info = {
            'limits_detected': [],
            'reset_times': [],
            'remaining_requests': []
        }
        
        for endpoint_data in endpoints_data:
            headers = endpoint_data['headers']
            endpoint = endpoint_data['endpoint']
            
            # Parse limit headers
            for limit_header in ['X-RateLimit-Limit', 'X-Rate-Limit-Limit', 'RateLimit-Limit']:
                if limit_header in headers:
                    try:
                        limit = int(headers[limit_header])
                        info['limits_detected'].append({
                            'endpoint': endpoint,
                            'limit': limit,
                            'header': limit_header
                        })
                    except ValueError:
                        pass
            
            # Parse remaining headers
            for remaining_header in ['X-RateLimit-Remaining', 'X-Rate-Limit-Remaining', 'RateLimit-Remaining']:
                if remaining_header in headers:
                    try:
                        remaining = int(headers[remaining_header])
                        info['remaining_requests'].append({
                            'endpoint': endpoint,
                            'remaining': remaining,
                            'header': remaining_header
                        })
                    except ValueError:
                        pass
            
            # Parse reset headers
            for reset_header in ['X-RateLimit-Reset', 'X-Rate-Limit-Reset', 'RateLimit-Reset']:
                if reset_header in headers:
                    info['reset_times'].append({
                        'endpoint': endpoint,
                        'reset': headers[reset_header],
                        'header': reset_header
                    })
        
        return info
    
    def check_custom_headers(self) -> Dict[str, Any]:
        """Check for custom or non-standard rate limiting headers"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking for custom rate limit headers...{Style.RESET_ALL}")
        
        custom_patterns = [
            'limit', 'rate', 'throttle', 'quota', 'bucket',
            'requests', 'calls', 'api', 'usage'
        ]
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            custom_headers = {}
            
            for header_name, header_value in response.headers.items():
                header_lower = header_name.lower()
                
                for pattern in custom_patterns:
                    if pattern in header_lower:
                        custom_headers[header_name] = header_value
                        break
            
            return {
                'custom_headers_found': len(custom_headers) > 0,
                'headers': custom_headers
            }
            
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error checking custom headers: {e}{Style.RESET_ALL}")
            return {'custom_headers_found': False, 'headers': {}}
    
    def analyze_429_response(self) -> Optional[Dict[str, Any]]:
        """Trigger and analyze a 429 response if possible"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Attempting to trigger 429 response...{Style.RESET_ALL}")
        
        endpoint = urljoin(self.target_url, '/session')
        
        # Try to trigger rate limiting
        for i in range(20):
            try:
                response = self.session.post(
                    endpoint,
                    json={'login': 'test', 'password': 'test'},
                    timeout=5
                )
                
                if response.status_code == 429:
                    return {
                        'triggered': True,
                        'headers': dict(response.headers),
                        'body': response.text[:500],  # First 500 chars
                        'attempts_to_trigger': i + 1
                    }
                
            except Exception:
                break
        
        return {
            'triggered': False,
            'attempts_made': 20
        }