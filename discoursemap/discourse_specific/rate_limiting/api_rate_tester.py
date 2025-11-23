#!/usr/bin/env python3
"""
API Rate Limiting Tester

Tests rate limits on various Discourse API endpoints.
"""

import time
import requests
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin


class APIRateTester:
    """Tests rate limiting on API endpoints"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.api_endpoints = [
            '/categories.json',
            '/latest.json',
            '/posts.json'
        ]  # Limited to 3 endpoints for performance
    
    def test_all_endpoints(self) -> List[Dict[str, Any]]:
        """Test rate limiting on all API endpoints"""
        results = []
        
        for endpoint in self.api_endpoints:
            result = self.test_endpoint_rate_limit(endpoint)
            results.append(result)
            time.sleep(1)  # Brief pause between endpoint tests
        
        return results
    
    def test_endpoint_rate_limit(self, endpoint: str) -> Dict[str, Any]:
        """Test rate limiting on a specific endpoint"""
        url = urljoin(self.target_url, endpoint)
        
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing API rate limit: {endpoint}{Style.RESET_ALL}")
        
        attempts = 0
        rate_limited = False
        
        for i in range(10):  # Reduced from 50 for performance
            try:
                response = self.session.get(url, timeout=5)
                attempts += 1
                
                if response.status_code == 429:
                    rate_limited = True
                    return {
                        'endpoint': endpoint,
                        'type': 'api',
                        'triggered_after': attempts,
                        'status_code': 429,
                        'headers': dict(response.headers),
                        'rate_limited': True
                    }
                
                time.sleep(0.1)
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing {endpoint}: {e}{Style.RESET_ALL}")
                break
        
        return {
            'endpoint': endpoint,
            'rate_limited': False,
            'attempts': attempts,
            'severity': 'MEDIUM',
            'issue': f'No rate limiting detected on {endpoint}'
        }
    
    def test_authenticated_endpoints(self, auth_token: Optional[str] = None) -> List[Dict[str, Any]]:
        """Test rate limiting on authenticated endpoints"""
        auth_endpoints = [
            '/posts.json',
            '/topics.json',
            '/messages.json',
            '/notifications.json'
        ]
        
        results = []
        headers = {}
        if auth_token:
            headers['Authorization'] = f'Bearer {auth_token}'
        
        for endpoint in auth_endpoints:
            url = urljoin(self.target_url, endpoint)
            attempts = 0
            rate_limited = False
            
            for i in range(10):  # Reduced from 30 for performance
                try:
                    response = self.session.post(
                        url,
                        headers=headers,
                        json={'test': 'data'},
                        timeout=5
                    )
                    attempts += 1
                    
                    if response.status_code == 429:
                        rate_limited = True
                        results.append({
                            'endpoint': endpoint,
                            'type': 'authenticated_api',
                            'triggered_after': attempts,
                            'status_code': 429,
                            'rate_limited': True
                        })
                        break
                    
                    time.sleep(0.2)
                except Exception:
                    break
            
            if not rate_limited:
                results.append({
                    'endpoint': endpoint,
                    'rate_limited': False,
                    'attempts': attempts,
                    'type': 'authenticated_api'
                })
        
        return results