#!/usr/bin/env python3
"""
Rate Limit Bypass Tester

Tests various techniques to bypass rate limiting mechanisms.
"""

import time
import requests
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin
import random


class BypassTester:
    """Tests rate limit bypass techniques"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.bypass_methods = []
    
    def test_all_bypass_methods(self) -> List[Dict[str, Any]]:
        """Test all available bypass methods"""
        methods = [
            self.test_user_agent_rotation,
            self.test_ip_header_spoofing,
            self.test_referer_bypass,
            self.test_method_override,
            self.test_case_variation,
            self.test_parameter_pollution
        ]
        
        results = []
        for method in methods:
            try:
                result = method()
                if result:
                    results.append(result)
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error in bypass test: {e}{Style.RESET_ALL}")
        
        return results
    
    def test_user_agent_rotation(self) -> Optional[Dict[str, Any]]:
        """Test bypassing rate limits with User-Agent rotation"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing User-Agent rotation bypass...{Style.RESET_ALL}")
        
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)',
            'Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0'
        ]
        
        endpoint = urljoin(self.target_url, '/session')
        successful_requests = 0
        
        for i in range(20):
            try:
                headers = {'User-Agent': random.choice(user_agents)}
                response = self.session.post(
                    endpoint,
                    json={'login': 'test', 'password': 'test'},
                    headers=headers,
                    timeout=5
                )
                
                if response.status_code != 429:
                    successful_requests += 1
                
                time.sleep(0.1)
            except Exception:
                break
        
        if successful_requests > 15:  # If most requests succeeded
            return {
                'method': 'User-Agent Rotation',
                'successful': True,
                'requests_made': successful_requests,
                'severity': 'HIGH',
                'description': 'Rate limiting can be bypassed with User-Agent rotation'
            }
        
        return None
    
    def test_ip_header_spoofing(self) -> Optional[Dict[str, Any]]:
        """Test bypassing with IP header spoofing"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing IP header spoofing bypass...{Style.RESET_ALL}")
        
        ip_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Client-IP',
            'X-Originating-IP',
            'CF-Connecting-IP'
        ]
        
        endpoint = urljoin(self.target_url, '/session')
        successful_bypasses = []
        
        for header in ip_headers:
            successful_requests = 0
            
            for i in range(10):
                try:
                    fake_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
                    headers = {header: fake_ip}
                    
                    response = self.session.post(
                        endpoint,
                        json={'login': 'test', 'password': 'test'},
                        headers=headers,
                        timeout=5
                    )
                    
                    if response.status_code != 429:
                        successful_requests += 1
                    
                    time.sleep(0.1)
                except Exception:
                    break
            
            if successful_requests > 7:
                successful_bypasses.append(header)
        
        if successful_bypasses:
            return {
                'method': 'IP Header Spoofing',
                'successful': True,
                'headers': successful_bypasses,
                'severity': 'HIGH',
                'description': f'Rate limiting bypassed using headers: {", ".join(successful_bypasses)}'
            }
        
        return None
    
    def test_referer_bypass(self) -> Optional[Dict[str, Any]]:
        """Test bypassing with Referer header manipulation"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing Referer bypass...{Style.RESET_ALL}")
        
        referers = [
            'https://www.google.com/',
            'https://www.facebook.com/',
            'https://twitter.com/',
            f'{self.target_url}/admin',
            f'{self.target_url}/internal'
        ]
        
        endpoint = urljoin(self.target_url, '/session')
        successful_requests = 0
        
        for i in range(15):
            try:
                headers = {'Referer': random.choice(referers)}
                response = self.session.post(
                    endpoint,
                    json={'login': 'test', 'password': 'test'},
                    headers=headers,
                    timeout=5
                )
                
                if response.status_code != 429:
                    successful_requests += 1
                
                time.sleep(0.1)
            except Exception:
                break
        
        if successful_requests > 10:
            return {
                'method': 'Referer Bypass',
                'successful': True,
                'requests_made': successful_requests,
                'severity': 'MEDIUM',
                'description': 'Rate limiting can be bypassed with Referer manipulation'
            }
        
        return None
    
    def test_method_override(self) -> Optional[Dict[str, Any]]:
        """Test HTTP method override bypass"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing HTTP method override bypass...{Style.RESET_ALL}")
        
        endpoint = urljoin(self.target_url, '/session')
        override_headers = [
            {'X-HTTP-Method-Override': 'GET'},
            {'X-Method-Override': 'GET'},
            {'_method': 'GET'}
        ]
        
        for headers in override_headers:
            successful_requests = 0
            
            for i in range(10):
                try:
                    response = self.session.post(
                        endpoint,
                        json={'login': 'test', 'password': 'test'},
                        headers=headers,
                        timeout=5
                    )
                    
                    if response.status_code != 429:
                        successful_requests += 1
                    
                    time.sleep(0.1)
                except Exception:
                    break
            
            if successful_requests > 7:
                return {
                    'method': 'HTTP Method Override',
                    'successful': True,
                    'header_used': headers,
                    'severity': 'MEDIUM',
                    'description': 'Rate limiting bypassed with method override'
                }
        
        return None
    
    def test_case_variation(self) -> Optional[Dict[str, Any]]:
        """Test case variation bypass"""
        endpoints = [
            '/Session',
            '/SESSION',
            '/sEsSiOn',
            '/session/',
            '/session//'
        ]
        
        successful_bypasses = []
        
        for endpoint in endpoints:
            url = urljoin(self.target_url, endpoint)
            successful_requests = 0
            
            for i in range(5):
                try:
                    response = self.session.post(
                        url,
                        json={'login': 'test', 'password': 'test'},
                        timeout=5
                    )
                    
                    if response.status_code != 429:
                        successful_requests += 1
                    
                    time.sleep(0.2)
                except Exception:
                    break
            
            if successful_requests > 3:
                successful_bypasses.append(endpoint)
        
        if successful_bypasses:
            return {
                'method': 'Case Variation',
                'successful': True,
                'endpoints': successful_bypasses,
                'severity': 'LOW',
                'description': 'Rate limiting bypassed with case variations'
            }
        
        return None
    
    def test_parameter_pollution(self) -> Optional[Dict[str, Any]]:
        """Test parameter pollution bypass"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing parameter pollution bypass...{Style.RESET_ALL}")
        
        endpoint = urljoin(self.target_url, '/session')
        pollution_payloads = [
            {'login': 'test', 'password': 'test', 'login': 'admin'},
            {'login[]': 'test', 'password': 'test'},
            {'login': ['test', 'admin'], 'password': 'test'}
        ]
        
        for payload in pollution_payloads:
            successful_requests = 0
            
            for i in range(8):
                try:
                    response = self.session.post(
                        endpoint,
                        json=payload,
                        timeout=5
                    )
                    
                    if response.status_code != 429:
                        successful_requests += 1
                    
                    time.sleep(0.1)
                except Exception:
                    break
            
            if successful_requests > 5:
                return {
                    'method': 'Parameter Pollution',
                    'successful': True,
                    'payload': payload,
                    'severity': 'MEDIUM',
                    'description': 'Rate limiting bypassed with parameter pollution'
                }
        
        return None