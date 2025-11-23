#!/usr/bin/env python3
"""
API Security Module

Tests for Discourse API security vulnerabilities.
"""

from typing import Dict, List, Any
import re
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class APISecurityTests:
    """Discourse API security tests"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.target_url = scanner.target_url
        
    def scan(self) -> List[Dict[str, Any]]:
        """Run all API security tests"""
        vulnerabilities = []
        
        # Test 1: Check for exposed API keys in common locations
        vulnerabilities.extend(self._check_exposed_api_keys())
        
        # Test 2: Check for unauthenticated API endpoints
        vulnerabilities.extend(self._check_unauthenticated_endpoints())
        
        return vulnerabilities
        
    def _check_exposed_api_keys(self) -> List[Dict[str, Any]]:
        """Check for exposed API keys in JS files and HTML source"""
        vulns = []
        
        # Common API key patterns
        api_key_patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            r'discourse[_-]?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            r'["\']([a-f0-9]{32,64})["\']',  # Generic hex keys
        ]
        
        try:
            # Check main page
            response = self.scanner.make_request(self.target_url)
            if response:
                # Extract and check JS files
                soup = BeautifulSoup(response.text, 'html.parser')
                js_files = [script.get('src') for script in soup.find_all('script', src=True)]
                
                # Check main HTML
                for pattern in api_key_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    if matches:
                        vulns.append({
                            'type': 'API Key Exposure',
                            'description': 'Potential API key found in HTML source',
                            'location': 'main page',
                            'severity': 'high',
                            'key_preview': matches[0][:10] + '...'
                        })
                
                # Check JS files
                for js_file in js_files[:5]:  # Limit to first 5 files
                    try:
                        js_url = urljoin(self.target_url, js_file)
                        js_response = self.scanner.make_request(js_url)
                        if js_response:
                            for pattern in api_key_patterns:
                                matches = re.findall(pattern, js_response.text, re.IGNORECASE)
                                if matches:
                                    vulns.append({
                                        'type': 'API Key Exposure',
                                        'description': f'Potential API key found in JS file',
                                        'location': js_file,
                                        'severity': 'high',
                                        'key_preview': matches[0][:10] + '...'
                                    })
                                    break
                    except Exception:
                        continue
        except Exception:
            pass
        return vulns
        
    def _check_unauthenticated_endpoints(self) -> List[Dict[str, Any]]:
        """Check access to endpoints that should require auth"""
        vulns = []
        sensitive_endpoints = [
            '/admin/users.json',
            '/admin/site_settings.json',
            '/admin/backups.json'
        ]
        
        for endpoint in sensitive_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.scanner.make_request(url)
                
                if response and response.status_code == 200:
                    # Verify it's not a login page or error
                    if 'login' not in response.url and 'error' not in response.text.lower():
                        vulns.append({
                            'type': 'Unauthenticated API Access',
                            'endpoint': endpoint,
                            'description': f'Sensitive endpoint accessible without auth: {endpoint}',
                            'severity': 'critical'
                        })
            except Exception:
                continue
                
        return vulns
