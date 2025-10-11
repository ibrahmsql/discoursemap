#!/usr/bin/env python3
"""
Discourse Validator Module

Validates that target is a Discourse forum and checks version compatibility.
"""

import requests
import re
from typing import Dict, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin


class DiscourseValidator:
    """Validates Discourse forum targets"""
    
    def __init__(self, target_url: str, verbose: bool = False):
        """Initialize validator"""
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.results = {
            'is_discourse': False,
            'version': None,
            'version_details': {},
            'confidence': 0,
            'indicators': []
        }
    
    def validate(self) -> Dict[str, Any]:
        """Validate if target is a Discourse forum"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] Validating Discourse forum...{Style.RESET_ALL}")
        
        self._check_meta_tags()
        self._check_api_endpoints()
        self._check_discourse_headers()
        self._extract_version()
        self._check_discourse_assets()
        
        # Calculate confidence score
        confidence = len(self.results['indicators']) * 20
        self.results['confidence'] = min(confidence, 100)
        self.results['is_discourse'] = confidence >= 60
        
        return self.results
    
    def _check_meta_tags(self):
        """Check for Discourse meta tags"""
        try:
            response = requests.get(self.target_url, timeout=10)
            
            # Look for Discourse generator meta tag
            if 'Discourse' in response.text:
                self.results['indicators'].append('Discourse keyword found')
            
            # Check for specific meta tags
            discourse_patterns = [
                r'<meta\s+name=["\']discourse["\']',
                r'data-discourse-',
                r'discourse\.org',
            ]
            
            for pattern in discourse_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    self.results['indicators'].append(f'Pattern matched: {pattern}')
                    
        except Exception:
            pass
    
    def _check_api_endpoints(self):
        """Check for Discourse API endpoints"""
        api_endpoints = [
            '/site.json',
            '/about.json',
            '/categories.json',
            '/latest.json'
        ]
        
        for endpoint in api_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if any(key in data for key in ['categories', 'topic_list', 'about']):
                            self.results['indicators'].append(f'Valid Discourse API: {endpoint}')
                    except:
                        pass
                        
            except Exception:
                pass
    
    def _check_discourse_headers(self):
        """Check for Discourse-specific headers"""
        try:
            response = requests.get(self.target_url, timeout=10)
            
            discourse_headers = [
                'X-Discourse-Route',
                'X-Discourse-Username',
                'X-Discourse-Logged-In'
            ]
            
            for header in discourse_headers:
                if header in response.headers:
                    self.results['indicators'].append(f'Discourse header: {header}')
                    
        except Exception:
            pass
    
    def _extract_version(self):
        """Extract Discourse version"""
        try:
            # Try site.json
            url = urljoin(self.target_url, '/site.json')
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                version = data.get('version')
                
                if version:
                    self.results['version'] = version
                    self.results['version_details'] = {
                        'full_version': version,
                        'major': version.split('.')[0] if '.' in version else None
                    }
                    self.results['indicators'].append(f'Version detected: {version}')
                    
        except Exception:
            pass
    
    def _check_discourse_assets(self):
        """Check for Discourse asset files"""
        asset_paths = [
            '/assets/discourse.js',
            '/assets/vendor.js',
            '/stylesheets/desktop.css'
        ]
        
        for asset in asset_paths:
            try:
                url = urljoin(self.target_url, asset)
                response = requests.head(url, timeout=5)
                
                if response.status_code == 200:
                    self.results['indicators'].append(f'Discourse asset found: {asset}')
                    
            except Exception:
                pass
    
    def print_results(self):
        """Print validation results"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"Discourse Validation Results")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        status = "✓ CONFIRMED" if self.results['is_discourse'] else "✗ NOT DETECTED"
        color = Fore.GREEN if self.results['is_discourse'] else Fore.RED
        
        print(f"{color}Status: {status}{Style.RESET_ALL}")
        print(f"Confidence: {self.results['confidence']}%")
        
        if self.results['version']:
            print(f"{Fore.GREEN}Version: {self.results['version']}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Indicators Found: {len(self.results['indicators'])}{Style.RESET_ALL}")
        for indicator in self.results['indicators']:
            print(f"  • {indicator}")
