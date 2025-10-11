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
        """
        Create a DiscourseValidator for a target URL and configure verbosity.
        
        Parameters:
        	target_url (str): Base URL of the site to validate; a trailing slash will be removed.
        	verbose (bool): If True, enable verbose status output during validation.
        
        Initializes:
        	results (dict): Default validation state with keys:
        		- is_discourse: False
        		- version: None
        		- version_details: {}
        		- confidence: 0
        		- indicators: []
        """
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
        """
        Run a sequence of checks to determine whether the target URL is a Discourse forum and collect related indicators.
        
        Performs meta tag, API endpoint, header, version, and asset checks, computes a confidence score as 20 points per found indicator (capped at 100), and sets `is_discourse` to `True` when confidence is greater than or equal to 60.
        
        Returns:
            dict: Results dictionary containing:
                - is_discourse (bool): `True` when confidence >= 60, `False` otherwise.
                - version (str|None): Extracted Discourse version string when available.
                - version_details (dict|None): Additional version info (e.g., full_version, major) when available.
                - confidence (int): Confidence percentage (0–100).
                - indicators (list[str]): Collected indicator strings found during validation.
        """
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
        """
        Detects Discourse-related markers in the target page's HTML and records indicators.
        
        Performs an HTTP GET to the instance's root page and, if the page is reachable, appends entries to self.results['indicators'] for:
        - the presence of the literal "Discourse" in the page text, and
        - any matches against common Discourse-related patterns (meta name="discourse", data-discourse- attributes, discourse.org references).
        
        Network errors and parsing failures are ignored and do not raise exceptions.
        """
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
        """
        Probe common Discourse API endpoints on the instance and record positive indicators.
        
        For each known endpoint, perform an HTTP request and, if the response contains JSON with keys such as `categories`, `topic_list`, or `about`, append a `Valid Discourse API: <endpoint>` entry to `self.results['indicators']`.
        """
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
        """
        Obtain Discourse version information from the site's /site.json and record it in self.results.
        
        If /site.json returns JSON containing a `version` field, this method sets:
        - `self.results['version']` to the version string,
        - `self.results['version_details']` to a dict with `full_version` and `major` (the portion before the first dot, or `None` if not present),
        and appends an indicator string "Version detected: <version>" to `self.results['indicators']`. Network, HTTP, and JSON parsing errors are ignored.
        """
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
        """
        Detects common Discourse static asset files on the target site and records any found assets as indicators.
        
        This method probes a set of well-known Discourse asset paths and appends a descriptive indicator to self.results['indicators'] for each asset that is present.
        """
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
        """
        Print a concise, colorized summary of the validation results to standard output.
        
        Displays a header, detection status (CONFIRMED or NOT DETECTED), the computed confidence percentage, the discovered version if available, and a numbered list of found indicators. Output includes ANSI color formatting for readability.
        """
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