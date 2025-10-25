#!/usr/bin/env python3
"""
Trust Level Discovery Module

Handles trust level enumeration and configuration discovery.
"""

import requests
from urllib.parse import urljoin
from colorama import Fore, Style


class TrustLevelDiscovery:
    """Trust level discovery and enumeration functionality"""
    
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.verbose = verbose
    
    def discover_trust_level_config(self):
        """Discover trust level configuration"""
        config = {}
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Discovering trust level configuration...{Style.RESET_ALL}")
        
        try:
            # Get site settings that might reveal TL config
            settings_url = urljoin(self.target_url, '/admin/site_settings.json')
            response = requests.get(settings_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                site_settings = data.get('site_settings', [])
                
                for setting in site_settings:
                    setting_name = setting.get('setting')
                    if 'trust_level' in setting_name or 'tl' in setting_name:
                        config[setting_name] = {
                            'value': setting.get('value'),
                            'default': setting.get('default'),
                            'description': setting.get('description', '')
                        }
                        
                        if self.verbose:
                            print(f"  Found TL setting: {setting_name} = {setting.get('value')}")
            
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error discovering TL config: {e}{Style.RESET_ALL}")
        
        return config
    
    def enumerate_trust_level_requirements(self):
        """Enumerate trust level requirements"""
        requirements = {
            'tl0': {'name': 'New User', 'requirements': []},
            'tl1': {'name': 'Basic User', 'requirements': []},
            'tl2': {'name': 'Member', 'requirements': []},
            'tl3': {'name': 'Regular', 'requirements': []},
            'tl4': {'name': 'Leader', 'requirements': []}
        }
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Enumerating trust level requirements...{Style.RESET_ALL}")
        
        try:
            # Try to get TL requirements from about page or API
            about_url = urljoin(self.target_url, '/about.json')
            response = requests.get(about_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                about_data = data.get('about', {})
                
                # Look for trust level information
                if 'trust_levels' in about_data:
                    tl_data = about_data['trust_levels']
                    for tl in tl_data:
                        tl_id = tl.get('id', 0)
                        if f'tl{tl_id}' in requirements:
                            requirements[f'tl{tl_id}'].update({
                                'name': tl.get('name', ''),
                                'requirements': tl.get('requirements', [])
                            })
                            
                            if self.verbose:
                                print(f"  TL{tl_id}: {tl.get('name', '')}")
            
        except Exception as e:
            if self.verbose:
                print(f"  Error getting TL requirements: {e}")
        
        return requirements
    
    def check_trust_level_endpoints(self):
        """Check accessibility of trust level related endpoints"""
        endpoints = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Checking trust level endpoints...{Style.RESET_ALL}")
        
        # Test various TL-related endpoints
        test_endpoints = [
            '/admin/users/trust_level',
            '/admin/users/trust_level_locked',
            '/admin/users/list/trust_level_0',
            '/admin/users/list/trust_level_1',
            '/admin/users/list/trust_level_2',
            '/admin/users/list/trust_level_3',
            '/admin/users/list/trust_level_4',
            '/users/trust_level_promotions'
        ]
        
        for endpoint in test_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = requests.get(url, timeout=5)
                
                endpoint_info = {
                    'endpoint': endpoint,
                    'status_code': response.status_code,
                    'accessible': response.status_code == 200,
                    'content_length': len(response.text) if response.text else 0
                }
                endpoints.append(endpoint_info)
                
                if self.verbose and response.status_code == 200:
                    print(f"  Accessible: {endpoint}")
                
            except Exception:
                continue
        
        return endpoints