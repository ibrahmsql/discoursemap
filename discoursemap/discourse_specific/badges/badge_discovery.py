#!/usr/bin/env python3
"""
Badge Discovery Module

Handles badge enumeration and discovery functionality.
"""

import requests
from urllib.parse import urljoin
from colorama import Fore, Style


class BadgeDiscovery:
    """Badge discovery and enumeration functionality"""
    
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.verbose = verbose
    
    def enumerate_badges(self):
        """Enumerate visible badges"""
        badges = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Enumerating badges...{Style.RESET_ALL}")
        
        try:
            # Get badges via API
            api_url = urljoin(self.target_url, '/badges.json')
            response = requests.get(api_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                badge_list = data.get('badges', [])
                
                for badge in badge_list:
                    badge_info = {
                        'id': badge.get('id'),
                        'name': badge.get('name'),
                        'description': badge.get('description'),
                        'badge_type_id': badge.get('badge_type_id'),
                        'grant_count': badge.get('grant_count', 0),
                        'enabled': badge.get('enabled', True),
                        'allow_title': badge.get('allow_title', False),
                        'multiple_grant': badge.get('multiple_grant', False),
                        'listable': badge.get('listable', True),
                        'auto_revoke': badge.get('auto_revoke', True),
                        'query': badge.get('query'),
                        'trigger': badge.get('trigger')
                    }
                    badges.append(badge_info)
                    
                    if self.verbose:
                        print(f"  Found: {badge_info['name']} (ID: {badge_info['id']})")
            
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error enumerating badges: {e}{Style.RESET_ALL}")
        
        return badges
    
    def discover_hidden_badges(self):
        """Discover hidden badges through ID bruteforce"""
        hidden_badges = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Discovering hidden badges...{Style.RESET_ALL}")
        
        # Test common badge IDs
        for badge_id in range(1, 51):
            try:
                api_url = urljoin(self.target_url, f'/badges/{badge_id}.json')
                response = requests.get(api_url, timeout=2)
                
                if response.status_code == 200:
                    data = response.json()
                    badge = data.get('badge', {})
                    
                    if badge:
                        badge_info = {
                            'id': badge.get('id'),
                            'name': badge.get('name'),
                            'description': badge.get('description'),
                            'hidden': True,
                            'enabled': badge.get('enabled', True)
                        }
                        hidden_badges.append(badge_info)
                        
                        if self.verbose:
                            print(f"  Hidden badge found: {badge_info['name']} (ID: {badge_info['id']})")
                
            except Exception:
                continue
        
        return hidden_badges
    
    def categorize_badges(self, badges):
        """Categorize badges by type"""
        badge_types = {
            'gold': [],
            'silver': [],
            'bronze': []
        }
        
        for badge in badges:
            badge_type_id = badge.get('badge_type_id', 3)  # Default to bronze
            
            if badge_type_id == 1:
                badge_types['gold'].append(badge)
            elif badge_type_id == 2:
                badge_types['silver'].append(badge)
            else:
                badge_types['bronze'].append(badge)
        
        return badge_types