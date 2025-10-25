#!/usr/bin/env python3
"""
Category Discovery Module

Handles category enumeration and discovery functionality.
"""

import requests
from urllib.parse import urljoin
from colorama import Fore, Style


class CategoryDiscovery:
    """Category discovery and enumeration functionality"""
    
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.verbose = verbose
    
    def enumerate_categories(self):
        """Enumerate visible categories"""
        categories = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Enumerating visible categories...{Style.RESET_ALL}")
        
        try:
            # Get categories via API
            api_url = urljoin(self.target_url, '/categories.json')
            response = requests.get(api_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                category_list = data.get('category_list', {})
                
                for category in category_list.get('categories', []):
                    cat_info = {
                        'id': category.get('id'),
                        'name': category.get('name'),
                        'slug': category.get('slug'),
                        'description': category.get('description_text', ''),
                        'parent_category_id': category.get('parent_category_id'),
                        'read_restricted': category.get('read_restricted', False),
                        'permissions': category.get('permissions', {}),
                        'topic_count': category.get('topic_count', 0),
                        'post_count': category.get('post_count', 0)
                    }
                    categories.append(cat_info)
                    
                    if self.verbose:
                        print(f"  Found: {cat_info['name']} (ID: {cat_info['id']})")
            
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error enumerating categories: {e}{Style.RESET_ALL}")
        
        return categories
    
    def discover_hidden_categories(self):
        """Discover hidden categories through ID bruteforce"""
        hidden_categories = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Discovering hidden categories...{Style.RESET_ALL}")
        
        # Test common category IDs
        for cat_id in range(1, 101):
            try:
                api_url = urljoin(self.target_url, f'/c/{cat_id}.json')
                response = requests.get(api_url, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    category = data.get('category', {})
                    
                    if category:
                        cat_info = {
                            'id': category.get('id'),
                            'name': category.get('name'),
                            'slug': category.get('slug'),
                            'hidden': True,
                            'read_restricted': category.get('read_restricted', False)
                        }
                        hidden_categories.append(cat_info)
                        
                        if self.verbose:
                            print(f"  Hidden category found: {cat_info['name']} (ID: {cat_info['id']})")
                
            except Exception:
                continue
        
        return hidden_categories
    
    def build_category_tree(self, categories):
        """Build hierarchical category tree"""
        tree = {}
        
        # Create parent-child relationships
        for category in categories:
            parent_id = category.get('parent_category_id')
            cat_id = category.get('id')
            
            if parent_id:
                if parent_id not in tree:
                    tree[parent_id] = {'children': []}
                tree[parent_id]['children'].append(cat_id)
            else:
                if cat_id not in tree:
                    tree[cat_id] = {'children': []}
        
        return tree