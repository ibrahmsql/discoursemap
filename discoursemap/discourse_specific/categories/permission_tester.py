#!/usr/bin/env python3
"""
Category Permission Tester

Handles category permission testing and bypass attempts.
"""

import requests
from urllib.parse import urljoin
from colorama import Fore, Style


class CategoryPermissionTester:
    """Category permission testing functionality"""
    
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.verbose = verbose
    
    def test_read_permissions(self, categories):
        """Test read permissions for categories"""
        permission_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing read permissions...{Style.RESET_ALL}")
        
        for category in categories:
            cat_id = category.get('id')
            cat_name = category.get('name')
            
            try:
                # Test direct category access
                cat_url = urljoin(self.target_url, f'/c/{cat_id}')
                response = requests.get(cat_url, timeout=10)
                
                # Test API access
                api_url = urljoin(self.target_url, f'/c/{cat_id}.json')
                api_response = requests.get(api_url, timeout=10)
                
                # Check for permission inconsistencies
                if response.status_code == 200 and api_response.status_code != 200:
                    issue = {
                        'category_id': cat_id,
                        'category_name': cat_name,
                        'issue': 'Web access allowed but API blocked',
                        'severity': 'medium'
                    }
                    permission_issues.append(issue)
                    
                elif response.status_code != 200 and api_response.status_code == 200:
                    issue = {
                        'category_id': cat_id,
                        'category_name': cat_name,
                        'issue': 'API access allowed but web blocked',
                        'severity': 'medium'
                    }
                    permission_issues.append(issue)
                
            except Exception as e:
                if self.verbose:
                    print(f"  Error testing {cat_name}: {e}")
        
        return permission_issues
    
    def test_write_permissions(self, categories):
        """Test write permissions for categories"""
        write_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing write permissions...{Style.RESET_ALL}")
        
        for category in categories:
            cat_id = category.get('id')
            cat_name = category.get('name')
            
            try:
                # Test topic creation
                create_url = urljoin(self.target_url, '/posts')
                test_data = {
                    'title': 'Test Topic',
                    'raw': 'Test content',
                    'category': cat_id
                }
                
                response = requests.post(create_url, data=test_data, timeout=10)
                
                # Check response for permission bypass
                if response.status_code == 200:
                    issue = {
                        'category_id': cat_id,
                        'category_name': cat_name,
                        'issue': 'Unauthorized topic creation allowed',
                        'severity': 'high'
                    }
                    write_issues.append(issue)
                
            except Exception as e:
                if self.verbose:
                    print(f"  Error testing write access for {cat_name}: {e}")
        
        return write_issues
    
    def test_permission_bypass(self, categories):
        """Test various permission bypass techniques"""
        bypass_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing permission bypass techniques...{Style.RESET_ALL}")
        
        for category in categories:
            cat_id = category.get('id')
            cat_name = category.get('name')
            
            # Test various bypass methods
            bypass_methods = [
                f'/c/{cat_id}?_method=GET',
                f'/c/{cat_id}.json?bypass=1',
                f'/c/{cat_id}/../{cat_id}',
                f'/c/{cat_id}%00',
                f'/c/{cat_id}?admin=1'
            ]
            
            for method in bypass_methods:
                try:
                    test_url = urljoin(self.target_url, method)
                    response = requests.get(test_url, timeout=5)
                    
                    if response.status_code == 200:
                        issue = {
                            'category_id': cat_id,
                            'category_name': cat_name,
                            'bypass_method': method,
                            'issue': 'Permission bypass detected',
                            'severity': 'high'
                        }
                        bypass_issues.append(issue)
                        
                        if self.verbose:
                            print(f"  Bypass found: {method}")
                
                except Exception:
                    continue
        
        return bypass_issues
    
    def test_group_bypass(self, categories):
        """Test group-based permission bypass"""
        group_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing group permission bypass...{Style.RESET_ALL}")
        
        # Test common group manipulation
        test_groups = ['admin', 'moderators', 'staff', 'trust_level_4']
        
        for category in categories:
            cat_id = category.get('id')
            cat_name = category.get('name')
            
            for group in test_groups:
                try:
                    # Test group parameter injection
                    test_url = urljoin(self.target_url, f'/c/{cat_id}?group={group}')
                    response = requests.get(test_url, timeout=5)
                    
                    if response.status_code == 200:
                        issue = {
                            'category_id': cat_id,
                            'category_name': cat_name,
                            'group': group,
                            'issue': 'Group parameter bypass detected',
                            'severity': 'high'
                        }
                        group_issues.append(issue)
                
                except Exception:
                    continue
        
        return group_issues