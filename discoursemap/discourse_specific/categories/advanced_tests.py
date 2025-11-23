#!/usr/bin/env python3
"""
Advanced Category Tests

Advanced category security testing including subcategories, visibility, and archiving.
"""

import requests
from urllib.parse import urljoin
from colorama import Fore, Style


class AdvancedCategoryTests:
    """Advanced category security testing functionality"""
    
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.verbose = verbose
    
    def test_subcategory_security(self, categories, category_tree):
        """Test subcategory permission inheritance"""
        subcategory_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing subcategory security...{Style.RESET_ALL}")
        
        for parent_id, data in category_tree.items():
            children = data.get('children', [])
            
            for child_id in children:
                try:
                    # Test if child has different permissions than parent
                    parent_url = urljoin(self.target_url, f'/c/{parent_id}.json')
                    child_url = urljoin(self.target_url, f'/c/{child_id}.json')
                    
                    parent_response = requests.get(parent_url, timeout=5)
                    child_response = requests.get(child_url, timeout=5)
                    
                    # Check for permission inheritance issues
                    if parent_response.status_code != child_response.status_code:
                        issue = {
                            'parent_id': parent_id,
                            'child_id': child_id,
                            'issue': 'Permission inheritance mismatch',
                            'parent_status': parent_response.status_code,
                            'child_status': child_response.status_code,
                            'severity': 'medium'
                        }
                        subcategory_issues.append(issue)
                
                except Exception as e:
                    if self.verbose:
                        print(f"  Error testing subcategory {child_id}: {e}")
        
        return subcategory_issues
    
    def test_category_visibility(self, categories):
        """Test category visibility manipulation"""
        visibility_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing category visibility...{Style.RESET_ALL}")
        
        for category in categories[:3]:  # Limit to first 3 categories for performance
            cat_id = category.get('id')
            cat_name = category.get('name')
            
            # Test visibility manipulation techniques
            visibility_tests = [
                f'/c/{cat_id}?visible=true',
                f'/c/{cat_id}?show_hidden=1',
                f'/c/{cat_id}?force_visible=true',
                f'/c/{cat_id}.json?include_hidden=1'
            ]
            
            for test in visibility_tests:
                try:
                    test_url = urljoin(self.target_url, test)
                    response = requests.get(test_url, timeout=5)
                    
                    if response.status_code == 200:
                        # Check if response contains more data than expected
                        if len(response.text) > 1000:  # Arbitrary threshold
                            issue = {
                                'category_id': cat_id,
                                'category_name': cat_name,
                                'test_method': test,
                                'issue': 'Visibility bypass detected',
                                'severity': 'medium'
                            }
                            visibility_issues.append(issue)
                
                except Exception:
                    continue
        
        return visibility_issues
    
    def test_category_archiving(self, categories):
        """Test category archiving vulnerabilities"""
        archiving_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing category archiving...{Style.RESET_ALL}")
        
        for category in categories[:3]:  # Limit to first 3 categories for performance
            cat_id = category.get('id')
            cat_name = category.get('name')
            
            try:
                # Test archive manipulation
                archive_url = urljoin(self.target_url, f'/categories/{cat_id}/archive')
                response = requests.post(archive_url, timeout=5)
                
                if response.status_code in [200, 302]:
                    issue = {
                        'category_id': cat_id,
                        'category_name': cat_name,
                        'issue': 'Unauthorized category archiving possible',
                        'severity': 'high'
                    }
                    archiving_issues.append(issue)
                
                # Test unarchive
                unarchive_url = urljoin(self.target_url, f'/categories/{cat_id}/unarchive')
                response = requests.post(unarchive_url, timeout=5)
                
                if response.status_code in [200, 302]:
                    issue = {
                        'category_id': cat_id,
                        'category_name': cat_name,
                        'issue': 'Unauthorized category unarchiving possible',
                        'severity': 'high'
                    }
                    archiving_issues.append(issue)
            
            except Exception as e:
                if self.verbose:
                    print(f"  Error testing archiving for {cat_name}: {e}")
        
        return archiving_issues
    
    def test_ownership_bypass(self, categories):
        """Test category ownership bypass"""
        ownership_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing ownership bypass...{Style.RESET_ALL}")
        
        for category in categories[:3]:  # Limit to first 3 categories for performance
            cat_id = category.get('id')
            cat_name = category.get('name')
            
            # Test ownership manipulation
            ownership_tests = [
                {'url': f'/categories/{cat_id}/edit', 'method': 'GET'},
                {'url': f'/categories/{cat_id}/settings', 'method': 'GET'},
                {'url': f'/categories/{cat_id}/permissions', 'method': 'GET'},
                {'url': f'/categories/{cat_id}/delete', 'method': 'POST'}
            ]
            
            for test in ownership_tests:
                try:
                    test_url = urljoin(self.target_url, test['url'])
                    
                    if test['method'] == 'GET':
                        response = requests.get(test_url, timeout=5)
                    else:
                        response = requests.post(test_url, timeout=5)
                    
                    if response.status_code in [200, 302]:
                        issue = {
                            'category_id': cat_id,
                            'category_name': cat_name,
                            'test_url': test['url'],
                            'issue': 'Unauthorized administrative access detected',
                            'severity': 'critical'
                        }
                        ownership_issues.append(issue)
                
                except Exception:
                    continue
        
        return ownership_issues