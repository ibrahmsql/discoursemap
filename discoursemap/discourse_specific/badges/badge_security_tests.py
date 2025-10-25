#!/usr/bin/env python3
"""
Badge Security Tests

Handles badge security testing and vulnerability detection.
"""

import requests
from urllib.parse import urljoin
from colorama import Fore, Style


class BadgeSecurityTests:
    """Badge security testing functionality"""
    
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.verbose = verbose
    
    def test_badge_manipulation(self, badges):
        """Test badge manipulation vulnerabilities"""
        manipulation_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing badge manipulation...{Style.RESET_ALL}")
        
        for badge in badges[:5]:  # Test first 5 badges
            badge_id = badge.get('id')
            badge_name = badge.get('name')
            
            try:
                # Test badge granting
                grant_url = urljoin(self.target_url, f'/user_badges')
                test_data = {
                    'badge_id': badge_id,
                    'username': 'testuser'
                }
                
                response = requests.post(grant_url, data=test_data, timeout=10)
                
                if response.status_code in [200, 201]:
                    issue = {
                        'badge_id': badge_id,
                        'badge_name': badge_name,
                        'issue': 'Unauthorized badge granting possible',
                        'severity': 'high'
                    }
                    manipulation_issues.append(issue)
                    
                    if self.verbose:
                        print(f"  Badge manipulation found: {badge_name}")
                
            except Exception as e:
                if self.verbose:
                    print(f"  Error testing {badge_name}: {e}")
        
        return manipulation_issues
    
    def test_sql_query_exposure(self, badges):
        """Test for SQL query exposure in badges"""
        sql_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing SQL query exposure...{Style.RESET_ALL}")
        
        for badge in badges:
            badge_id = badge.get('id')
            badge_name = badge.get('name')
            query = badge.get('query', '')
            
            if query:
                # Check for sensitive SQL patterns
                sensitive_patterns = [
                    'SELECT.*FROM.*users',
                    'password',
                    'email',
                    'api_key',
                    'token',
                    'secret'
                ]
                
                for pattern in sensitive_patterns:
                    if pattern.lower() in query.lower():
                        issue = {
                            'badge_id': badge_id,
                            'badge_name': badge_name,
                            'query': query,
                            'pattern': pattern,
                            'issue': 'Sensitive data exposure in badge query',
                            'severity': 'medium'
                        }
                        sql_issues.append(issue)
                        
                        if self.verbose:
                            print(f"  SQL exposure found in {badge_name}: {pattern}")
        
        return sql_issues
    
    def test_custom_badge_creation(self):
        """Test custom badge creation vulnerabilities"""
        creation_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing custom badge creation...{Style.RESET_ALL}")
        
        try:
            # Test badge creation
            create_url = urljoin(self.target_url, '/admin/badges')
            test_data = {
                'name': 'Test Badge',
                'description': 'Test Description',
                'badge_type_id': 3,
                'query': 'SELECT id FROM users WHERE id = 1'
            }
            
            response = requests.post(create_url, data=test_data, timeout=10)
            
            if response.status_code in [200, 201]:
                issue = {
                    'issue': 'Unauthorized badge creation possible',
                    'severity': 'critical',
                    'description': 'Custom badges can be created without admin privileges'
                }
                creation_issues.append(issue)
                
                if self.verbose:
                    print(f"  Custom badge creation vulnerability found")
            
        except Exception as e:
            if self.verbose:
                print(f"  Error testing badge creation: {e}")
        
        return creation_issues
    
    def test_badge_grouping(self, badges):
        """Test badge grouping privilege escalation"""
        grouping_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing badge grouping...{Style.RESET_ALL}")
        
        for badge in badges[:3]:  # Test first 3 badges
            badge_id = badge.get('id')
            badge_name = badge.get('name')
            
            try:
                # Test badge group manipulation
                group_url = urljoin(self.target_url, f'/badges/{badge_id}/badge_groupings')
                test_data = {
                    'badge_grouping': {
                        'name': 'Test Group',
                        'description': 'Test Description'
                    }
                }
                
                response = requests.post(group_url, json=test_data, timeout=5)
                
                if response.status_code in [200, 201]:
                    issue = {
                        'badge_id': badge_id,
                        'badge_name': badge_name,
                        'issue': 'Badge grouping manipulation possible',
                        'severity': 'medium'
                    }
                    grouping_issues.append(issue)
                    
                    if self.verbose:
                        print(f"  Badge grouping issue found: {badge_name}")
                
            except Exception:
                continue
        
        return grouping_issues
    
    def test_auto_badge_flaws(self, badges):
        """Test automatic badge assignment flaws"""
        auto_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing automatic badge flaws...{Style.RESET_ALL}")
        
        for badge in badges:
            badge_id = badge.get('id')
            badge_name = badge.get('name')
            trigger = badge.get('trigger')
            
            if trigger:
                # Check for problematic triggers
                problematic_triggers = [
                    'TriggerType.PostAction',
                    'TriggerType.PostRevision',
                    'TriggerType.UserChange'
                ]
                
                if any(pt in str(trigger) for pt in problematic_triggers):
                    issue = {
                        'badge_id': badge_id,
                        'badge_name': badge_name,
                        'trigger': trigger,
                        'issue': 'Potentially exploitable auto-trigger',
                        'severity': 'medium'
                    }
                    auto_issues.append(issue)
                    
                    if self.verbose:
                        print(f"  Auto-badge flaw found: {badge_name}")
        
        return auto_issues