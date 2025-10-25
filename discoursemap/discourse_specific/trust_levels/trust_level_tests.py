#!/usr/bin/env python3
"""
Trust Level Security Tests

Handles trust level security testing and bypass attempts.
"""

import requests
from urllib.parse import urljoin
from colorama import Fore, Style


class TrustLevelTests:
    """Trust level security testing functionality"""
    
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.verbose = verbose
    
    def test_trust_level_bypass(self):
        """Test trust level bypass vulnerabilities"""
        bypass_attempts = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing trust level bypass...{Style.RESET_ALL}")
        
        # Test various bypass methods
        bypass_methods = [
            {'method': 'Parameter injection', 'params': {'trust_level': 4}},
            {'method': 'Header manipulation', 'headers': {'X-Trust-Level': '4'}},
            {'method': 'Cookie manipulation', 'cookies': {'trust_level': '4'}},
            {'method': 'User-Agent spoofing', 'headers': {'User-Agent': 'DiscourseBot/1.0 (TL4)'}},
            {'method': 'Referer manipulation', 'headers': {'Referer': '/admin/users/trust_level_4'}}
        ]
        
        for method in bypass_methods:
            try:
                # Test on a restricted endpoint
                test_url = urljoin(self.target_url, '/admin/users')
                
                kwargs = {}
                if 'params' in method:
                    kwargs['params'] = method['params']
                if 'headers' in method:
                    kwargs['headers'] = method['headers']
                if 'cookies' in method:
                    kwargs['cookies'] = method['cookies']
                
                response = requests.get(test_url, timeout=5, **kwargs)
                
                if response.status_code == 200:
                    bypass_attempt = {
                        'method': method['method'],
                        'endpoint': '/admin/users',
                        'success': True,
                        'severity': 'high',
                        'description': f'Trust level bypass via {method["method"]}'
                    }
                    bypass_attempts.append(bypass_attempt)
                    
                    if self.verbose:
                        print(f"  Bypass found: {method['method']}")
                
            except Exception:
                continue
        
        return bypass_attempts
    
    def test_privilege_escalation(self):
        """Test privilege escalation through trust levels"""
        escalation_attempts = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing privilege escalation...{Style.RESET_ALL}")
        
        # Test trust level manipulation endpoints
        escalation_tests = [
            {
                'endpoint': '/admin/users/trust_level',
                'method': 'POST',
                'data': {'user_id': 1, 'level': 4},
                'description': 'Direct trust level modification'
            },
            {
                'endpoint': '/admin/users/trust_level_lock',
                'method': 'PUT',
                'data': {'user_id': 1, 'trust_level_locked': False},
                'description': 'Trust level lock bypass'
            },
            {
                'endpoint': '/admin/users/grant_admin',
                'method': 'PUT',
                'data': {'user_id': 1},
                'description': 'Admin privilege escalation'
            }
        ]
        
        for test in escalation_tests:
            try:
                url = urljoin(self.target_url, test['endpoint'])
                
                if test['method'] == 'POST':
                    response = requests.post(url, data=test['data'], timeout=5)
                elif test['method'] == 'PUT':
                    response = requests.put(url, data=test['data'], timeout=5)
                else:
                    response = requests.get(url, params=test['data'], timeout=5)
                
                if response.status_code in [200, 201, 202]:
                    escalation = {
                        'endpoint': test['endpoint'],
                        'method': test['method'],
                        'description': test['description'],
                        'success': True,
                        'severity': 'critical'
                    }
                    escalation_attempts.append(escalation)
                    
                    if self.verbose:
                        print(f"  Escalation possible: {test['description']}")
                
            except Exception:
                continue
        
        return escalation_attempts
    
    def test_automatic_promotion_flaws(self):
        """Test automatic promotion system flaws"""
        promotion_flaws = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing automatic promotion flaws...{Style.RESET_ALL}")
        
        try:
            # Test promotion trigger endpoints
            promotion_url = urljoin(self.target_url, '/admin/users/trust_level_promotions')
            response = requests.get(promotion_url, timeout=10)
            
            if response.status_code == 200:
                flaw = {
                    'issue': 'Promotion data accessible',
                    'endpoint': '/admin/users/trust_level_promotions',
                    'severity': 'medium',
                    'description': 'Trust level promotion data is accessible without authentication'
                }
                promotion_flaws.append(flaw)
                
                if self.verbose:
                    print(f"  Promotion data accessible")
            
            # Test manual promotion trigger
            trigger_url = urljoin(self.target_url, '/admin/users/recalculate_trust_level')
            response = requests.post(trigger_url, data={'user_id': 1}, timeout=5)
            
            if response.status_code in [200, 202]:
                flaw = {
                    'issue': 'Manual promotion trigger accessible',
                    'endpoint': '/admin/users/recalculate_trust_level',
                    'severity': 'high',
                    'description': 'Trust level recalculation can be triggered without authorization'
                }
                promotion_flaws.append(flaw)
                
                if self.verbose:
                    print(f"  Manual promotion trigger accessible")
            
        except Exception as e:
            if self.verbose:
                print(f"  Error testing promotion flaws: {e}")
        
        return promotion_flaws
    
    def test_group_trust_level_overrides(self):
        """Test group-based trust level overrides"""
        override_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing group TL overrides...{Style.RESET_ALL}")
        
        try:
            # Test group membership manipulation for TL bypass
            groups_url = urljoin(self.target_url, '/groups.json')
            response = requests.get(groups_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                groups = data.get('groups', [])
                
                for group in groups[:5]:  # Test first 5 groups
                    group_id = group.get('id')
                    group_name = group.get('name')
                    
                    # Test joining group
                    join_url = urljoin(self.target_url, f'/groups/{group_id}/members')
                    response = requests.post(join_url, data={'usernames': 'testuser'}, timeout=5)
                    
                    if response.status_code in [200, 201]:
                        issue = {
                            'group_id': group_id,
                            'group_name': group_name,
                            'issue': 'Unauthorized group join possible',
                            'severity': 'medium',
                            'description': f'Can join group {group_name} which may have TL overrides'
                        }
                        override_issues.append(issue)
                        
                        if self.verbose:
                            print(f"  Group join possible: {group_name}")
            
        except Exception as e:
            if self.verbose:
                print(f"  Error testing group overrides: {e}")
        
        return override_issues
    
    def test_trust_level_permissions(self):
        """Test trust level based permissions"""
        permission_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Testing TL-based permissions...{Style.RESET_ALL}")
        
        # Test various TL-restricted actions
        tl_actions = [
            {'action': 'Create topic', 'endpoint': '/posts', 'method': 'POST', 'min_tl': 0},
            {'action': 'Upload files', 'endpoint': '/uploads', 'method': 'POST', 'min_tl': 1},
            {'action': 'Send messages', 'endpoint': '/posts', 'method': 'POST', 'min_tl': 1},
            {'action': 'Edit posts', 'endpoint': '/posts/1', 'method': 'PUT', 'min_tl': 2},
            {'action': 'Flag posts', 'endpoint': '/post_actions', 'method': 'POST', 'min_tl': 0}
        ]
        
        for action in tl_actions:
            try:
                url = urljoin(self.target_url, action['endpoint'])
                test_data = {'title': 'Test', 'raw': 'Test content', 'category': 1}
                
                if action['method'] == 'POST':
                    response = requests.post(url, data=test_data, timeout=5)
                elif action['method'] == 'PUT':
                    response = requests.put(url, data=test_data, timeout=5)
                else:
                    response = requests.get(url, timeout=5)
                
                if response.status_code in [200, 201]:
                    issue = {
                        'action': action['action'],
                        'endpoint': action['endpoint'],
                        'min_tl_required': action['min_tl'],
                        'issue': 'Action allowed without proper TL',
                        'severity': 'medium'
                    }
                    permission_issues.append(issue)
                    
                    if self.verbose:
                        print(f"  Permission bypass: {action['action']}")
                
            except Exception:
                continue
        
        return permission_issues