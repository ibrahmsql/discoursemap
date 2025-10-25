#!/usr/bin/env python3
"""
Trust Level Analysis Module

Handles trust level analysis and vulnerability assessment.
"""

import requests
from urllib.parse import urljoin
from colorama import Fore, Style


class TrustLevelAnalysis:
    """Trust level analysis and assessment functionality"""
    
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.verbose = verbose
    
    def analyze_locked_users(self):
        """Analyze trust level locked users"""
        locked_users = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Analyzing locked users...{Style.RESET_ALL}")
        
        try:
            # Try to get locked users list
            locked_url = urljoin(self.target_url, '/admin/users/list/trust_level_locked')
            response = requests.get(locked_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                users = data.get('users', [])
                
                for user in users:
                    user_info = {
                        'id': user.get('id'),
                        'username': user.get('username'),
                        'trust_level': user.get('trust_level'),
                        'trust_level_locked': user.get('trust_level_locked', False),
                        'admin': user.get('admin', False),
                        'moderator': user.get('moderator', False)
                    }
                    locked_users.append(user_info)
                    
                    if self.verbose:
                        print(f"  Locked user: {user_info['username']} (TL{user_info['trust_level']})")
            
        except Exception as e:
            if self.verbose:
                print(f"  Error analyzing locked users: {e}")
        
        return locked_users
    
    def check_trust_level_consistency(self, requirements):
        """Check trust level requirement consistency"""
        consistency_issues = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Checking TL consistency...{Style.RESET_ALL}")
        
        # Check for logical inconsistencies in TL requirements
        for tl_name, tl_data in requirements.items():
            tl_requirements = tl_data.get('requirements', [])
            
            # Check for unrealistic requirements
            for req in tl_requirements:
                if isinstance(req, dict):
                    # Check for suspiciously low requirements for high TLs
                    if tl_name in ['tl3', 'tl4']:
                        if req.get('days_visited', 0) < 30:
                            issue = {
                                'trust_level': tl_name,
                                'issue': 'Low days_visited requirement',
                                'requirement': req,
                                'severity': 'low',
                                'description': f'{tl_name} has suspiciously low days_visited requirement'
                            }
                            consistency_issues.append(issue)
                        
                        if req.get('posts_read', 0) < 100:
                            issue = {
                                'trust_level': tl_name,
                                'issue': 'Low posts_read requirement',
                                'requirement': req,
                                'severity': 'low',
                                'description': f'{tl_name} has suspiciously low posts_read requirement'
                            }
                            consistency_issues.append(issue)
        
        if self.verbose and consistency_issues:
            print(f"  Found {len(consistency_issues)} consistency issues")
        
        return consistency_issues
    
    def analyze_trust_level_distribution(self):
        """Analyze trust level distribution among users"""
        distribution = {}
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Analyzing TL distribution...{Style.RESET_ALL}")
        
        try:
            # Try to get user statistics for each trust level
            for tl in range(5):  # TL0 to TL4
                tl_url = urljoin(self.target_url, f'/admin/users/list/trust_level_{tl}')
                response = requests.get(tl_url, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    user_count = len(data.get('users', []))
                    distribution[f'tl{tl}'] = {
                        'count': user_count,
                        'accessible': True
                    }
                    
                    if self.verbose:
                        print(f"  TL{tl}: {user_count} users")
                else:
                    distribution[f'tl{tl}'] = {
                        'count': 0,
                        'accessible': False
                    }
            
        except Exception as e:
            if self.verbose:
                print(f"  Error analyzing distribution: {e}")
        
        return distribution
    
    def check_trust_level_api_exposure(self):
        """Check for trust level API exposure"""
        api_exposures = []
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Checking TL API exposure...{Style.RESET_ALL}")
        
        # Test various TL-related API endpoints
        api_endpoints = [
            '/admin/users/trust_level.json',
            '/admin/users/trust_level_promotions.json',
            '/admin/site_settings/trust_level.json',
            '/users/trust_level_stats.json',
            '/admin/users/list/trust_level_0.json',
            '/admin/users/list/trust_level_4.json'
        ]
        
        for endpoint in api_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200:
                    exposure = {
                        'endpoint': endpoint,
                        'status_code': response.status_code,
                        'content_length': len(response.text),
                        'severity': 'medium',
                        'description': f'Trust level API endpoint {endpoint} is accessible'
                    }
                    api_exposures.append(exposure)
                    
                    if self.verbose:
                        print(f"  API exposed: {endpoint}")
                
            except Exception:
                continue
        
        return api_exposures
    
    def generate_trust_level_recommendations(self, findings):
        """Generate trust level security recommendations"""
        recommendations = []
        
        # Base recommendations
        base_recommendations = [
            "Review trust level requirements regularly",
            "Implement proper access controls for TL management endpoints",
            "Monitor trust level changes and promotions",
            "Use group-based permissions instead of relying solely on trust levels",
            "Regularly audit high trust level users"
        ]
        
        recommendations.extend(base_recommendations)
        
        # Specific recommendations based on findings
        if findings.get('bypass_attempts'):
            recommendations.append("Fix identified trust level bypass vulnerabilities immediately")
        
        if findings.get('privilege_escalation'):
            recommendations.append("Implement stronger authorization checks for privilege escalation")
        
        if findings.get('api_exposures'):
            recommendations.append("Restrict access to trust level management APIs")
        
        if findings.get('automatic_promotion'):
            recommendations.append("Review automatic promotion triggers for security issues")
        
        return recommendations