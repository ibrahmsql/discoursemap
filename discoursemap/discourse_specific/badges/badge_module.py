#!/usr/bin/env python3
"""
Discourse Badge System Security Module

Comprehensive badge system security testing.
"""

from colorama import Fore, Style
from .badge_discovery import BadgeDiscovery
from .badge_security_tests import BadgeSecurityTests


class BadgeSecurityModule:
    """Advanced badge system security testing for Discourse"""
    
    def __init__(self, target_url, verbose=False):
        """Initialize the BadgeSecurityModule"""
        self.target_url = target_url
        self.verbose = verbose
        self.results = {
            'module': 'Badge Security (Advanced)',
            'badges_found': [],
            'badge_types': {
                'gold': [],
                'silver': [],
                'bronze': []
            },
            'badge_manipulation': [],
            'badge_enumeration': [],
            'sql_query_exposure': [],
            'auto_badge_flaws': [],
            'custom_badge_vulns': [],
            'badge_grouping_issues': [],
            'vulnerabilities': [],
            'recommendations': [],
            'total_tests': 0
        }
        
        # Initialize sub-modules
        self.discovery = BadgeDiscovery(target_url, verbose)
        self.security_tests = BadgeSecurityTests(target_url, verbose)
    
    def run(self):
        """Run the full badge security assessment"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting Badge Security Scan...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Target: {self.target_url}{Style.RESET_ALL}\n")
        
        # Phase 1: Badge Discovery
        self.results['badges_found'] = self.discovery.enumerate_badges()
        hidden_badges = self.discovery.discover_hidden_badges()
        self.results['badge_enumeration'] = hidden_badges
        self.results['badge_types'] = self.discovery.categorize_badges(self.results['badges_found'])
        
        # Phase 2: Security Testing
        self.results['badge_manipulation'] = self.security_tests.test_badge_manipulation(self.results['badges_found'])
        self.results['sql_query_exposure'] = self.security_tests.test_sql_query_exposure(self.results['badges_found'])
        self.results['custom_badge_vulns'] = self.security_tests.test_custom_badge_creation()
        self.results['badge_grouping_issues'] = self.security_tests.test_badge_grouping(self.results['badges_found'])
        self.results['auto_badge_flaws'] = self.security_tests.test_auto_badge_flaws(self.results['badges_found'])
        
        # Generate vulnerabilities and recommendations
        self._generate_vulnerabilities()
        self._generate_recommendations()
        
        return self.results
    
    def _generate_vulnerabilities(self):
        """Generate vulnerability entries from findings"""
        # Convert findings to vulnerability format
        for issue in self.results['badge_manipulation']:
            vuln = {
                'title': f"Badge Manipulation: {issue.get('issue', 'Unknown')}",
                'severity': issue.get('severity', 'medium'),
                'description': f"Badge {issue.get('badge_name', 'Unknown')} has manipulation issues",
                'badge_id': issue.get('badge_id')
            }
            self.results['vulnerabilities'].append(vuln)
        
        for issue in self.results['custom_badge_vulns']:
            vuln = {
                'title': f"Custom Badge Creation: {issue.get('issue', 'Unknown')}",
                'severity': issue.get('severity', 'high'),
                'description': issue.get('description', 'Custom badge creation vulnerability'),
            }
            self.results['vulnerabilities'].append(vuln)
    
    def _generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = [
            "Review badge granting permissions regularly",
            "Implement proper access controls for badge management",
            "Monitor badge creation and modification activities",
            "Validate SQL queries in custom badges",
            "Regularly audit automatic badge triggers"
        ]
        
        if self.results['badge_enumeration']:
            recommendations.append("Review hidden badges for proper access controls")
        
        if self.results['badge_manipulation']:
            recommendations.append("Fix identified badge manipulation vulnerabilities immediately")
        
        self.results['recommendations'] = recommendations