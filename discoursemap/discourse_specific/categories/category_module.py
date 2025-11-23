#!/usr/bin/env python3
"""
Discourse Category Security Module - ADVANCED

Comprehensive category permission and security testing.
"""

from colorama import Fore, Style
from .category_discovery import CategoryDiscovery
from .permission_tester import CategoryPermissionTester
from .advanced_tests import AdvancedCategoryTests


class CategorySecurityModule:
    """Advanced category permission security testing"""
    
    def __init__(self, target_url, verbose=False):
        """Initialize the CategorySecurityModule"""
        self.target_url = target_url
        self.verbose = verbose
        self.results = {
            'module': 'Category Security',
            'module_name': 'Category Security',
            'target': target_url,
            'categories_found': [],
            'category_tree': {},
            'hidden_categories': [],
            'restricted_categories': [],
            'permission_bypass': [],
            'group_permissions': [],
            'subcategory_issues': [],
            'visibility_issues': [],
            'ownership_bypass': [],
            'vulnerabilities': [],
            'recommendations': [],
            'total_tests': 0
        }
        
        # Initialize sub-modules
        self.discovery = CategoryDiscovery(target_url, verbose)
        self.permission_tester = CategoryPermissionTester(target_url, verbose)
        self.advanced_tests = AdvancedCategoryTests(target_url, verbose)
    
    def run(self):
        """Run the full category security assessment"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting Advanced Category Security Scan...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Target: {self.target_url}{Style.RESET_ALL}\n")
        
        # Phase 1: Category Discovery
        self.results['categories_found'] = self.discovery.enumerate_categories()
        # Skip hidden category discovery for performance (would take too long)
        # self.results['hidden_categories'] = self.discovery.discover_hidden_categories()
        self.results['hidden_categories'] = []  # Skipped for performance
        self.results['category_tree'] = self.discovery.build_category_tree(self.results['categories_found'])
        
        # Phase 2: Permission Testing
        self.results['permission_bypass'].extend(
            self.permission_tester.test_read_permissions(self.results['categories_found'])
        )
        self.results['permission_bypass'].extend(
            self.permission_tester.test_write_permissions(self.results['categories_found'])
        )
        self.results['permission_bypass'].extend(
            self.permission_tester.test_permission_bypass(self.results['categories_found'])
        )
        self.results['group_permissions'] = self.permission_tester.test_group_bypass(self.results['categories_found'])
        
        # Phase 3: Advanced Tests
        self.results['subcategory_issues'] = self.advanced_tests.test_subcategory_security(
            self.results['categories_found'], self.results['category_tree']
        )
        self.results['visibility_issues'] = self.advanced_tests.test_category_visibility(self.results['categories_found'])
        self.results['ownership_bypass'] = self.advanced_tests.test_ownership_bypass(self.results['categories_found'])
        
        # Generate vulnerabilities and recommendations
        self._generate_vulnerabilities()
        self._generate_recommendations()
        
        return self.results
    
    def _generate_vulnerabilities(self):
        """Generate vulnerability entries from findings"""
        # Convert findings to vulnerability format
        for issue in self.results['permission_bypass']:
            vuln = {
                'title': f"Category Permission Issue: {issue.get('issue', 'Unknown')}",
                'severity': issue.get('severity', 'medium'),
                'description': f"Category {issue.get('category_name', 'Unknown')} has permission issues",
                'category_id': issue.get('category_id')
            }
            self.results['vulnerabilities'].append(vuln)
        
        for issue in self.results['ownership_bypass']:
            vuln = {
                'title': f"Category Ownership Bypass: {issue.get('issue', 'Unknown')}",
                'severity': issue.get('severity', 'high'),
                'description': f"Unauthorized access to category {issue.get('category_name', 'Unknown')}",
                'category_id': issue.get('category_id')
            }
            self.results['vulnerabilities'].append(vuln)
    
    def _generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = [
            "Review category permissions regularly",
            "Implement proper access controls for restricted categories",
            "Monitor category creation and modification activities",
            "Use group-based permissions instead of individual user permissions",
            "Regularly audit subcategory permission inheritance"
        ]
        
        if self.results['hidden_categories']:
            recommendations.append("Review hidden categories for proper access controls")
        
        if self.results['permission_bypass']:
            recommendations.append("Fix identified permission bypass vulnerabilities immediately")
        
        self.results['recommendations'] = recommendations