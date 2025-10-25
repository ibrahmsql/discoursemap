#!/usr/bin/env python3
"""
Discourse Trust Level Security Module - ADVANCED

Comprehensive testing for Discourse trust levels.
"""

from colorama import Fore, Style
from .trust_level_discovery import TrustLevelDiscovery
from .trust_level_tests import TrustLevelTests
from .trust_level_analysis import TrustLevelAnalysis


class TrustLevelSecurityModule:
    """Advanced trust level security testing"""
    
    def __init__(self, target_url, verbose=False):
        """Initialize the TrustLevelSecurityModule"""
        self.target_url = target_url
        self.verbose = verbose
        self.results = {
            'module': 'Trust Level Security',
            'module_name': 'Trust Level Security',
            'target': target_url,
            'trust_level_config': {},
            'tl_requirements': {'tl0': {}, 'tl1': {}, 'tl2': {}, 'tl3': {}, 'tl4': {}},
            'bypass_attempts': [],
            'privilege_escalation': [],
            'tl_locked_users': [],
            'automatic_promotion': [],
            'group_tl_overrides': [],
            'tl_based_permissions': [],
            'vulnerabilities': [],
            'recommendations': [],
            'total_tests': 0
        }
        
        # Initialize sub-modules
        self.discovery = TrustLevelDiscovery(target_url, verbose)
        self.tests = TrustLevelTests(target_url, verbose)
        self.analysis = TrustLevelAnalysis(target_url, verbose)
    
    def run(self):
        """Run the full trust level security assessment"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting Trust Level Security Scan...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Target: {self.target_url}{Style.RESET_ALL}\n")
        
        # Phase 1: Discovery
        self.results['trust_level_config'] = self.discovery.discover_trust_level_config()
        self.results['tl_requirements'] = self.discovery.enumerate_trust_level_requirements()
        endpoints = self.discovery.check_trust_level_endpoints()
        
        # Phase 2: Security Testing
        self.results['bypass_attempts'] = self.tests.test_trust_level_bypass()
        self.results['privilege_escalation'] = self.tests.test_privilege_escalation()
        self.results['automatic_promotion'] = self.tests.test_automatic_promotion_flaws()
        self.results['group_tl_overrides'] = self.tests.test_group_trust_level_overrides()
        self.results['tl_based_permissions'] = self.tests.test_trust_level_permissions()
        
        # Phase 3: Analysis
        self.results['tl_locked_users'] = self.analysis.analyze_locked_users()
        consistency_issues = self.analysis.check_trust_level_consistency(self.results['tl_requirements'])
        distribution = self.analysis.analyze_trust_level_distribution()
        api_exposures = self.analysis.check_trust_level_api_exposure()
        
        # Generate vulnerabilities and recommendations
        self._generate_vulnerabilities()
        self.results['recommendations'] = self.analysis.generate_trust_level_recommendations(self.results)
        
        return self.results
    
    def _generate_vulnerabilities(self):
        """Generate vulnerability entries from findings"""
        # Convert findings to vulnerability format
        for bypass in self.results['bypass_attempts']:
            if bypass.get('success'):
                vuln = {
                    'title': f"Trust Level Bypass: {bypass.get('method', 'Unknown')}",
                    'severity': bypass.get('severity', 'medium'),
                    'description': bypass.get('description', 'Trust level bypass detected'),
                    'method': bypass.get('method')
                }
                self.results['vulnerabilities'].append(vuln)
        
        for escalation in self.results['privilege_escalation']:
            if escalation.get('success'):
                vuln = {
                    'title': f"Privilege Escalation: {escalation.get('description', 'Unknown')}",
                    'severity': escalation.get('severity', 'high'),
                    'description': f"Privilege escalation via {escalation.get('endpoint', 'unknown endpoint')}",
                    'endpoint': escalation.get('endpoint')
                }
                self.results['vulnerabilities'].append(vuln)