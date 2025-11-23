#!/usr/bin/env python3
"""
Rate Limit Module

Main rate limiting module that combines all rate limiting tests.
"""

from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from .login_rate_tester import LoginRateTester
from .api_rate_tester import APIRateTester
from .bypass_tester import BypassTester
from .header_analyzer import HeaderAnalyzer


class RateLimitModule:
    """Main rate limiting module"""
    
    def __init__(self, target_url: str, session: Optional[Any] = None,
                 verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session
        self.verbose = verbose
        
        # Initialize sub-modules
        self.login_tester = LoginRateTester(target_url, session, verbose)
        self.api_tester = APIRateTester(target_url, session, verbose)
        self.bypass_tester = BypassTester(target_url, session, verbose)
        self.header_analyzer = HeaderAnalyzer(target_url, session, verbose)
    
    def run(self) -> Dict[str, Any]:
        """Run comprehensive rate limiting tests (wrapper for scan method)"""
        return self.scan()
    
    def scan(self) -> Dict[str, Any]:
        """Run comprehensive rate limiting tests"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting comprehensive rate limiting scan...{Style.RESET_ALL}")
        
        results = {
            'login_rate_limiting': self.login_tester.test_login_rate_limit(),
            'api_rate_limiting': self.api_tester.test_all_endpoints(),
            'bypass_techniques': self.bypass_tester.test_all_bypass_methods(),
            'header_analysis': self.header_analyzer.analyze_headers(),
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Analyze results and generate recommendations
        self._analyze_results(results)
        
        return results
    
    def _analyze_results(self, results: Dict[str, Any]):
        """Analyze results and generate vulnerabilities/recommendations"""
        
        # Check login rate limiting
        login_result = results.get('login_rate_limiting', {})
        if not login_result.get('rate_limited', False):
            results['vulnerabilities'].append({
                'type': 'Missing Rate Limiting',
                'severity': 'HIGH',
                'endpoint': '/session',
                'description': 'Login endpoint lacks rate limiting protection'
            })
            
            results['recommendations'].append({
                'severity': 'HIGH',
                'issue': 'Missing login rate limiting',
                'recommendation': 'Implement rate limiting on authentication endpoints'
            })
        
        # Check API rate limiting
        api_results = results.get('api_rate_limiting', [])
        unprotected_apis = [r for r in api_results if not r.get('rate_limited', False)]
        
        if unprotected_apis:
            for api in unprotected_apis:
                results['vulnerabilities'].append({
                    'type': 'Missing API Rate Limiting',
                    'severity': 'MEDIUM',
                    'endpoint': api.get('endpoint', 'Unknown'),
                    'description': f"API endpoint {api.get('endpoint')} lacks rate limiting"
                })
        
        # Check bypass techniques
        bypass_results = results.get('bypass_techniques', [])
        successful_bypasses = [b for b in bypass_results if b.get('successful', False)]
        
        if successful_bypasses:
            for bypass in successful_bypasses:
                results['vulnerabilities'].append({
                    'type': 'Rate Limit Bypass',
                    'severity': 'HIGH',
                    'method': bypass.get('method', 'Unknown'),
                    'description': f"Rate limiting can be bypassed using {bypass.get('method')}"
                })
                
                results['recommendations'].append({
                    'severity': 'HIGH',
                    'issue': f"Rate limit bypass via {bypass.get('method')}",
                    'recommendation': 'Implement more robust rate limiting that cannot be easily bypassed'
                })
        
        # Check header analysis
        header_analysis = results.get('header_analysis', {})
        if not header_analysis.get('headers_found', []):
            results['recommendations'].append({
                'severity': 'LOW',
                'issue': 'No rate limiting headers detected',
                'recommendation': 'Consider adding rate limiting headers for transparency'
            })
    
    def quick_test(self) -> Dict[str, Any]:
        """Run a quick rate limiting test"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Running quick rate limiting test...{Style.RESET_ALL}")
        
        return {
            'login_test': self.login_tester.test_login_rate_limit(),
            'header_check': self.header_analyzer.analyze_headers()
        }