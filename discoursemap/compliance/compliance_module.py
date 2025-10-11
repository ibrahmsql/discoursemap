#!/usr/bin/env python3
"""
Discourse Compliance Module (Refactored)

Compliance and regulatory testing for Discourse forums.
Split from 1272 lines into modular components.
"""

from typing import Dict, Any
from colorama import Fore, Style
from .owasp_tests import OWASPTests
from .gdpr_ccpa_tests import PrivacyComplianceTests


class ComplianceModule:
    """Compliance testing module (Refactored)"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Compliance Testing',
            'target': scanner.target_url,
            'owasp_compliance': [],
            'gdpr_compliance': [],
            'ccpa_compliance': [],
            'security_headers': [],
            'privacy_policies': [],
            'recommendations': []
        }
        
        # Initialize sub-modules
        self.owasp_tester = OWASPTests(scanner)
        self.privacy_tester = PrivacyComplianceTests(scanner)
    
    def run(self):
        """Execute compliance tests"""
        return self.run_scan()
    
    def run_scan(self):
        """Execute all compliance scans"""
        print(f"{Fore.CYAN}[*] Starting Compliance Scan...{Style.RESET_ALL}")
        
        # OWASP Top 10 2021
        print(f"{Fore.YELLOW}[*] Testing OWASP Top 10 2021 compliance...{Style.RESET_ALL}")
        self.results['owasp_compliance'] = self.owasp_tester.run_all_tests()
        
        # GDPR Compliance
        print(f"{Fore.YELLOW}[*] Testing GDPR compliance...{Style.RESET_ALL}")
        self.results['gdpr_compliance'] = self.privacy_tester.test_gdpr_compliance()
        
        # CCPA Compliance
        print(f"{Fore.YELLOW}[*] Testing CCPA compliance...{Style.RESET_ALL}")
        self.results['ccpa_compliance'] = self.privacy_tester.test_ccpa_compliance()
        
        # Security Headers
        self._test_security_headers()
        
        # Generate recommendations
        self._generate_recommendations()
        
        # Print summary
        self._print_summary()
        
        return self.results
    
    def _test_security_headers(self):
        """Test security headers compliance"""
        print(f"{Fore.CYAN}[*] Testing security headers...{Style.RESET_ALL}")
        
        security_headers = {
            'strict-transport-security': 'HSTS - Enforces HTTPS',
            'content-security-policy': 'CSP - Prevents XSS',
            'x-frame-options': 'Prevents clickjacking',
            'x-content-type-options': 'Prevents MIME sniffing',
            'x-xss-protection': 'XSS filter',
            'referrer-policy': 'Controls referrer information'
        }
        
        try:
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                for header, description in security_headers.items():
                    if header in headers:
                        self.results['security_headers'].append({
                            'type': 'Security Header Present',
                            'severity': 'info',
                            'header': header,
                            'value': headers[header],
                            'description': f'{description} - Header present'
                        })
                    else:
                        severity = 'high' if header in ['strict-transport-security', 'content-security-policy'] else 'medium'
                        self.results['security_headers'].append({
                            'type': 'Missing Security Header',
                            'severity': severity,
                            'header': header,
                            'description': f'{description} - Header missing'
                        })
        except Exception as e:
            print(f"[!] Error testing security headers: {str(e)}")
    
    def _generate_recommendations(self):
        """Generate compliance recommendations"""
        recommendations = []
        
        # Count issues by severity
        all_issues = (
            self.results['owasp_compliance'] +
            self.results['gdpr_compliance'] +
            self.results['ccpa_compliance'] +
            self.results['security_headers']
        )
        
        critical = len([i for i in all_issues if i.get('severity') == 'critical'])
        high = len([i for i in all_issues if i.get('severity') == 'high'])
        medium = len([i for i in all_issues if i.get('severity') == 'medium'])
        
        if critical > 0:
            recommendations.append({
                'severity': 'CRITICAL',
                'issue': f'{critical} critical compliance issues',
                'recommendation': 'Address immediately - system may be vulnerable to serious attacks'
            })
        
        if high > 0:
            recommendations.append({
                'severity': 'HIGH',
                'issue': f'{high} high-priority compliance issues',
                'recommendation': 'Address as soon as possible to improve security posture'
            })
        
        if medium > 0:
            recommendations.append({
                'severity': 'MEDIUM',
                'issue': f'{medium} medium-priority compliance issues',
                'recommendation': 'Plan to address in next security review cycle'
            })
        
        self.results['recommendations'] = recommendations
    
    def _print_summary(self):
        """Print scan summary"""
        print(f"\n{Fore.GREEN}[+] Compliance scan complete!{Style.RESET_ALL}")
        
        owasp_count = len(self.results['owasp_compliance'])
        gdpr_count = len(self.results['gdpr_compliance'])
        ccpa_count = len(self.results['ccpa_compliance'])
        headers_count = len([h for h in self.results['security_headers'] if h['type'] == 'Missing Security Header'])
        
        print(f"    OWASP findings: {owasp_count}")
        print(f"    GDPR findings: {gdpr_count}")
        print(f"    CCPA findings: {ccpa_count}")
        print(f"    Missing headers: {headers_count}")
