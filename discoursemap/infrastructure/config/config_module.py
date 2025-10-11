#!/usr/bin/env python3
"""
Discourse Configuration Module (Refactored)

Configuration security testing for Discourse forums.
Split from 1030 lines into modular components.
"""

from typing import Dict, Any
from colorama import Fore, Style
from .config_parsers import ConfigParser
from .config_security import ConfigSecurityTester


class ConfigModule:
    """Configuration security module (Refactored)"""
    
    def __init__(self, scanner):
        """
        Create a ConfigModule that orchestrates configuration parsing and security testing for a target.
        
        Parameters:
            scanner: External scanner object that provides the target URL (accessible as `scanner.target_url`) and utilities required by the parser and security tester.
        
        Description:
            Initializes the module's results structure with placeholders for site settings, about info, detected plugins, HTML configuration, vulnerabilities, and recommendations, and instantiates the ConfigParser and ConfigSecurityTester sub-modules using the provided scanner.
        """
        self.scanner = scanner
        self.results = {
            'module_name': 'Configuration Security',
            'target': scanner.target_url,
            'site_settings': {},
            'about_info': {},
            'plugins': [],
            'html_config': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Initialize sub-modules
        self.parser = ConfigParser(scanner)
        self.security_tester = ConfigSecurityTester(scanner)
    
    def run(self) -> Dict[str, Any]:
        """
        Run the full configuration security scan and collect aggregated findings.
        
        Performs parsing of site configuration and about.json, detects plugins and HTML configuration, runs security tests, generates recommendations based on findings, and prints a concise summary to the console.
        
        Returns:
            results (Dict[str, Any]): Aggregated scan data containing keys such as
                - module_name: Name of the module ("Configuration Security")
                - target: Scanned target URL
                - site_settings: Parsed site settings
                - about_info: Parsed about.json data
                - plugins: Detected plugins list
                - html_config: Extracted HTML configuration data
                - vulnerabilities: List of discovered security issues
                - recommendations: Generated remediation and prioritization items
        """
        print(f"{Fore.CYAN}[*] Starting Configuration Security Scan...{Style.RESET_ALL}")
        
        # Parse configurations
        print(f"{Fore.YELLOW}[*] Parsing site configuration...{Style.RESET_ALL}")
        self.results['site_settings'] = self.parser.parse_site_settings()
        self.results['about_info'] = self.parser.parse_about_json()
        self.results['plugins'] = self.parser.detect_plugins()
        self.results['html_config'] = self.parser.extract_html_config()
        
        # Test security
        print(f"{Fore.YELLOW}[*] Testing configuration security...{Style.RESET_ALL}")
        self.results['vulnerabilities'] = self.security_tester.test_all_security()
        
        # Generate recommendations
        self._generate_recommendations()
        
        # Print summary
        self._print_summary()
        
        return self.results
    
    def _generate_recommendations(self):
        """
        Builds a prioritized list of configuration recommendations and stores it in self.results['recommendations'].
        
        Creates recommendation entries when there are any vulnerabilities with severity "critical" or "high", and when the number of detected plugins exceeds 20. Each entry is a dict with the keys: 'severity' (one of 'CRITICAL', 'HIGH', 'MEDIUM'), 'issue' (a short description including the relevant count), and 'recommendation' (an action-oriented suggestion).
        """
        recommendations = []
        
        # Count by severity
        critical = len([v for v in self.results['vulnerabilities'] if v['severity'] == 'critical'])
        high = len([v for v in self.results['vulnerabilities'] if v['severity'] == 'high'])
        
        if critical > 0:
            recommendations.append({
                'severity': 'CRITICAL',
                'issue': f'{critical} critical configuration issues',
                'recommendation': 'Fix immediately - sensitive data may be exposed'
            })
        
        if high > 0:
            recommendations.append({
                'severity': 'HIGH',
                'issue': f'{high} high-priority configuration issues',
                'recommendation': 'Review and harden configuration settings'
            })
        
        # Plugin recommendations
        if len(self.results['plugins']) > 20:
            recommendations.append({
                'severity': 'MEDIUM',
                'issue': f'Large number of plugins installed ({len(self.results["plugins"])})',
                'recommendation': 'Review plugins and disable unused ones'
            })
        
        self.results['recommendations'] = recommendations
    
    def _print_summary(self):
        """
        Print a concise console summary of the configuration scan results.
        
        Outputs the discovered site version, number of detected plugins, and total vulnerabilities.
        If any vulnerabilities are present and one or more have severity "critical", also prints a highlighted critical-issues line.
        """
        print(f"\n{Fore.GREEN}[+] Configuration scan complete!{Style.RESET_ALL}")
        
        print(f"    Site version: {self.results['site_settings'].get('version', 'Unknown')}")
        print(f"    Plugins found: {len(self.results['plugins'])}")
        print(f"    Vulnerabilities: {len(self.results['vulnerabilities'])}")
        
        if self.results['vulnerabilities']:
            critical = len([v for v in self.results['vulnerabilities'] if v['severity'] == 'critical'])
            if critical > 0:
                print(f"    {Fore.RED}⚠ Critical issues: {critical}{Style.RESET_ALL}")