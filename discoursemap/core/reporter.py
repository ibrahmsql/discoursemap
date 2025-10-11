#!/usr/bin/env python3
"""
Discourse Reporter Module (Refactored)

Report generation - split from 726 lines.
"""

from colorama import Fore, Style
from .report_generator import ReportGenerator


class Reporter:
    """Report generation (Refactored)"""
    
    def __init__(self):
        self.generator = ReportGenerator()
    
    def generate_report(self, results, format='text'):
        """Generate scan report"""
        if format == 'json':
            return self.generator.generate_json(results)
        elif format == 'text':
            return self.generator.generate_summary(results)
        else:
            return str(results)
    
    def print_summary(self, results):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"SCAN SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        print(f"Target: {results.get('target', 'Unknown')}")
        
        if 'vulnerabilities' in results:
            vuln_count = len(results['vulnerabilities'])
            print(f"Vulnerabilities: {vuln_count}")
            
            if vuln_count > 0:
                print(f"\n{Fore.RED}Found vulnerabilities:{Style.RESET_ALL}")
                for vuln in results['vulnerabilities'][:5]:
                    print(f"  - {vuln.get('type', 'Unknown')}")
