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
        """
        Initialize the Reporter and create an internal ReportGenerator instance.
        
        Creates and assigns a new ReportGenerator to self.generator for producing reports in various formats.
        """
        self.generator = ReportGenerator()
    
    def generate_report(self, results, format='text'):
        """
        Produce a report representation for the given scan results.
        
        Parameters:
            results (dict): Scan results data; commonly includes keys like 'target' and 'vulnerabilities'.
            format (str): Output format. Use 'json' for JSON output, 'text' for a human-readable summary. Defaults to 'text'; any other value returns the string representation of `results`.
        
        Returns:
            report (str): Report content in the requested format or the fallback string form of `results`.
        """
        if format == 'json':
            return self.generator.generate_json(results)
        elif format == 'text':
            return self.generator.generate_summary(results)
        else:
            return str(results)
    
    def print_summary(self, results):
        """
        Display a formatted, colored scan summary to standard output.
        
        When `results` contains a 'target' key its value is shown (defaults to 'Unknown').
        If `results` contains a 'vulnerabilities' key, the total count is shown and up to
        the first five vulnerability entries will have their `type` values listed (each
        defaults to 'Unknown' if missing).
        
        Parameters:
            results (dict): Scan results mapping. Expected optional keys:
                - 'target' (str): Identifier of the scan target.
                - 'vulnerabilities' (list[dict]): List of vulnerability records where each
                  record may include a 'type' key.
        """
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