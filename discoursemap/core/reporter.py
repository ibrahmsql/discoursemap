#!/usr/bin/env python3
"""
Discourse Reporter Module (Refactored)

Report generation - split from 726 lines.
"""

from colorama import Fore, Style
from .report_generator import ReportGenerator


class Reporter:
    """Report generation (Refactored)"""
    
    def __init__(self, target_url=None):
        """
        Initialize the Reporter and create a ReportGenerator instance.
        
        Args:
            target_url: Optional target URL for the report
        
        Creates and assigns a ReportGenerator to the `generator` attribute on the instance.
        """
        self.target_url = target_url
        self.generator = ReportGenerator()
        self.scan_start_time = None
        self.scan_end_time = None
        self.module_results = {}
    
    def generate_report(self, results, format='text'):
        """
        Produce a report from scan results in the requested format.
        
        Parameters:
            results: Scan result data (typically a mapping) to be rendered into a report.
            format (str): Desired output format — 'json' to produce a JSON report, 'text' to produce a human-readable summary, any other value to return the string representation of `results`.
        
        Returns:
            str: The report as a string in the requested format.
        """
        if format == 'json':
            return self.generator.generate_json(results)
        elif format == 'text':
            return self.generator.generate_summary(results)
        else:
            return str(results)
    
    def add_module_results(self, module_name, results):
        """Add results from a module"""
        self.module_results[module_name] = results
    
    def finalize_scan(self):
        """Finalize the scan (placeholder for future functionality)"""
        pass
    
    def print_summary(self, results):
        """
        Prints a colored, framed scan summary including target and up to five vulnerability types.
        
        Prints a header, the target (from results['target'] or 'Unknown'), the total number of vulnerabilities if present, and the first five vulnerability entries' `type` values (defaulting to 'Unknown').
        
        Parameters:
            results (dict): Scan result mapping. Recognized keys:
                - 'target' (str): scan target.
                - 'vulnerabilities' (list[dict]): list of vulnerability objects; each may include a 'type' key.
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
    
    def generate_json_report(self, results, output_file):
        """Generate JSON report and save to file"""
        import json
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
    
    def generate_html_report(self, results, output_file):
        """Generate HTML report and save to file"""
        html_content = self.generator.generate_html(results)
        with open(output_file, 'w') as f:
            f.write(html_content)
    
    def generate_csv_report(self, results, output_file):
        """Generate CSV report and save to file"""
        csv_content = self.generator.generate_csv(results)
        with open(output_file, 'w') as f:
            f.write(csv_content)