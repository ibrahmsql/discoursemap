#!/usr/bin/env python3
"""Report Generation Helper"""

import json
from datetime import datetime


class ReportGenerator:
    """Generate various report formats"""
    
    def generate_json(self, results):
        """
        Produce a pretty-printed JSON representation of the provided results.
        
        Parameters:
            results: A JSON-serializable Python object containing the report data.
        
        Returns:
            json_report (str): JSON-formatted string of `results` using two-space indentation.
        """
        return json.dumps(results, indent=2)
    
    def generate_summary(self, results):
        """
        Builds a human-readable summary of scan results.
        
        Parameters:
            results (dict): Scan results. Recognized keys:
                - 'target' (str, optional): The scan target; reported as 'Unknown' if absent.
                - 'vulnerabilities' (list, optional): If present, its length is reported as the vulnerability count.
        
        Returns:
            str: Newline-separated summary including a timestamp ("Scan completed: ..."), the target line, and, when available, "Vulnerabilities found: N".
        """
        summary = []
        summary.append(f"Scan completed: {datetime.now()}")
        summary.append(f"Target: {results.get('target', 'Unknown')}")
        
        if 'vulnerabilities' in results:
            vuln_count = len(results['vulnerabilities'])
            summary.append(f"Vulnerabilities found: {vuln_count}")
        
        return "\n".join(summary)