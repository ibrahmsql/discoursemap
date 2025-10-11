#!/usr/bin/env python3
"""Report Generation Helper"""

import json
from datetime import datetime


class ReportGenerator:
    """Generate various report formats"""
    
    def generate_json(self, results):
        """
        Produce a JSON-formatted string representation of the provided results.
        
        Parameters:
        	results (any): A JSON-serializable object containing report data.
        
        Returns:
        	json_str (str): A pretty-printed JSON string of `results` using two-space indentation.
        """
        return json.dumps(results, indent=2)
    
    def generate_summary(self, results):
        """
        Builds a human-readable text summary of scan results.
        
        Parameters:
            results (dict): Scan results dictionary. May include 'target' (string; defaults to "Unknown" if absent)
                and 'vulnerabilities' (iterable of findings) to report a vulnerability count.
        
        Returns:
            summary (str): Multi-line string containing the scan completion timestamp, the target, and,
            if present, a line reporting the number of vulnerabilities found.
        """
        summary = []
        summary.append(f"Scan completed: {datetime.now()}")
        summary.append(f"Target: {results.get('target', 'Unknown')}")
        
        if 'vulnerabilities' in results:
            vuln_count = len(results['vulnerabilities'])
            summary.append(f"Vulnerabilities found: {vuln_count}")
        
        return "\n".join(summary)