#!/usr/bin/env python3
"""Report Generation Helper"""

import json
from datetime import datetime


class ReportGenerator:
    """Generate various report formats"""
    
    def generate_json(self, results):
        """Generate JSON report"""
        return json.dumps(results, indent=2)
    
    def generate_summary(self, results):
        """Generate text summary"""
        summary = []
        summary.append(f"Scan completed: {datetime.now()}")
        summary.append(f"Target: {results.get('target', 'Unknown')}")
        
        if 'vulnerabilities' in results:
            vuln_count = len(results['vulnerabilities'])
            summary.append(f"Vulnerabilities found: {vuln_count}")
        
        return "\n".join(summary)
