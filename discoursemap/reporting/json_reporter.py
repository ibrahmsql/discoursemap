#!/usr/bin/env python3
"""
JSON Reporter Module

Generates JSON format reports from scan results.
"""

import json
from typing import Dict, List, Optional, Any
from datetime import datetime


class JSONReporter:
    """Generates JSON format reports"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def generate_report(self, scan_results: Dict[str, Any], 
                       target_url: str, 
                       scan_type: str = "comprehensive") -> Dict[str, Any]:
        """Generate a comprehensive JSON report"""
        
        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'target_url': target_url,
                'scan_type': scan_type,
                'report_format': 'json',
                'report_version': '1.0'
            },
            'executive_summary': self._generate_executive_summary(scan_results),
            'detailed_findings': scan_results,
            'recommendations': self._extract_recommendations(scan_results),
            'statistics': self._generate_statistics(scan_results)
        }
        
        return report
    
    def _generate_executive_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary from scan results"""
        
        total_vulnerabilities = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        # Count vulnerabilities by severity
        for module_name, module_results in scan_results.items():
            if isinstance(module_results, dict):
                vulnerabilities = module_results.get('vulnerabilities', [])
                if isinstance(vulnerabilities, list):
                    total_vulnerabilities += len(vulnerabilities)
                    
                    for vuln in vulnerabilities:
                        severity = vuln.get('severity', '').upper()
                        if severity == 'CRITICAL':
                            critical_count += 1
                        elif severity == 'HIGH':
                            high_count += 1
                        elif severity == 'MEDIUM':
                            medium_count += 1
                        elif severity == 'LOW':
                            low_count += 1
        
        # Determine overall risk level
        if critical_count > 0:
            risk_level = 'CRITICAL'
        elif high_count > 0:
            risk_level = 'HIGH'
        elif medium_count > 0:
            risk_level = 'MEDIUM'
        elif low_count > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'overall_risk_level': risk_level,
            'total_vulnerabilities': total_vulnerabilities,
            'vulnerability_breakdown': {
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'low': low_count
            },
            'modules_scanned': len(scan_results),
            'scan_completion_status': 'completed'
        }
    
    def _extract_recommendations(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract all recommendations from scan results"""
        
        all_recommendations = []
        
        for module_name, module_results in scan_results.items():
            if isinstance(module_results, dict):
                recommendations = module_results.get('recommendations', [])
                
                if isinstance(recommendations, list):
                    for rec in recommendations:
                        if isinstance(rec, dict):
                            rec['source_module'] = module_name
                            all_recommendations.append(rec)
        
        # Sort by severity (Critical -> High -> Medium -> Low)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        
        all_recommendations.sort(
            key=lambda x: severity_order.get(x.get('severity', 'LOW').upper(), 4)
        )
        
        return all_recommendations
    
    def _generate_statistics(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate statistics from scan results"""
        
        stats = {
            'modules_executed': 0,
            'total_tests_performed': 0,
            'endpoints_tested': 0,
            'successful_tests': 0,
            'failed_tests': 0
        }
        
        for module_name, module_results in scan_results.items():
            if isinstance(module_results, dict):
                stats['modules_executed'] += 1
                
                # Count tests
                if 'tests_performed' in module_results:
                    stats['total_tests_performed'] += module_results['tests_performed']
                
                # Count endpoints
                if 'endpoints_tested' in module_results:
                    if isinstance(module_results['endpoints_tested'], list):
                        stats['endpoints_tested'] += len(module_results['endpoints_tested'])
                    elif isinstance(module_results['endpoints_tested'], int):
                        stats['endpoints_tested'] += module_results['endpoints_tested']
                
                # Count successes/failures
                if 'successful_tests' in module_results:
                    stats['successful_tests'] += module_results['successful_tests']
                
                if 'failed_tests' in module_results:
                    stats['failed_tests'] += module_results['failed_tests']
        
        return stats
    
    def save_report(self, report: Dict[str, Any], filename: str) -> bool:
        """Save report to JSON file"""
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            if self.verbose:
                print(f"Report saved to {filename}")
            
            return True
            
        except Exception as e:
            if self.verbose:
                print(f"Error saving report: {e}")
            return False
    
    def format_for_api(self, report: Dict[str, Any]) -> str:
        """Format report for API consumption"""
        
        # Create a compact version for API
        api_report = {
            'timestamp': report['report_metadata']['generated_at'],
            'target': report['report_metadata']['target_url'],
            'summary': report['executive_summary'],
            'recommendations': report['recommendations'][:10],  # Top 10 recommendations
            'statistics': report['statistics']
        }
        
        return json.dumps(api_report, separators=(',', ':'))  # Compact JSON