#!/usr/bin/env python3
"""
Data Processing Module

Data processing and analysis utilities for scan results.
"""

import json
import csv
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import hashlib
import base64


class DataProcessor:
    """Data processing and transformation utilities"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def normalize_scan_results(self, raw_results: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize scan results to a standard format"""
        
        normalized = {
            'metadata': {
                'processed_at': datetime.now().isoformat(),
                'total_modules': len(raw_results),
                'processor_version': '1.0'
            },
            'summary': self._generate_summary(raw_results),
            'modules': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        for module_name, module_data in raw_results.items():
            if isinstance(module_data, dict):
                normalized_module = self._normalize_module_data(module_name, module_data)
                normalized['modules'][module_name] = normalized_module
                
                # Extract vulnerabilities
                if 'vulnerabilities' in module_data:
                    for vuln in module_data['vulnerabilities']:
                        vuln['source_module'] = module_name
                        normalized['vulnerabilities'].append(vuln)
                
                # Extract recommendations
                if 'recommendations' in module_data:
                    for rec in module_data['recommendations']:
                        rec['source_module'] = module_name
                        normalized['recommendations'].append(rec)
        
        return normalized
    
    def _generate_summary(self, raw_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary statistics"""
        
        total_vulnerabilities = 0
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for module_data in raw_results.values():
            if isinstance(module_data, dict) and 'vulnerabilities' in module_data:
                vulns = module_data['vulnerabilities']
                if isinstance(vulns, list):
                    total_vulnerabilities += len(vulns)
                    
                    for vuln in vulns:
                        severity = vuln.get('severity', 'LOW').upper()
                        if severity in severity_counts:
                            severity_counts[severity] += 1
        
        return {
            'total_vulnerabilities': total_vulnerabilities,
            'severity_breakdown': severity_counts,
            'modules_with_findings': len([m for m in raw_results.values() 
                                        if isinstance(m, dict) and m.get('vulnerabilities')])
        }
    
    def _normalize_module_data(self, module_name: str, module_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize individual module data"""
        
        normalized = {
            'module_name': module_name,
            'execution_status': 'completed',
            'findings_count': 0,
            'data': {}
        }
        
        # Count findings
        if 'vulnerabilities' in module_data:
            normalized['findings_count'] = len(module_data['vulnerabilities'])
        
        # Copy relevant data
        for key, value in module_data.items():
            if key not in ['vulnerabilities', 'recommendations']:
                normalized['data'][key] = value
        
        return normalized
    
    def export_to_csv(self, data: Dict[str, Any], filename: str) -> bool:
        """Export vulnerabilities to CSV format"""
        
        try:
            vulnerabilities = data.get('vulnerabilities', [])
            
            if not vulnerabilities:
                if self.verbose:
                    print("No vulnerabilities to export")
                return False
            
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'module', 'type', 'severity', 'description', 
                    'endpoint', 'payload', 'status_code'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for vuln in vulnerabilities:
                    row = {
                        'module': vuln.get('source_module', ''),
                        'type': vuln.get('type', ''),
                        'severity': vuln.get('severity', ''),
                        'description': vuln.get('description', ''),
                        'endpoint': vuln.get('endpoint', ''),
                        'payload': vuln.get('payload', ''),
                        'status_code': vuln.get('status_code', '')
                    }
                    writer.writerow(row)
            
            if self.verbose:
                print(f"CSV export completed: {filename}")
            
            return True
            
        except Exception as e:
            if self.verbose:
                print(f"CSV export failed: {e}")
            return False
    
    def export_to_xml(self, data: Dict[str, Any], filename: str) -> bool:
        """Export data to XML format"""
        
        try:
            root = ET.Element('DiscourseMapReport')
            
            # Add metadata
            metadata = ET.SubElement(root, 'Metadata')
            for key, value in data.get('metadata', {}).items():
                elem = ET.SubElement(metadata, key.replace('_', ''))
                elem.text = str(value)
            
            # Add summary
            summary = ET.SubElement(root, 'Summary')
            for key, value in data.get('summary', {}).items():
                elem = ET.SubElement(summary, key.replace('_', ''))
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        sub_elem = ET.SubElement(elem, sub_key.replace('_', ''))
                        sub_elem.text = str(sub_value)
                else:
                    elem.text = str(value)
            
            # Add vulnerabilities
            vulnerabilities = ET.SubElement(root, 'Vulnerabilities')
            for vuln in data.get('vulnerabilities', []):
                vuln_elem = ET.SubElement(vulnerabilities, 'Vulnerability')
                for key, value in vuln.items():
                    elem = ET.SubElement(vuln_elem, key.replace('_', ''))
                    elem.text = str(value)
            
            # Write to file
            tree = ET.ElementTree(root)
            tree.write(filename, encoding='utf-8', xml_declaration=True)
            
            if self.verbose:
                print(f"XML export completed: {filename}")
            
            return True
            
        except Exception as e:
            if self.verbose:
                print(f"XML export failed: {e}")
            return False
    
    def filter_by_severity(self, data: Dict[str, Any], 
                          severities: List[str]) -> Dict[str, Any]:
        """Filter vulnerabilities by severity levels"""
        
        filtered_data = data.copy()
        
        if 'vulnerabilities' in filtered_data:
            filtered_vulns = [
                vuln for vuln in filtered_data['vulnerabilities']
                if vuln.get('severity', '').upper() in [s.upper() for s in severities]
            ]
            filtered_data['vulnerabilities'] = filtered_vulns
        
        return filtered_data
    
    def group_by_module(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group vulnerabilities by source module"""
        
        grouped = {}
        
        for vuln in vulnerabilities:
            module = vuln.get('source_module', 'unknown')
            if module not in grouped:
                grouped[module] = []
            grouped[module].append(vuln)
        
        return grouped
    
    def calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall risk score based on vulnerabilities"""
        
        severity_weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 1
        }
        
        total_score = 0
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW').upper()
            if severity in severity_weights:
                total_score += severity_weights[severity]
                severity_counts[severity] += 1
        
        # Normalize score (0-100)
        max_possible_score = len(vulnerabilities) * 10  # All critical
        normalized_score = (total_score / max_possible_score * 100) if max_possible_score > 0 else 0
        
        # Determine risk level
        if normalized_score >= 80:
            risk_level = 'CRITICAL'
        elif normalized_score >= 60:
            risk_level = 'HIGH'
        elif normalized_score >= 40:
            risk_level = 'MEDIUM'
        elif normalized_score >= 20:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'total_score': total_score,
            'normalized_score': normalized_score,
            'risk_level': risk_level,
            'severity_counts': severity_counts,
            'total_vulnerabilities': len(vulnerabilities)
        }
    
    def generate_hash(self, data: Union[str, Dict, List]) -> str:
        """Generate hash for data integrity"""
        
        if isinstance(data, (dict, list)):
            data_str = json.dumps(data, sort_keys=True)
        else:
            data_str = str(data)
        
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def encode_data(self, data: Union[str, bytes], encoding: str = 'base64') -> str:
        """Encode data using specified encoding"""
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if encoding.lower() == 'base64':
            return base64.b64encode(data).decode('ascii')
        elif encoding.lower() == 'hex':
            return data.hex()
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
    
    def decode_data(self, encoded_data: str, encoding: str = 'base64') -> bytes:
        """Decode data using specified encoding"""
        
        if encoding.lower() == 'base64':
            return base64.b64decode(encoded_data)
        elif encoding.lower() == 'hex':
            return bytes.fromhex(encoded_data)
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")