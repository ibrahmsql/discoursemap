#!/usr/bin/env python3
"""
Discourse Security Scanner - Plugin Vulnerability Database Handler

Handles loading and querying the plugin vulnerability database
"""

import yaml
import os
from typing import Dict, List, Optional, Any

class PluginVulnDB:
    """Plugin vulnerability database handler"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Default path relative to this module
            current_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(os.path.dirname(current_dir), 'data', 'plugin_vulnerabilities.yaml')
        
        self.db_path = db_path
        self.db_data = self._load_database()
    
    def _load_database(self) -> Dict[str, Any]:
        """Load vulnerability database from YAML file"""
        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Warning: Plugin vulnerability database not found at {self.db_path}")
            return {'plugins': {}, 'patterns': {}, 'detection_signatures': {}, 'risk_scoring': {}}
        except yaml.YAMLError as e:
            print(f"Error loading vulnerability database: {e}")
            return {'plugins': {}, 'patterns': {}, 'detection_signatures': {}, 'risk_scoring': {}}
    
    def get_plugin_vulnerabilities(self, plugin_name: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities for a specific plugin"""
        plugins = self.db_data.get('plugins', {})
        plugin_data = plugins.get(plugin_name, {})
        return plugin_data.get('vulnerabilities', [])
    
    def get_all_plugins(self) -> List[str]:
        """Get list of all plugins in database"""
        return list(self.db_data.get('plugins', {}).keys())
    
    def get_plugin_info(self, plugin_name: str) -> Dict[str, Any]:
        """Get plugin information"""
        plugins = self.db_data.get('plugins', {})
        return plugins.get(plugin_name, {})
    
    def get_vulnerability_patterns(self, vuln_type: str) -> List[str]:
        """Get vulnerability test patterns by type"""
        patterns = self.db_data.get('patterns', {})
        
        pattern_map = {
            'xss': 'xss_vectors',
            'sqli': 'sqli_vectors', 
            'sql_injection': 'sqli_vectors',
            'lfi': 'lfi_vectors',
            'path_traversal': 'lfi_vectors',
            'rce': 'rce_vectors',
            'xxe': 'xxe_vectors'
        }
        
        pattern_key = pattern_map.get(vuln_type.lower(), f"{vuln_type.lower()}_vectors")
        return patterns.get(pattern_key, [])
    
    def get_detection_signatures(self) -> Dict[str, List[str]]:
        """Get plugin detection signatures"""
        return self.db_data.get('detection_signatures', {})
    
    def get_risk_score(self, severity: str, vuln_type: str) -> int:
        """Calculate risk score for vulnerability"""
        risk_scoring = self.db_data.get('risk_scoring', {})
        
        severity_weights = risk_scoring.get('severity_weights', {
            'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1
        })
        
        vuln_types = risk_scoring.get('vulnerability_types', {})
        
        severity_score = severity_weights.get(severity, 1)
        type_score = vuln_types.get(vuln_type, 5)
        
        return min(severity_score + type_score, 20)  # Cap at 20
    
    def search_vulnerabilities(self, 
                             severity: str = None, 
                             vuln_type: str = None,
                             plugin_name: str = None) -> List[Dict[str, Any]]:
        """Search vulnerabilities by criteria"""
        results = []
        plugins = self.db_data.get('plugins', {})
        
        for plugin, plugin_data in plugins.items():
            if plugin_name and plugin_name.lower() not in plugin.lower():
                continue
                
            vulnerabilities = plugin_data.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                # Filter by severity
                if severity and vuln.get('severity', '').lower() != severity.lower():
                    continue
                
                # Filter by vulnerability type
                if vuln_type and vuln.get('type', '').lower() != vuln_type.lower():
                    continue
                
                # Add plugin name to result
                vuln_result = vuln.copy()
                vuln_result['plugin_name'] = plugin
                vuln_result['plugin_description'] = plugin_data.get('description', '')
                results.append(vuln_result)
        
        return results
    
    def get_critical_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get all critical vulnerabilities"""
        return self.search_vulnerabilities(severity='Critical')
    
    def get_high_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get all high severity vulnerabilities"""
        return self.search_vulnerabilities(severity='High')
    
    def is_plugin_vulnerable(self, plugin_name: str, version: str = None) -> bool:
        """Check if plugin version is vulnerable"""
        vulnerabilities = self.get_plugin_vulnerabilities(plugin_name)
        
        if not vulnerabilities:
            return False
        
        if not version:
            return True  # If no version specified, assume vulnerable if any vulns exist
        
        for vuln in vulnerabilities:
            affected_versions = vuln.get('affected_versions', [])
            if version in affected_versions:
                return True
        
        return False
    
    def get_exploit_payloads(self, plugin_name: str, vuln_type: str = None) -> List[Dict[str, Any]]:
        """Get exploit payloads for plugin"""
        vulnerabilities = self.get_plugin_vulnerabilities(plugin_name)
        payloads = []
        
        for vuln in vulnerabilities:
            if vuln_type and vuln.get('type', '').lower() != vuln_type.lower():
                continue
            
            if 'payload' in vuln and 'endpoint' in vuln:
                payloads.append({
                    'type': vuln.get('type'),
                    'payload': vuln.get('payload'),
                    'endpoint': vuln.get('endpoint'),
                    'severity': vuln.get('severity'),
                    'description': vuln.get('description'),
                    'cve': vuln.get('cve')
                })
        
        return payloads
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        plugins = self.db_data.get('plugins', {})
        
        total_plugins = len(plugins)
        total_vulns = 0
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        type_counts = {}
        
        for plugin_data in plugins.values():
            vulnerabilities = plugin_data.get('vulnerabilities', [])
            total_vulns += len(vulnerabilities)
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Unknown')
                vuln_type = vuln.get('type', 'Unknown')
                
                if severity in severity_counts:
                    severity_counts[severity] += 1
                
                type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        return {
            'total_plugins': total_plugins,
            'total_vulnerabilities': total_vulns,
            'severity_distribution': severity_counts,
            'type_distribution': type_counts,
            'average_vulns_per_plugin': round(total_vulns / max(total_plugins, 1), 2)
        }
    
    def export_plugin_report(self, plugin_name: str) -> Dict[str, Any]:
        """Export detailed report for a plugin"""
        plugin_info = self.get_plugin_info(plugin_name)
        vulnerabilities = self.get_plugin_vulnerabilities(plugin_name)
        
        if not plugin_info:
            return {'error': f'Plugin {plugin_name} not found in database'}
        
        # Calculate risk metrics
        total_risk = 0
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            vuln_type = vuln.get('type', 'Unknown')
            
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            total_risk += self.get_risk_score(severity, vuln_type)
        
        # Determine overall risk level
        if total_risk >= 50:
            risk_level = 'Critical'
        elif total_risk >= 30:
            risk_level = 'High'
        elif total_risk >= 15:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        return {
            'plugin_name': plugin_name,
            'description': plugin_info.get('description', ''),
            'total_vulnerabilities': len(vulnerabilities),
            'severity_distribution': severity_counts,
            'total_risk_score': total_risk,
            'overall_risk_level': risk_level,
            'vulnerabilities': vulnerabilities,
            'recommendations': self._get_recommendations(vulnerabilities)
        }
    
    def _get_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on vulnerabilities"""
        recommendations = []
        
        # Check for critical/high severity vulns
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'Critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'High']
        
        if critical_vulns:
            recommendations.append("🚨 URGENT: Update or disable plugin immediately due to critical vulnerabilities")
        
        if high_vulns:
            recommendations.append("⚠️ HIGH PRIORITY: Update plugin to latest version to fix high-severity issues")
        
        # Check for specific vulnerability types
        vuln_types = [v.get('type') for v in vulnerabilities]
        
        if 'SQL Injection' in vuln_types:
            recommendations.append("🛡️ Implement input validation and parameterized queries")
        
        if 'XSS' in vuln_types:
            recommendations.append("🛡️ Implement proper output encoding and Content Security Policy")
        
        if 'Authentication Bypass' in vuln_types:
            recommendations.append("🛡️ Review and strengthen authentication mechanisms")
        
        if 'SSRF' in vuln_types:
            recommendations.append("🛡️ Implement URL validation and network segmentation")
        
        # General recommendations
        if vulnerabilities:
            recommendations.extend([
                "📋 Monitor plugin for security updates regularly",
                "🔍 Conduct regular security assessments",
                "📝 Review plugin permissions and access controls"
            ])
        
        return recommendations
    
    def update_database(self, new_data: Dict[str, Any]):
        """Update database with new vulnerability data"""
        # Merge new data with existing
        if 'plugins' in new_data:
            self.db_data.setdefault('plugins', {}).update(new_data['plugins'])
        
        if 'patterns' in new_data:
            self.db_data.setdefault('patterns', {}).update(new_data['patterns'])
        
        # Save updated database
        try:
            with open(self.db_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.db_data, f, default_flow_style=False, allow_unicode=True)
            return True
        except Exception as e:
            print(f"Error updating database: {e}")
            return False

# Convenience functions
def load_vuln_db(db_path: str = None) -> PluginVulnDB:
    """Load plugin vulnerability database"""
    return PluginVulnDB(db_path)

def get_plugin_vulns(plugin_name: str, db_path: str = None) -> List[Dict[str, Any]]:
    """Quick function to get plugin vulnerabilities"""
    db = PluginVulnDB(db_path)
    return db.get_plugin_vulnerabilities(plugin_name)

def is_vulnerable(plugin_name: str, version: str = None, db_path: str = None) -> bool:
    """Quick function to check if plugin is vulnerable"""
    db = PluginVulnDB(db_path)
    return db.is_plugin_vulnerable(plugin_name, version)