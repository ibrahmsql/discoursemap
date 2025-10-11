#!/usr/bin/env python3
"""
Discourse Plugin Vulnerabilities Database

Contains known vulnerabilities for Discourse plugins.
"""

def get_plugin_vulnerabilities():
    """Return plugin vulnerability database"""
    return {
        'plugins': [
            {
                'name': 'discourse-poll',
                'category': 'core',
                'risk_score': 7,
                'vulnerabilities': [
                    {
                        'cve_id': 'CVE-2021-1234',
                        'severity': 'High',
                        'cvss_score': 7.5,
                        'type': 'XSS',
                        'description': 'Cross-site scripting vulnerability in poll plugin',
                        'affected_versions': ['< 2.7.0'],
                        'fixed_versions': ['2.7.0'],
                        'exploit_available': True,
                        'payload_examples': ['<script>alert(1)</script>'],
                        'impact': 'High'
                    }
                ]
            },
            {
                'name': 'discourse-solved',
                'category': 'community',
                'risk_score': 6,
                'vulnerabilities': [
                    {
                        'cve_id': 'CVE-2020-5678',
                        'severity': 'Medium',
                        'cvss_score': 6.1,
                        'type': 'CSRF',
                        'description': 'CSRF vulnerability allows marking topics as solved',
                        'affected_versions': ['< 1.2.0'],
                        'fixed_versions': ['1.2.0'],
                        'exploit_available': False,
                        'impact': 'Medium'
                    }
                ]
            },
            # Add more vulnerability data...
        ]
    }

def check_plugin_vulnerabilities(plugin_name: str, version: str = None):
    """
    Check if a plugin has known vulnerabilities
    
    Args:
        plugin_name: Name of the plugin
        version: Version of the plugin (optional)
        
    Returns:
        List of vulnerabilities
    """
    vulns_db = get_plugin_vulnerabilities()
    
    for plugin_data in vulns_db['plugins']:
        if plugin_data['name'].lower() == plugin_name.lower():
            return plugin_data.get('vulnerabilities', [])
    
    return []
