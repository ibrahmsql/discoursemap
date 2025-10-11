#!/usr/bin/env python3
"""
Discourse Plugin Vulnerabilities Database

Contains known vulnerabilities for Discourse plugins.
"""

def get_plugin_vulnerabilities():
    """
    Provide an in-code catalog of known Discourse plugin vulnerabilities.
    
    The returned dictionary contains a top-level key 'plugins' mapping to a list of plugin records. Each plugin record contains:
    - name (str): plugin name.
    - category (str): plugin category.
    - risk_score (number): overall risk score for the plugin.
    - vulnerabilities (list): list of vulnerability records.
    
    Each vulnerability record contains:
    - cve_id (str)
    - severity (str)
    - cvss_score (number)
    - type (str)
    - description (str)
    - affected_versions (list of str)
    - fixed_versions (list of str)
    - exploit_available (bool)
    - impact (str)
    Optional fields:
    - payload_examples (list of str): example exploit payloads; may be omitted.
    
    Returns:
        plugin_db (dict): Dictionary with key 'plugins' containing the list of plugin vulnerability records.
    """
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
    Determine known vulnerabilities for a named Discourse plugin.
    
    Parameters:
        plugin_name (str): Plugin name to look up (case-insensitive).
        version (str, optional): Plugin version; currently ignored by lookup.
    
    Returns:
        list: List of vulnerability records for the matching plugin, or an empty list if no match is found.
    """
    vulns_db = get_plugin_vulnerabilities()
    
    for plugin_data in vulns_db['plugins']:
        if plugin_data['name'].lower() == plugin_name.lower():
            return plugin_data.get('vulnerabilities', [])
    
    return []