#!/usr/bin/env python3
"""
Discourse Plugin Vulnerabilities Database

Contains known vulnerabilities for Discourse plugins.
"""

def get_plugin_vulnerabilities():
    """
    Provide a static database of known Discourse plugin vulnerabilities.
    
    Returns:
        dict: A dictionary with a single key `'plugins'` mapping to a list of plugin entries. Each plugin entry contains:
            - name (str): Plugin name.
            - category (str): Category label.
            - risk_score (int): Integer risk rating.
            - vulnerabilities (list): List of vulnerability records. Each vulnerability record contains:
                - cve_id (str)
                - severity (str)
                - cvss_score (float)
                - type (str)
                - description (str)
                - affected_versions (list[str])
                - fixed_versions (list[str])
                - exploit_available (bool)
                - payload_examples (list[str], optional)
                - impact (str)
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
    Retrieve known vulnerability records for a given plugin.
    
    Parameters:
        plugin_name (str): Name of the plugin to look up.
        version (str, optional): Version string (accepted but not used by this lookup).
    
    Returns:
        list: A list of vulnerability record dictionaries for the matched plugin (each record contains fields like `cve_id`, `severity`, `cvss_score`, `type`, `description`, `affected_versions`, `fixed_versions`, `exploit_available`, `payload_examples`, and `impact`). Returns an empty list if the plugin is not found or has no recorded vulnerabilities.
    """
    vulns_db = get_plugin_vulnerabilities()
    
    for plugin_data in vulns_db['plugins']:
        if plugin_data['name'].lower() == plugin_name.lower():
            return plugin_data.get('vulnerabilities', [])
    
    return []