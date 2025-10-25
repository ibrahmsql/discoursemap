#!/usr/bin/env python3
"""
Discourse Security Scanner - Plugin Security Module

Tests security issues in Discourse plugins and themes
"""

from .plugin_discovery import PluginDiscovery
from .plugin_security_tests import PluginSecurityTests


class PluginModule:
    """Plugin security testing module for Discourse forums"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Plugin Security Testing',
            'target': scanner.target_url,
            'plugins_found': [],
            'themes_found': [],
            'plugin_vulnerabilities': [],
            'theme_vulnerabilities': [],
            'outdated_plugins': [],
            'dangerous_permissions': [],
            'plugin_file_access': [],
            'theme_injection': []
        }
        
        # Initialize sub-modules
        self.discovery = PluginDiscovery(scanner)
        self.security_tests = PluginSecurityTests(scanner)
        
    def run(self):
        """Run plugin security testing module"""
        self.scanner.log("Starting plugin security scan...", 'info')
        
        # Phase 1: Discovery
        self.results['plugins_found'] = self.discovery.discover_plugins()
        self.results['themes_found'] = self.discovery.discover_themes()
        
        # Phase 2: Security Testing
        self.results['plugin_vulnerabilities'] = self.security_tests.test_plugin_vulnerabilities(
            self.results['plugins_found']
        )
        self.results['theme_vulnerabilities'] = self.security_tests.test_theme_vulnerabilities(
            self.results['themes_found']
        )
        
        # Phase 3: Additional Checks
        self.results['outdated_plugins'] = self.security_tests.check_outdated_plugins(
            self.results['plugins_found']
        )
        
        # Generate summary
        self._generate_summary()
        
        return self.results
    
    def _generate_summary(self):
        """Generate scan summary"""
        total_plugins = len(self.results['plugins_found'])
        total_themes = len(self.results['themes_found'])
        total_vulns = len(self.results['plugin_vulnerabilities']) + len(self.results['theme_vulnerabilities'])
        
        self.scanner.log(f"Plugin scan complete: {total_plugins} plugins, {total_themes} themes, {total_vulns} vulnerabilities found", 'success')