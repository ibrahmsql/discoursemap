#!/usr/bin/env python3
"""
Discourse Security Scanner - File Integrity Module

Checks file integrity and detects modifications in Discourse installations
"""

import os
from .core_file_checker import CoreFileChecker
from .suspicious_file_scanner import SuspiciousFileScanner
from .plugin_file_checker import PluginFileChecker
from .theme_file_checker import ThemeFileChecker
from .asset_file_checker import AssetFileChecker

class FileIntegrityModule:
    """Checks file integrity and detects modifications"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        
        # Initialize specialized checkers
        self.core_checker = CoreFileChecker(scanner)
        self.suspicious_scanner = SuspiciousFileScanner(scanner)
        self.plugin_checker = PluginFileChecker(scanner)
        self.theme_checker = ThemeFileChecker(scanner)
        self.asset_checker = AssetFileChecker(scanner)
    
    def run(self):
        """Run file integrity checks"""
        self.scanner.log("Starting file integrity checks...", 'info')
        
        results = {
            'core_files': self.core_checker.check_core_files(),
            'suspicious_files': self.suspicious_scanner.scan_suspicious_files(),
            'plugin_files': self.plugin_checker.check_plugin_files(),
            'theme_files': self.theme_checker.check_theme_files(),
            'asset_files': self.asset_checker.check_asset_files(),
            'modifications': self.core_checker.analyze_modifications()
        }
        
        # Calculate overall integrity score
        results['integrity_score'] = self._calculate_integrity_score(results)
        
        self.scanner.log(f"File integrity check completed. Score: {results['integrity_score']}/100", 'info')
        
        return results
    

    
    def _calculate_integrity_score(self, results):
        """Calculate overall integrity score"""
        total_score = 100
        
        # Deduct points for core file issues
        for file_info in results.get('core_files', []):
            if isinstance(file_info, dict):
                if file_info.get('status') == 'missing':
                    total_score -= 15
                else:
                    for issue in file_info.get('issues', []):
                        if issue.get('severity') == 'Critical':
                            total_score -= 20
                        elif issue.get('severity') == 'High':
                            total_score -= 10
                        elif issue.get('severity') == 'Medium':
                            total_score -= 5
        
        # Deduct points for suspicious files
        suspicious_files = results.get('suspicious_files', [])
        if isinstance(suspicious_files, list):
            total_score -= len(suspicious_files) * 25
        
        # Deduct points for modifications
        modifications = results.get('modifications', [])
        if isinstance(modifications, list):
            total_score -= len(modifications) * 15
        
        # Deduct points for plugin/theme/asset issues
        for file_category in ['plugin_files', 'theme_files', 'asset_files']:
            file_list = results.get(file_category, [])
            if isinstance(file_list, list):
                for file_info in file_list:
                    if isinstance(file_info, dict):
                        for issue in file_info.get('issues', []):
                            if issue.get('severity') == 'Critical':
                                total_score -= 10
                            elif issue.get('severity') == 'High':
                                total_score -= 5
                            elif issue.get('severity') == 'Medium':
                                total_score -= 2
        
        return max(0, total_score)