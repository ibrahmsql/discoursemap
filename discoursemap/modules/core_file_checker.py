#!/usr/bin/env python3
"""
Discourse Security Scanner - Core File Checker

Checks Discourse core files for integrity and modifications
"""

import hashlib
import time
from urllib.parse import urljoin

class CoreFileChecker:
    """Checks Discourse core files for integrity"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        
        # Known Discourse core file patterns and their expected characteristics
        self.core_file_patterns = {
            '/assets/application.js': {
                'type': 'javascript',
                'expected_size_range': (100000, 2000000),
                'expected_patterns': ['Discourse', 'Ember', 'application']
            },
            '/assets/application.css': {
                'type': 'stylesheet',
                'expected_size_range': (50000, 500000),
                'expected_patterns': ['.topic-list', '.discourse', 'body']
            },
            '/assets/vendor.js': {
                'type': 'javascript',
                'expected_size_range': (200000, 3000000),
                'expected_patterns': ['jQuery', 'Ember', 'vendor']
            },
            '/manifest.json': {
                'type': 'json',
                'expected_size_range': (100, 5000),
                'expected_patterns': ['name', 'short_name', 'start_url']
            },
            '/favicon.ico': {
                'type': 'icon',
                'expected_size_range': (1000, 50000),
                'expected_patterns': []
            }
        }
    
    def check_core_files(self):
        """Check Discourse core files for integrity"""
        self.scanner.log("Checking core files...", 'debug')
        
        core_files = []
        missing_files = []
        modified_files = []
        
        for file_path, expected in self.core_file_patterns.items():
            url = urljoin(self.scanner.target_url, file_path)
            response = self.scanner.make_request(url)
            
            file_info = {
                'path': file_path,
                'url': url,
                'type': expected['type'],
                'status': 'unknown'
            }
            
            if response and response.status_code == 200:
                content = response.text if expected['type'] in ['javascript', 'stylesheet', 'json'] else response.content
                file_size = len(content)
                
                file_info.update({
                    'status': 'found',
                    'size': file_size,
                    'content_type': response.headers.get('content-type', 'unknown'),
                    'last_modified': response.headers.get('last-modified', 'unknown')
                })
                
                # Check size range
                min_size, max_size = expected['expected_size_range']
                if min_size <= file_size <= max_size:
                    file_info['size_check'] = 'pass'
                else:
                    file_info['size_check'] = 'fail'
                    file_info['size_warning'] = f"Size {file_size} outside expected range {min_size}-{max_size}"
                
                # Check for expected patterns
                pattern_checks = []
                if expected['expected_patterns'] and expected['type'] in ['javascript', 'stylesheet', 'json']:
                    for pattern in expected['expected_patterns']:
                        if pattern.lower() in content.lower():
                            pattern_checks.append({'pattern': pattern, 'found': True})
                        else:
                            pattern_checks.append({'pattern': pattern, 'found': False})
                
                file_info['pattern_checks'] = pattern_checks
                
                # Calculate file hash
                if isinstance(content, str):
                    content = content.encode('utf-8')
                file_hash = hashlib.sha256(content).hexdigest()
                file_info['sha256'] = file_hash
                
                # Check for modifications
                issues = self._check_file_modifications(file_info)
                if issues:
                    modification_info = {
                        'file': file_path,
                        'issues': issues,
                        'risk_level': 'Medium',
                        'description': 'Core file may have been modified'
                    }
                    modified_files.append(modification_info)
                
            elif response and response.status_code == 404:
                file_info['status'] = 'missing'
                missing_files.append(file_info)
            else:
                file_info['status'] = 'error'
                if response:
                    file_info['status_code'] = response.status_code
            
            core_files.append(file_info)
        
        return {
            'core_files': core_files,
            'missing_files': missing_files,
            'modified_files': modified_files
        }
    
    def _check_file_modifications(self, file_info):
        """Check if a core file has been modified"""
        issues = []
        
        # Check size anomalies
        if file_info.get('size_check') == 'fail':
            issues.append('Unexpected file size')
        
        # Check pattern failures
        pattern_checks = file_info.get('pattern_checks', [])
        failed_patterns = [p['pattern'] for p in pattern_checks if not p['found']]
        if failed_patterns:
            issues.append(f"Missing expected patterns: {', '.join(failed_patterns)}")
        
        return issues
    
    def calculate_core_integrity_score(self, core_files, missing_files, modified_files):
        """Calculate integrity score for core files"""
        total_files = len(self.core_file_patterns)
        found_files = len([f for f in core_files if f['status'] == 'found'])
        
        # Base score from found files
        base_score = (found_files / total_files) * 100 if total_files > 0 else 0
        
        # Deduct points for issues
        score = base_score
        score -= len(missing_files) * 10
        score -= len(modified_files) * 15
        
        return max(0, min(100, score))