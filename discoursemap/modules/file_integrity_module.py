#!/usr/bin/env python3
"""
Discourse Security Scanner - File Integrity Module

Checks file integrity and detects unauthorized modifications
"""

import re
import time
import json
import hashlib
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from .utils import make_request

class FileIntegrityModule:
    """File integrity checker for Discourse forums"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'File Integrity Checker',
            'target': scanner.target_url,
            'core_files': [],
            'plugin_files': [],
            'theme_files': [],
            'asset_files': [],
            'modified_files': [],
            'suspicious_files': [],
            'missing_files': [],
            'integrity_score': 0,
            'scan_time': 0
        }
        self.start_time = time.time()
        
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
        
        # Suspicious file patterns that shouldn't exist
        self.suspicious_patterns = [
            r'.*\.php$',  # PHP files (Discourse is Ruby)
            r'.*\.asp$',  # ASP files
            r'.*\.jsp$',  # JSP files
            r'.*shell.*',  # Shell scripts in web directory
            r'.*backdoor.*',  # Backdoor files
            r'.*malware.*',  # Malware files
            r'.*\.bak$',  # Backup files
            r'.*\.old$',  # Old files
            r'.*\.tmp$',  # Temporary files
            r'.*\.log$',  # Log files in web directory
            r'.*\.sql$',  # SQL files in web directory
            r'.*config.*\.txt$',  # Config files as text
            r'.*password.*\.txt$',  # Password files
            r'.*admin.*\.txt$'  # Admin files
        ]
        
        # Common plugin and theme paths
        self.plugin_paths = [
            '/plugins/',
            '/assets/plugins/',
            '/javascripts/plugins/'
        ]
        
        self.theme_paths = [
            '/themes/',
            '/assets/themes/',
            '/stylesheets/themes/'
        ]
    
    def run(self):
        """Run file integrity checker module"""
        self.scanner.log("Starting file integrity check...")
        
        # Check core files
        self._check_core_files()
        
        # Check for suspicious files
        self._scan_suspicious_files()
        
        # Check plugin files
        self._check_plugin_files()
        
        # Check theme files
        self._check_theme_files()
        
        # Check asset files
        self._check_asset_files()
        
        # Analyze file modifications
        self._analyze_modifications()
        
        # Calculate integrity score
        self._calculate_integrity_score()
        
        self.results['scan_time'] = time.time() - self.start_time
        return self.results
    
    def _check_core_files(self):
        """Check Discourse core files for integrity"""
        self.scanner.log("Checking core files...", 'debug')
        
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
                
            elif response and response.status_code == 404:
                file_info['status'] = 'missing'
                self.results['missing_files'].append(file_info)
            else:
                file_info['status'] = 'error'
                if response:
                    file_info['status_code'] = response.status_code
            
            self.results['core_files'].append(file_info)
    
    def _scan_suspicious_files(self):
        """Scan for suspicious files that shouldn't exist"""
        self.scanner.log("Scanning for suspicious files...", 'debug')
        
        # Common suspicious file names to check
        suspicious_files = [
            'shell.php',
            'backdoor.php',
            'c99.php',
            'r57.php',
            'webshell.php',
            'admin.php',
            'config.php',
            'database.php',
            'info.php',
            'phpinfo.php',
            'test.php',
            'upload.php',
            'file.php',
            'cmd.asp',
            'shell.asp',
            'admin.asp',
            'login.txt',
            'passwords.txt',
            'config.txt',
            'backup.sql',
            'dump.sql',
            'database.sql',
            '.htaccess.bak',
            'wp-config.php',  # WordPress files (shouldn't exist in Discourse)
            'index.php',
            'admin/config.php'
        ]
        
        for suspicious_file in suspicious_files:
            url = urljoin(self.scanner.target_url, suspicious_file)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                file_info = {
                    'file': suspicious_file,
                    'url': url,
                    'size': len(response.content),
                    'content_type': response.headers.get('content-type', 'unknown'),
                    'risk_level': 'High',
                    'description': 'Suspicious file found - potential security risk'
                }
                
                # Analyze content for malicious patterns
                content = response.text if response.headers.get('content-type', '').startswith('text') else ''
                malicious_patterns = self._check_malicious_patterns(content)
                if malicious_patterns:
                    file_info['malicious_patterns'] = malicious_patterns
                    file_info['risk_level'] = 'Critical'
                
                self.results['suspicious_files'].append(file_info)
                self.scanner.log(f"Suspicious file found: {suspicious_file}", 'warning')
    
    def _check_plugin_files(self):
        """Check plugin files for integrity"""
        self.scanner.log("Checking plugin files...", 'debug')
        
        for plugin_path in self.plugin_paths:
            url = urljoin(self.scanner.target_url, plugin_path)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                # Try to extract plugin file listings
                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.find_all('a', href=True)
                
                for link in links:
                    href = link['href']
                    if href.endswith('.js') or href.endswith('.css'):
                        plugin_url = urljoin(url, href)
                        plugin_response = self.scanner.make_request(plugin_url)
                        
                        if plugin_response and plugin_response.status_code == 200:
                            plugin_info = {
                                'path': href,
                                'url': plugin_url,
                                'size': len(plugin_response.content),
                                'content_type': plugin_response.headers.get('content-type', 'unknown')
                            }
                            
                            # Check for suspicious content in plugins
                            content = plugin_response.text
                            suspicious_patterns = self._check_suspicious_plugin_content(content)
                            if suspicious_patterns:
                                plugin_info['suspicious_patterns'] = suspicious_patterns
                                plugin_info['risk_level'] = 'Medium'
                            
                            self.results['plugin_files'].append(plugin_info)
    
    def _check_theme_files(self):
        """Check theme files for integrity"""
        self.scanner.log("Checking theme files...", 'debug')
        
        for theme_path in self.theme_paths:
            url = urljoin(self.scanner.target_url, theme_path)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                # Try to extract theme file listings
                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.find_all('a', href=True)
                
                for link in links:
                    href = link['href']
                    if href.endswith('.css') or href.endswith('.scss'):
                        theme_url = urljoin(url, href)
                        theme_response = self.scanner.make_request(theme_url)
                        
                        if theme_response and theme_response.status_code == 200:
                            theme_info = {
                                'path': href,
                                'url': theme_url,
                                'size': len(theme_response.content),
                                'content_type': theme_response.headers.get('content-type', 'unknown')
                            }
                            
                            self.results['theme_files'].append(theme_info)
    
    def _check_asset_files(self):
        """Check asset files for integrity"""
        self.scanner.log("Checking asset files...", 'debug')
        
        # Get main page to extract asset references
        response = self.scanner.make_request(self.scanner.target_url)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract JavaScript files
            scripts = soup.find_all('script', {'src': True})
            for script in scripts[:10]:  # Limit to first 10
                src = script['src']
                if src.startswith('/'):
                    asset_url = urljoin(self.scanner.target_url, src)
                    asset_response = self.scanner.make_request(asset_url)
                    
                    if asset_response and asset_response.status_code == 200:
                        asset_info = {
                            'path': src,
                            'url': asset_url,
                            'type': 'javascript',
                            'size': len(asset_response.content),
                            'content_type': asset_response.headers.get('content-type', 'unknown')
                        }
                        
                        # Check for suspicious content
                        content = asset_response.text
                        if self._has_suspicious_js_content(content):
                            asset_info['suspicious'] = True
                            asset_info['risk_level'] = 'Medium'
                        
                        self.results['asset_files'].append(asset_info)
            
            # Extract CSS files
            links = soup.find_all('link', {'rel': 'stylesheet', 'href': True})
            for link in links[:10]:  # Limit to first 10
                href = link['href']
                if href.startswith('/'):
                    asset_url = urljoin(self.scanner.target_url, href)
                    asset_response = self.scanner.make_request(asset_url)
                    
                    if asset_response and asset_response.status_code == 200:
                        asset_info = {
                            'path': href,
                            'url': asset_url,
                            'type': 'stylesheet',
                            'size': len(asset_response.content),
                            'content_type': asset_response.headers.get('content-type', 'unknown')
                        }
                        
                        self.results['asset_files'].append(asset_info)
    
    def _analyze_modifications(self):
        """Analyze files for potential modifications"""
        self.scanner.log("Analyzing file modifications...", 'debug')
        
        # Check core files for modifications
        for core_file in self.results['core_files']:
            if core_file['status'] == 'found':
                issues = []
                
                # Check size anomalies
                if core_file.get('size_check') == 'fail':
                    issues.append('Unexpected file size')
                
                # Check pattern failures
                pattern_checks = core_file.get('pattern_checks', [])
                failed_patterns = [p['pattern'] for p in pattern_checks if not p['found']]
                if failed_patterns:
                    issues.append(f"Missing expected patterns: {', '.join(failed_patterns)}")
                
                if issues:
                    modification_info = {
                        'file': core_file['path'],
                        'issues': issues,
                        'risk_level': 'Medium',
                        'description': 'Core file may have been modified'
                    }
                    self.results['modified_files'].append(modification_info)
    
    def _calculate_integrity_score(self):
        """Calculate overall integrity score"""
        total_score = 100
        
        # Deduct points for issues
        total_score -= len(self.results['suspicious_files']) * 20
        total_score -= len(self.results['modified_files']) * 10
        total_score -= len(self.results['missing_files']) * 5
        
        # Ensure score doesn't go below 0
        self.results['integrity_score'] = max(0, total_score)
        
        # Determine overall status
        if self.results['integrity_score'] >= 90:
            self.results['integrity_status'] = 'Good'
        elif self.results['integrity_score'] >= 70:
            self.results['integrity_status'] = 'Fair'
        elif self.results['integrity_score'] >= 50:
            self.results['integrity_status'] = 'Poor'
        else:
            self.results['integrity_status'] = 'Critical'
    
    def _check_malicious_patterns(self, content):
        """Check content for malicious patterns"""
        malicious_patterns = [
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'shell_exec\s*\(',
            r'passthru\s*\(',
            r'base64_decode\s*\(',
            r'gzinflate\s*\(',
            r'str_rot13\s*\(',
            r'\$_GET\s*\[',
            r'\$_POST\s*\[',
            r'\$_REQUEST\s*\[',
            r'file_get_contents\s*\(',
            r'fopen\s*\(',
            r'fwrite\s*\(',
            r'curl_exec\s*\(',
            r'wget\s+',
            r'nc\s+-',
            r'/bin/sh',
            r'/bin/bash'
        ]
        
        found_patterns = []
        for pattern in malicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns.append(pattern)
        
        return found_patterns
    
    def _check_suspicious_plugin_content(self, content):
        """Check plugin content for suspicious patterns"""
        suspicious_patterns = [
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'XMLHttpRequest\s*\(',
            r'fetch\s*\(',
            r'window\.location',
            r'document\.cookie',
            r'localStorage',
            r'sessionStorage'
        ]
        
        found_patterns = []
        for pattern in suspicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns.append(pattern)
        
        return found_patterns
    
    def _has_suspicious_js_content(self, content):
        """Check if JavaScript content has suspicious characteristics"""
        suspicious_indicators = [
            'eval(',
            'document.write(',
            'unescape(',
            'String.fromCharCode(',
            'atob(',
            'btoa(',
            'setTimeout(',
            'setInterval('
        ]
        
        # Count suspicious indicators
        count = sum(1 for indicator in suspicious_indicators if indicator in content)
        
        # If more than 3 suspicious indicators, flag as suspicious
        return count > 3