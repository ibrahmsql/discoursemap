#!/usr/bin/env python3
"""
Discourse Security Scanner - Backup File Scanner Module

Scans for Discourse backup files, configuration files, and sensitive data exposure
"""

import re
import time
import json
import os
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from .utils import make_request

class BackupScannerModule:
    """Backup file and configuration scanner for Discourse forums"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Backup File Scanner',
            'target': scanner.target_url,
            'backup_files': [],
            'config_files': [],
            'log_files': [],
            'sensitive_files': [],
            'database_dumps': [],
            'temp_files': [],
            'scan_time': 0
        }
        self.start_time = time.time()
        
        # Discourse-specific backup and config file patterns
        self.backup_patterns = [
            '/admin/backups/',
            '/backups/',
            'discourse-backup-*.tar.gz',
            'backup-*.tar.gz',
            'site-backup-*.tar.gz',
            'forum-backup-*.tar.gz',
            'discourse.sql',
            'discourse_production.sql',
            'database.sql',
            'db_backup.sql',
            'pg_dump.sql',
            'postgres_backup.sql',
            'backup.zip',
            'discourse.zip',
            'site.zip',
            'forum.zip'
        ]
        
        self.config_patterns = [
            'app.yml',
            'discourse.conf',
            'database.yml',
            'redis.yml',
            'secrets.yml',
            '.env',
            '.env.production',
            '.env.local',
            'environment.rb',
            'app.yml.backup',
            'database.yml.backup',
            'config.backup',
            'settings.backup',
            'docker-compose.yml',
            'Dockerfile',
            'containers/app.yml'
        ]
        
        self.log_patterns = [
            'log/production.log',
            'log/unicorn.stderr.log',
            'log/unicorn.stdout.log',
            'log/rails.log',
            'log/sidekiq.log',
            'logs/error.log',
            'logs/access.log',
            'logs/discourse.log',
            'var/log/discourse.log',
            'debug.log',
            'error.log',
            'application.log'
        ]
        
        self.sensitive_patterns = [
            'config/secrets.yml',
            'config/database.yml',
            'config/redis.yml',
            'ssl/discourse.crt',
            'ssl/discourse.key',
            'certs/fullchain.pem',
            'certs/privkey.pem',
            '.ssh/id_rsa',
            '.ssh/id_rsa.pub',
            'ssh_keys/discourse',
            '.git/config',
            '.gitignore',
            '.git/HEAD'
        ]
    
    def run(self):
        """Run backup file scanner module"""
        self.scanner.log("Starting backup file scanner...")
        
        # Scan for backup files
        self._scan_backup_files()
        
        # Scan for configuration files
        self._scan_config_files()
        
        # Scan for log files
        self._scan_log_files()
        
        # Scan for sensitive files
        self._scan_sensitive_files()
        
        # Check admin backup interface
        self._check_admin_backups()
        
        # Scan for temporary files
        self._scan_temp_files()
        
        # Directory traversal attempts
        self._attempt_directory_traversal()
        
        self.results['scan_time'] = time.time() - self.start_time
        return self.results
    
    def _scan_backup_files(self):
        """Scan for Discourse backup files"""
        self.scanner.log("Scanning for backup files...", 'debug')
        
        for pattern in self.backup_patterns:
            url = urljoin(self.scanner.target_url, pattern)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                if self._is_backup_file(response, pattern):
                    self.results['backup_files'].append({
                        'file': pattern,
                        'url': url,
                        'size': len(response.content),
                        'content_type': response.headers.get('content-type', 'unknown'),
                        'risk_level': 'Critical',
                        'description': 'Discourse backup file accessible'
                    })
                    self.scanner.log(f"Found backup file: {pattern}", 'warning')
    
    def _scan_config_files(self):
        """Scan for configuration files"""
        self.scanner.log("Scanning for configuration files...", 'debug')
        
        for pattern in self.config_patterns:
            url = urljoin(self.scanner.target_url, pattern)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                if self._is_config_file(response, pattern):
                    sensitive_data = self._extract_sensitive_config_data(response.text)
                    
                    self.results['config_files'].append({
                        'file': pattern,
                        'url': url,
                        'size': len(response.content),
                        'risk_level': 'High',
                        'sensitive_data': sensitive_data,
                        'description': 'Configuration file exposed'
                    })
                    self.scanner.log(f"Found config file: {pattern}", 'warning')
    
    def _scan_log_files(self):
        """Scan for log files"""
        self.scanner.log("Scanning for log files...", 'debug')
        
        for pattern in self.log_patterns:
            url = urljoin(self.scanner.target_url, pattern)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                if self._is_log_file(response, pattern):
                    log_analysis = self._analyze_log_content(response.text)
                    
                    self.results['log_files'].append({
                        'file': pattern,
                        'url': url,
                        'size': len(response.content),
                        'risk_level': 'Medium',
                        'analysis': log_analysis,
                        'description': 'Log file accessible'
                    })
                    self.scanner.log(f"Found log file: {pattern}", 'info')
    
    def _scan_sensitive_files(self):
        """Scan for sensitive files"""
        self.scanner.log("Scanning for sensitive files...", 'debug')
        
        for pattern in self.sensitive_patterns:
            url = urljoin(self.scanner.target_url, pattern)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                self.results['sensitive_files'].append({
                    'file': pattern,
                    'url': url,
                    'size': len(response.content),
                    'risk_level': 'Critical',
                    'description': 'Sensitive file exposed'
                })
                self.scanner.log(f"Found sensitive file: {pattern}", 'error')
    
    def _check_admin_backups(self):
        """Check admin backup interface"""
        self.scanner.log("Checking admin backup interface...", 'debug')
        
        admin_backup_urls = [
            '/admin/backups',
            '/admin/backups.json',
            '/admin/api/backups',
            '/admin/backups/logs'
        ]
        
        for url_path in admin_backup_urls:
            url = urljoin(self.scanner.target_url, url_path)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                if 'backup' in response.text.lower() or 'download' in response.text.lower():
                    self.results['backup_files'].append({
                        'file': 'admin_backup_interface',
                        'url': url,
                        'risk_level': 'High',
                        'description': 'Admin backup interface accessible without authentication'
                    })
                    self.scanner.log(f"Admin backup interface accessible: {url_path}", 'warning')
    
    def _scan_temp_files(self):
        """Scan for temporary files"""
        temp_patterns = [
            'tmp/',
            'temp/',
            'cache/',
            '.tmp',
            '.temp',
            '.bak',
            '.old',
            '.orig',
            '~'
        ]
        
        for pattern in temp_patterns:
            url = urljoin(self.scanner.target_url, pattern)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                self.results['temp_files'].append({
                    'file': pattern,
                    'url': url,
                    'risk_level': 'Low',
                    'description': 'Temporary file accessible'
                })
    
    def _attempt_directory_traversal(self):
        """Attempt directory traversal to find backup files"""
        traversal_payloads = [
            '../',
            '../../',
            '../../../',
            '..\\',
            '..\\..\\',
            '%2e%2e%2f',
            '%2e%2e%5c'
        ]
        
        target_files = ['app.yml', 'database.yml', 'discourse.conf']
        
        for payload in traversal_payloads:
            for target in target_files:
                url = urljoin(self.scanner.target_url, f"{payload}{target}")
                response = self.scanner.make_request(url)
                
                if response and response.status_code == 200:
                    if self._is_config_file(response, target):
                        self.results['config_files'].append({
                            'file': f"{payload}{target}",
                            'url': url,
                            'risk_level': 'Critical',
                            'description': 'Configuration file accessible via directory traversal'
                        })
    
    def _is_backup_file(self, response, filename):
        """Check if response contains a backup file"""
        content_type = response.headers.get('content-type', '').lower()
        
        backup_content_types = [
            'application/gzip',
            'application/x-gzip',
            'application/tar',
            'application/x-tar',
            'application/zip',
            'application/octet-stream'
        ]
        
        if any(ct in content_type for ct in backup_content_types):
            return True
        
        backup_extensions = ['.tar.gz', '.zip', '.sql', '.bak']
        if any(filename.endswith(ext) for ext in backup_extensions):
            return True
        
        return False
    
    def _is_config_file(self, response, filename):
        """Check if response contains a configuration file"""
        content = response.text.lower()
        
        config_indicators = [
            'database:',
            'redis:',
            'hostname:',
            'db_name:',
            'db_username:',
            'db_password:',
            'secret_key_base:',
            'discourse_hostname:'
        ]
        
        return any(indicator in content for indicator in config_indicators)
    
    def _is_log_file(self, response, filename):
        """Check if response contains a log file"""
        content = response.text.lower()
        
        log_indicators = [
            'error:',
            'warning:',
            'info:',
            'debug:',
            'fatal:',
            'exception:',
            'traceback:',
            'started',
            'completed'
        ]
        
        return any(indicator in content for indicator in log_indicators)
    
    def _extract_sensitive_config_data(self, content):
        """Extract sensitive data from configuration files"""
        sensitive_data = []
        
        # Simple pattern matching for common config values
        patterns = {
            'db_password': r'db_password[:\s]*["\']?([^\s"\'\n]+)',
            'db_username': r'db_username[:\s]*["\']?([^\s"\'\n]+)',
            'secret_key': r'secret_key_base[:\s]*["\']?([^\s"\'\n]+)',
            'api_key': r'api_key[:\s]*["\']?([^\s"\'\n]+)'
        }
        
        for key, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) > 5:
                    sensitive_data.append({
                        'type': key,
                        'value': match[:20] + '...' if len(match) > 20 else match
                    })
        
        return sensitive_data
    
    def _analyze_log_content(self, content):
        """Analyze log file content for sensitive information"""
        analysis = {
            'errors': 0,
            'warnings': 0,
            'sensitive_info': []
        }
        
        lines = content.split('\n')[:100]
        
        for line in lines:
            if 'error' in line.lower():
                analysis['errors'] += 1
            if 'warning' in line.lower():
                analysis['warnings'] += 1
            
            if any(term in line.lower() for term in ['password', 'token', 'key', 'secret']):
                analysis['sensitive_info'].append(line[:100])
        
        return analysis