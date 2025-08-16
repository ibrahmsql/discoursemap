#!/usr/bin/env python3
"""
Discourse Security Scanner - Suspicious File Scanner

Specialized scanner for detecting suspicious files that shouldn't exist 
in a Discourse forum installation. Identifies potential security threats,
backdoors, and malicious files specific to Discourse platform vulnerabilities.

Author: ibrahimsql
"""

import re
from urllib.parse import urljoin
from .malicious_pattern_checker import MaliciousPatternChecker

class SuspiciousFileScanner:
    """Discourse-specific suspicious file scanner
    
    Detects suspicious files that shouldn't exist in a Discourse forum
    installation, including potential backdoors, malware, and security
    threats specific to Ruby-based Discourse platform.
    """
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.pattern_checker = MaliciousPatternChecker()
        
        # Suspicious file patterns that shouldn't exist in Discourse (Ruby-based)
        self.suspicious_patterns = [
            r'.*\.php$',  # PHP files (Discourse is Ruby-based, PHP indicates compromise)
            r'.*\.asp$',  # ASP files (not used in Discourse)
            r'.*\.jsp$',  # JSP files (not used in Discourse)
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
        
        # Common suspicious file names to check
        self.suspicious_files = [
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
            'index.php',
            'admin/config.php',
            'wp-config.php',
            'configuration.php',
            'settings.php',
            'connect.php',
            'db.php',
            'mysql.php',
            'sql.php',
            'install.php',
            'setup.php',
            'eval.php',
            'base64.php',
            'decode.php',
            'obfuscated.php'
        ]
    
    def scan_suspicious_files(self):
        """Scan for suspicious files that shouldn't exist in Discourse"""
        self.scanner.log("Scanning for suspicious files in Discourse installation...", 'debug')
        
        suspicious_files_found = []
        
        for suspicious_file in self.suspicious_files:
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
                malicious_patterns = self.pattern_checker.check_malicious_patterns(content)
                if malicious_patterns['has_malicious']:
                    file_info['malicious_patterns'] = malicious_patterns
                    file_info['risk_level'] = 'Critical'
                
                suspicious_files_found.append(file_info)
                self.scanner.log(f"Suspicious file found: {suspicious_file}", 'warning')
        
        return suspicious_files_found
    
    def check_suspicious_patterns(self, file_path):
        """Check if a file path matches suspicious patterns"""
        for pattern in self.suspicious_patterns:
            if re.match(pattern, file_path, re.IGNORECASE):
                return True
        return False
    
    def analyze_file_content(self, content, file_path):
        """Analyze file content for suspicious patterns"""
        analysis = {
            'is_suspicious': False,
            'risk_level': 'Low',
            'issues': []
        }
        
        # Check for malicious patterns
        malicious_check = self.pattern_checker.check_malicious_patterns(content)
        if malicious_check['has_malicious']:
            analysis['is_suspicious'] = True
            analysis['risk_level'] = 'Critical'
            analysis['issues'].append('Contains malicious code patterns')
            analysis['malicious_patterns'] = malicious_check
        
        # Check for suspicious plugin content
        plugin_check = self.pattern_checker.check_suspicious_plugin_content(content)
        if plugin_check['is_suspicious']:
            analysis['is_suspicious'] = True
            analysis['risk_level'] = 'Medium' if analysis['risk_level'] == 'Low' else analysis['risk_level']
            analysis['issues'].append('Contains suspicious plugin patterns')
            analysis['suspicious_patterns'] = plugin_check
        
        # Check for suspicious JavaScript
        if self.pattern_checker.has_suspicious_js_content(content):
            analysis['is_suspicious'] = True
            analysis['risk_level'] = 'Medium' if analysis['risk_level'] == 'Low' else analysis['risk_level']
            analysis['issues'].append('Contains suspicious JavaScript code')
        
        # Check file extension against Discourse platform (Ruby-based)
        if file_path.endswith('.php') and 'discourse' in content.lower():
            analysis['is_suspicious'] = True
            analysis['risk_level'] = 'High'
            analysis['issues'].append('PHP file detected in Ruby-based Discourse installation - potential security compromise')
        
        return analysis
    
    def get_risk_assessment(self, suspicious_files):
        """Get overall risk assessment based on found suspicious files"""
        if not suspicious_files:
            return {
                'risk_level': 'Low',
                'description': 'No suspicious files detected',
                'recommendations': ['Continue regular monitoring']
            }
        
        critical_files = [f for f in suspicious_files if f.get('risk_level') == 'Critical']
        high_risk_files = [f for f in suspicious_files if f.get('risk_level') == 'High']
        
        if critical_files:
            return {
                'risk_level': 'Critical',
                'description': f'Found {len(critical_files)} critical suspicious files',
                'recommendations': [
                    'Immediately investigate and remove suspicious files',
                    'Check server logs for unauthorized access',
                    'Scan for additional malware',
                    'Change all passwords and API keys',
                    'Consider restoring from clean backup'
                ]
            }
        elif high_risk_files:
            return {
                'risk_level': 'High',
                'description': f'Found {len(high_risk_files)} high-risk suspicious files',
                'recommendations': [
                    'Investigate and remove suspicious files',
                    'Review server access logs',
                    'Update Discourse and all plugins',
                    'Strengthen access controls'
                ]
            }
        else:
            return {
                'risk_level': 'Medium',
                'description': f'Found {len(suspicious_files)} potentially suspicious files',
                'recommendations': [
                    'Review found files for legitimacy',
                    'Remove unnecessary files',
                    'Monitor for additional suspicious activity'
                ]
            }
    
    def discover_discourse_backup_files(self):
        """Discover Discourse backup files"""
        discourse_backup_files = [
            # Database backups
            '/backups',
            '/backups/default',
            '/admin/backups',
            '/admin/backups.json',
            '/admin/backups/logs',
            '/admin/backups/status',
            '/admin/backups/rollback',
            '/admin/backups/upload',
            '/admin/backups/download',
            
            # Configuration files
            '/config/database.yml',
            '/config/discourse.conf',
            '/config/app.yml',
            '/config/web.template.yml',
            '/config/redis.yml',
            '/config/sidekiq.yml',
            '/config/puma.rb',
            '/config/nginx.conf',
            '/config/unicorn.rb',
            
            # Environment and secrets
            '/.env',
            '/.env.production',
            '/.env.local',
            '/config/secrets.yml',
            '/config/master.key',
            '/config/credentials.yml.enc',
            
            # Log files
            '/log/production.log',
            '/log/unicorn.stderr.log',
            '/log/unicorn.stdout.log',
            '/log/sidekiq.log',
            '/log/redis.log',
            '/log/nginx.access.log',
            '/log/nginx.error.log',
            
            # SSL certificates
            '/ssl',
            '/certs',
            '/config/ssl',
            '/shared/ssl',
            
            # Upload directories
            '/uploads',
            '/public/uploads',
            '/shared/uploads',
            
            # Docker files
            '/Dockerfile',
            '/docker-compose.yml',
            '/.dockerignore',
            '/containers',
            
            # Git repositories
            '/.git',
            '/.gitignore',
            '/.git/config'
        ]
        
        return discourse_backup_files
    
    def discover_discourse_config_files(self):
        """Discover Discourse configuration files"""
        discourse_config_files = [
            # Core Discourse configuration
            '/config/discourse.conf',
            '/config/app.yml',
            '/config/web.template.yml',
            '/config/data.template.yml',
            '/config/mail-receiver.template.yml',
            '/config/redis.template.yml',
            '/config/postgres.template.yml',
            
            # Rails configuration
            '/config/application.rb',
            '/config/environment.rb',
            '/config/routes.rb',
            '/config/database.yml',
            '/config/redis.yml',
            '/config/cable.yml',
            '/config/storage.yml',
            '/config/environments/production.rb',
            '/config/environments/development.rb',
            '/config/environments/test.rb',
            
            # Environment files
            '/.env',
            '/.env.production',
            '/.env.development',
            '/.env.local',
            '/.env.example',
            
            # Docker launcher paths
            '/launcher',
            '/shared/standalone/launcher',
            '/var/discourse/launcher',
            
            # Nginx configuration
            '/etc/nginx/conf.d/discourse.conf',
            '/etc/nginx/sites-available/discourse',
            '/etc/nginx/sites-enabled/discourse',
            
            # Systemd services
            '/etc/systemd/system/discourse.service',
            '/lib/systemd/system/discourse.service',
            
            # Plugin configurations
            '/plugins/*/config',
            '/plugins/*/plugin.rb',
            '/plugins/*/settings.yml'
        ]
        
        return discourse_config_files