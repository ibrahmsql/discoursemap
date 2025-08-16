#!/usr/bin/env python3
"""
Discourse Security Scanner - Theme File Checker

Checks Discourse theme files for integrity and security issues
"""

import re
from urllib.parse import urljoin
from .malicious_pattern_checker import MaliciousPatternChecker

class ThemeFileChecker:
    """Checks Discourse theme files for security and integrity issues"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.pattern_checker = MaliciousPatternChecker()
        
        # Common theme file paths to check
        self.theme_paths = [
            'stylesheets/',
            'javascripts/',
            'assets/stylesheets/',
            'assets/javascripts/',
            'themes/',
            'themes/default/',
            'themes/custom/'
        ]
        
        # Theme file extensions
        self.theme_extensions = ['.css', '.scss', '.sass', '.js', '.coffee', '.hbs', '.erb']
        
        # Suspicious theme patterns
        self.suspicious_theme_patterns = [
            r'eval\s*\(',
            r'Function\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'location\.href\s*=',
            r'window\.location',
            r'document\.cookie',
            r'localStorage',
            r'sessionStorage',
            r'XMLHttpRequest',
            r'fetch\s*\(',
            r'ajax\s*\(',
            r'\$\.get\s*\(',
            r'\$\.post\s*\(',
            r'\$\.ajax\s*\(',
            r'<script[^>]*>',
            r'javascript:',
            r'data:text/html',
            r'vbscript:',
            r'expression\s*\(',
            r'@import\s+["\']data:',
            r'url\s*\(\s*["\']?data:',
            r'background\s*:\s*url\s*\(\s*["\']?javascript:'
        ]
    
    def check_theme_files(self):
        """Check theme files for integrity and security issues"""
        self.scanner.log("Checking theme files...", 'debug')
        
        theme_issues = []
        
        # Check common theme paths
        for theme_path in self.theme_paths:
            url = urljoin(self.scanner.target_url, theme_path)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                # Try to extract theme file names from directory listing
                theme_files = self._extract_theme_files(response.text, theme_path)
                
                for theme_file in theme_files:
                    file_url = urljoin(url, theme_file)
                    file_response = self.scanner.make_request(file_url)
                    
                    if file_response and file_response.status_code == 200:
                        file_issues = self._check_theme_content(theme_file, file_response.text, file_url)
                        theme_issues.extend(file_issues)
        
        # Check specific common theme files
        common_theme_files = [
            'stylesheets/application.css',
            'stylesheets/desktop.css',
            'stylesheets/mobile.css',
            'javascripts/application.js',
            'javascripts/discourse.js',
            'assets/stylesheets/application.css',
            'assets/javascripts/application.js',
            'themes/default/desktop/desktop.scss',
            'themes/default/mobile/mobile.scss',
            'themes/default/common/common.scss'
        ]
        
        for theme_file in common_theme_files:
            url = urljoin(self.scanner.target_url, theme_file)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                file_issues = self._check_theme_content(theme_file, response.text, url)
                theme_issues.extend(file_issues)
        
        return theme_issues
    
    def _extract_theme_files(self, content, base_path):
        """Extract theme file names from directory listing or HTML content"""
        theme_files = []
        
        # Look for file links in directory listing
        patterns = [
            r'href=["\']([^"\']*/[^"\'/]*\.(css|scss|sass|js|coffee|hbs|erb))["\']',
            r'href=["\']([^"\']*(css|scss|sass|js|coffee|hbs|erb))["\']',
            r'([a-zA-Z0-9_-]+\.(css|scss|sass|js|coffee|hbs|erb))'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    theme_files.append(match[0])
                else:
                    theme_files.append(match)
        
        # Remove duplicates and clean up
        theme_files = list(set([f.strip('/') for f in theme_files if f and not f.startswith('http')]))
        
        return theme_files[:30]  # Limit to prevent excessive requests
    
    def _check_theme_content(self, theme_file, content, url):
        """Check theme content for security issues"""
        issues = []
        
        # Check for malicious patterns
        malicious_check = self.pattern_checker.check_malicious_patterns(content)
        if malicious_check['has_malicious']:
            issues.append({
                'type': 'malicious_code',
                'file': theme_file,
                'url': url,
                'severity': 'Critical',
                'description': 'Theme file contains malicious code patterns',
                'patterns': malicious_check['patterns']
            })
        
        # Check for suspicious JavaScript
        if self.pattern_checker.has_suspicious_js_content(content):
            issues.append({
                'type': 'suspicious_javascript',
                'file': theme_file,
                'url': url,
                'severity': 'High',
                'description': 'Theme file contains suspicious JavaScript code'
            })
        
        # Check for theme-specific suspicious patterns
        for pattern in self.suspicious_theme_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                issues.append({
                    'type': 'suspicious_pattern',
                    'file': theme_file,
                    'url': url,
                    'severity': 'Medium',
                    'description': f'Theme file contains suspicious pattern: {pattern}',
                    'pattern': pattern
                })
        
        # Check for external resource loading
        external_patterns = [
            r'@import\s+["\']https?://[^"\'\'\\n\\r]+["\']',
            r'url\s*\(\s*["\']?https?://[^"\')\\n\\r]+["\']?\)',
            r'src\s*=\s*["\']https?://[^"\'\'\\n\\r]+["\']',
            r'href\s*=\s*["\']https?://[^"\'\'\\n\\r]+["\']'
        ]
        
        for pattern in external_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                issues.append({
                    'type': 'external_resource',
                    'file': theme_file,
                    'url': url,
                    'severity': 'Low',
                    'description': f'Theme file loads external resource: {match}',
                    'resource': match
                })
        
        # Check for inline styles with suspicious content
        if theme_file.endswith(('.css', '.scss', '.sass')):
            suspicious_css_patterns = [
                r'expression\s*\(',
                r'javascript:',
                r'vbscript:',
                r'data:text/html',
                r'@import\s+["\']data:'
            ]
            
            for pattern in suspicious_css_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    issues.append({
                        'type': 'suspicious_css',
                        'file': theme_file,
                        'url': url,
                        'severity': 'High',
                        'description': f'CSS file contains suspicious pattern: {pattern}',
                        'pattern': pattern
                    })
        
        return issues
    
    def discover_discourse_theme_endpoints(self):
        """Discover Discourse theme endpoints"""
        # Discourse theme-related endpoints
        discourse_theme_endpoints = [
            # Theme management
            '/admin/customize',
            '/admin/customize/themes',
            '/admin/customize/themes.json',
            '/admin/customize/themes/import',
            '/admin/customize/themes/upload',
            '/admin/customize/colors',
            '/admin/customize/colors.json',
            '/admin/customize/css_html',
            '/admin/customize/email_templates',
            '/admin/customize/email_style',
            '/admin/customize/user_fields',
            '/admin/customize/site_texts',
            '/admin/customize/robots',
            '/admin/customize/embedding',
            '/admin/customize/permalinks',
            
            # Theme assets
            '/theme-javascripts',
            '/theme-stylesheets',
            '/stylesheets',
            '/stylesheets/desktop.css',
            '/stylesheets/mobile.css',
            '/stylesheets/desktop_theme.css',
            '/stylesheets/mobile_theme.css',
            '/extra-locales',
            
            # Theme uploads
            '/uploads/default',
            '/uploads/default/theme',
            '/uploads/default/theme_uploads',
            '/uploads/default/optimized',
            '/uploads/default/original',
            
            # Component themes
            '/admin/customize/components',
            '/admin/customize/components.json',
            
            # Theme settings
            '/admin/site_settings/category/theme',
            '/admin/site_settings/category/theming',
            
            # Custom CSS/JS
            '/admin/customize/css_html/show',
            '/admin/customize/css_html/edit',
            
            # Theme preview
            '/theme-preview',
            '/safe-mode',
            '/theme-qunit',
            
            # Brand assets
            '/admin/customize/watched_words',
            '/admin/customize/form_templates',
            '/admin/customize/themes/bulk_destroy'
        ]
        
        return discourse_theme_endpoints

    def get_theme_security_summary(self, all_issues):
        """Generate theme security summary"""
        return {
            'total_issues': len(all_issues),
            'critical_issues': len([i for i in all_issues if i.get('severity') == 'critical']),
            'high_issues': len([i for i in all_issues if i.get('severity') == 'high']),
            'medium_issues': len([i for i in all_issues if i.get('severity') == 'medium']),
            'low_issues': len([i for i in all_issues if i.get('severity') == 'low']),
            'categories': {
                'malicious_patterns': len([i for i in all_issues if i.get('category') == 'malicious_pattern']),
                'suspicious_code': len([i for i in all_issues if i.get('category') == 'suspicious_code']),
                'external_resources': len([i for i in all_issues if i.get('category') == 'external_resource']),
                'obfuscated_code': len([i for i in all_issues if i.get('category') == 'obfuscated_code']),
                'sensitive_data': len([i for i in all_issues if i.get('category') == 'sensitive_data'])
            },
            'recommendations': {
                'review_theme_files': len([i for i in all_issues if 'theme' in i.get('file', '')]),
                'check_external_resources': len([i for i in all_issues if i.get('category') == 'external_resource']),
                'validate_user_input': len([i for i in all_issues if 'input' in i.get('description', '').lower()]),
                'update_themes': len([i for i in all_issues if 'outdated' in i.get('description', '').lower()])
            },
            'security_score': max(0, 100 - (len(all_issues) * 5)),
            'risk_level': (
                'critical' if len([i for i in all_issues if i.get('severity') == 'critical']) > 0
                else 'high' if len([i for i in all_issues if i.get('severity') == 'high']) > 2
                else 'medium' if len([i for i in all_issues if i.get('severity') in ['high', 'medium']]) > 0
                else 'low'
            )
        }