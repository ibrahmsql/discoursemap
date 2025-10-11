#!/usr/bin/env python3
"""
Configuration Security Tests

Tests for configuration security issues.
"""

from urllib.parse import urljoin


class ConfigSecurityTester:
    """Configuration security testing"""
    
    def __init__(self, scanner):
        """
        Initialize the ConfigSecurityTester with a scanner and prepare internal vulnerability storage.
        
        Parameters:
            scanner (object): Scanner instance used to perform HTTP requests and provide the target URL for tests. The instance is retained for use by test methods.
        
        """
        self.scanner = scanner
        self.vulnerabilities = []
    
    def test_all_security(self):
        """
        Execute all configuration security checks and collect discovered vulnerabilities.
        
        Runs the exposed configs, default settings, debug mode, and sensitive information checks in sequence and aggregates any findings.
        
        Returns:
            list: Collected vulnerability entries; each entry is a dict describing a detected issue (type, severity, description, and related fields).
        """
        self.test_exposed_configs()
        self.test_default_settings()
        self.test_debug_mode()
        self.test_sensitive_info()
        
        return self.vulnerabilities
    
    def test_exposed_configs(self):
        """
        Check for publicly accessible configuration files on the scanner's target.
        
        For each common configuration path, requests the corresponding URL on the scanner's target and, when a 200 OK response is received, appends a vulnerability entry to self.vulnerabilities describing an 'Exposed Configuration' with severity 'critical', the tested path, and a descriptive message.
        """
        config_paths = [
            '/config/database.yml',
            '/config/secrets.yml',
            '/.env',
            '/config.json',
            '/settings.json'
        ]
        
        for path in config_paths:
            try:
                url = urljoin(self.scanner.target_url, path)
                response = self.scanner.make_request(url, timeout=5)
                
                if response and response.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'Exposed Configuration',
                        'severity': 'critical',
                        'path': path,
                        'description': f'Configuration file exposed: {path}'
                    })
            except Exception:
                continue
    
    def test_default_settings(self):
        """
        Validate site default configuration values and record insecure settings.
        
        Checks the site's configuration for two insecure conditions and appends a vulnerability entry to self.vulnerabilities for each finding:
        - Default site title: flags common unchanged titles (e.g., "discourse", "my discourse", "new site").
        - Anonymous posting enabled: flags when `allow_anonymous_posting` is true.
        
        Each appended vulnerability is a dict containing at least `type`, `severity`, `setting`, and `description`.
        """
        try:
            site_url = urljoin(self.scanner.target_url, '/site.json')
            response = self.scanner.make_request(site_url, timeout=10)
            
            if response and response.status_code == 200:
                data = response.json()
                
                # Check for default title
                title = data.get('title', '')
                if title.lower() in ['discourse', 'my discourse', 'new site']:
                    self.vulnerabilities.append({
                        'type': 'Default Configuration',
                        'severity': 'low',
                        'setting': 'title',
                        'description': 'Default site title not changed'
                    })
                
                # Check for guest access
                if data.get('allow_anonymous_posting', False):
                    self.vulnerabilities.append({
                        'type': 'Permissive Configuration',
                        'severity': 'medium',
                        'setting': 'allow_anonymous_posting',
                        'description': 'Anonymous posting is enabled'
                    })
        except Exception:
            pass
    
    def test_debug_mode(self):
        """
        Detect whether the target site is exposing debug information and record a high-severity vulnerability if found.
        
        When a debug indicator is observed in the response body or headers, appends a dict with keys 'type', 'severity', 'indicator', and 'description' to self.vulnerabilities.
        """
        try:
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if response:
                debug_indicators = [
                    'debug mode',
                    'stacktrace',
                    'x-debug',
                    'x-rack-debugger'
                ]
                
                content_lower = response.text.lower()
                headers_lower = {k.lower(): v for k, v in response.headers.items()}
                
                for indicator in debug_indicators:
                    if indicator in content_lower or indicator in headers_lower:
                        self.vulnerabilities.append({
                            'type': 'Debug Mode Enabled',
                            'severity': 'high',
                            'indicator': indicator,
                            'description': f'Debug mode detected: {indicator}'
                        })
                        break
        except Exception:
            pass
    
    def test_sensitive_info(self):
        """
        Scan the scanner's target page for exposed sensitive configuration values and record findings.
        
        Searches the HTTP response body for common sensitive patterns (e.g., "password", "api_key", "secret_key", "access_token", "private_key") and, when a pattern appears alongside a value indicator (e.g., "value="), appends a high-severity vulnerability entry to self.vulnerabilities describing the matched pattern.
        """
        try:
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if response:
                sensitive_patterns = [
                    'password',
                    'api_key',
                    'secret_key',
                    'access_token',
                    'private_key'
                ]
                
                content_lower = response.text.lower()
                
                for pattern in sensitive_patterns:
                    if pattern in content_lower:
                        # Check if it's not just in a form field
                        if f'value=' in content_lower and pattern in content_lower:
                            self.vulnerabilities.append({
                                'type': 'Sensitive Information Exposure',
                                'severity': 'high',
                                'pattern': pattern,
                                'description': f'Potential sensitive info exposure: {pattern}'
                            })
                            break
        except Exception:
            pass