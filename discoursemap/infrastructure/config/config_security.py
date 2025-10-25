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
        Initializes the ConfigSecurityTester with a scanner and prepares an empty list to collect discovered vulnerabilities.
        
        Parameters:
            scanner: An object providing `target_url` and `make_request(url, timeout)` used to perform HTTP requests against the target for security checks.
        """
        self.scanner = scanner
        self.vulnerabilities = []
    
    def test_all_security(self):
        """
        Execute all configuration security checks and return collected findings.
        
        This runs the module's configured tests for exposed configuration files, insecure default settings,
        enabled debug indicators, and potential sensitive information exposure, accumulating any discovered
        vulnerabilities.
        
        Returns:
            list: A list of vulnerability dictionaries, each describing a discovered issue (type, severity,
            identifier, and description).
        """
        self.test_exposed_configs()
        self.test_default_settings()
        self.test_debug_mode()
        self.test_sensitive_info()
        
        return self.vulnerabilities
    
    def test_exposed_configs(self):
        """
        Check common configuration file paths on the scanner target and record any exposed files.
        
        For each known config path, performs an HTTP request to the combined target URL and, when a successful (HTTP 200) response is returned, appends a vulnerability entry to self.vulnerabilities with keys: 'type' set to 'Exposed Configuration', 'severity' set to 'critical', 'path' set to the checked path, and a descriptive 'description'.
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
        Check the site's /site.json for insecure default settings and record findings.
        
        Fetches the site's /site.json and, if available, detects:
        - an unchanged default site title (e.g., "discourse", "my discourse", "new site"), recording a "Default Configuration" low-severity finding for the "title" setting;
        - a permissive `allow_anonymous_posting` set to true, recording a "Permissive Configuration" medium-severity finding for that setting.
        
        Findings are appended as dicts to `self.vulnerabilities` (keys include `type`, `severity`, `setting`, and `description`). Exceptions raised while fetching or parsing the response are ignored.
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
        Detect whether the target application exposes debug information and record a corresponding vulnerability.
        
        If a debug indicator is found in the HTTP response body or headers, append a vulnerability dictionary to self.vulnerabilities with keys 'type' (set to "Debug Mode Enabled"), 'severity' (set to "high"), 'indicator' (the matched indicator), and 'description'. The method stops after the first match. Exceptions raised while making the request are suppressed.
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
        Scan the scanner's target response for exposed sensitive configuration values and record findings.
        
        Checks the response body for common sensitive patterns (`password`, `api_key`, `secret_key`, `access_token`, `private_key`) and, when a pattern appears together with `value=`, appends a high-severity vulnerability entry to `self.vulnerabilities` describing the pattern. Exceptions raised during the check are ignored.
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