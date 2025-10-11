#!/usr/bin/env python3
"""
OWASP Top 10 2021 Security Tests

Comprehensive OWASP compliance testing module.
"""

import time
from urllib.parse import urljoin
from colorama import Fore, Style


class OWASPTests:
    """OWASP Top 10 2021 security testing"""
    
    def __init__(self, scanner):
        """
        Initialize an OWASPTests instance with a scanner and prepare an empty results list.
        
        Parameters:
            scanner: An object that provides a `target_url` attribute and a `make_request` method used to perform HTTP requests during the tests.
        """
        self.scanner = scanner
        self.results = []
    
    def run_all_tests(self):
        """
        Run the full OWASP Top 10:2021 test suite against the scanner's target.
        
        Returns:
            results (list): Accumulated list of finding dictionaries produced by each test.
        """
        self.test_broken_access_control()
        self.test_cryptographic_failures()
        self.test_injection_vulnerabilities()
        self.test_insecure_design()
        self.test_security_misconfiguration()
        self.test_vulnerable_components()
        self.test_authentication_failures()
        self.test_integrity_failures()
        self.test_logging_monitoring()
        self.test_ssrf_vulnerabilities()
        
        return self.results
    
    def test_broken_access_control(self):
        """
        Detects admin endpoints that are accessible without authentication, indicating broken access control.
        
        When an admin endpoint returns HTTP 200, records a high-severity finding in self.results describing the exposed endpoint.
        """
        try:
            admin_endpoints = ['/admin', '/admin/users', '/admin/settings']
            
            for endpoint in admin_endpoints:
                url = urljoin(self.scanner.target_url, endpoint)
                response = self.scanner.make_request(url, timeout=5)
                
                if response and response.status_code == 200:
                    self.results.append({
                        'type': 'A01:2021 - Broken Access Control',
                        'severity': 'high',
                        'endpoint': endpoint,
                        'description': f'Admin endpoint accessible without authentication: {endpoint}'
                    })
        except Exception:
            pass
    
    def test_cryptographic_failures(self):
        """
        Detect cryptographic failures (A02:2021) for the scanner target and record findings in self.results.
        
        Appends a critical finding if the target URL does not use HTTPS. Appends a high-severity finding if a response from the target is missing the Strict-Transport-Security header.
        """
        try:
            if not self.scanner.target_url.startswith('https://'):
                self.results.append({
                    'type': 'A02:2021 - Cryptographic Failures',
                    'severity': 'critical',
                    'description': 'Site not using HTTPS - data transmitted in clear text'
                })
            
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if response:
                if 'strict-transport-security' not in response.headers:
                    self.results.append({
                        'type': 'A02:2021 - Cryptographic Failures',
                        'severity': 'high',
                        'description': 'Missing HSTS header - vulnerable to SSL stripping attacks'
                    })
        except Exception:
            pass
    
    def test_injection_vulnerabilities(self):
        """
        Detects injection vulnerabilities against the application's search endpoint using a set of common payloads.
        
        Sends each payload to the '/search' endpoint and records findings in self.results when a payload causes a server error or is reflected back in the response. Appends entries with type 'A03:2021 - Injection' and includes 'severity' ('high' for server errors, 'medium' for reflected payloads), the triggering 'payload', and a short 'description'.
        """
        try:
            injection_payloads = [
                "' OR '1'='1",
                "<script>alert(1)</script>",
                "${7*7}",
                "../../../etc/passwd"
            ]
            
            search_url = urljoin(self.scanner.target_url, '/search')
            
            for payload in injection_payloads:
                response = self.scanner.make_request(
                    search_url, 
                    params={'q': payload},
                    timeout=5
                )
                
                if response:
                    if response.status_code == 500:
                        self.results.append({
                            'type': 'A03:2021 - Injection',
                            'severity': 'high',
                            'payload': payload,
                            'description': 'Injection payload causes server error'
                        })
                    elif payload in response.text:
                        self.results.append({
                            'type': 'A03:2021 - Injection',
                            'severity': 'medium',
                            'payload': payload,
                            'description': 'Injection payload reflected in response'
                        })
        except Exception:
            pass
    
    def test_insecure_design(self):
        """
        Detects exposed debugging information in the target's response body indicating insecure design.
        
        Searches the fetched page for common debugging indicators (for example: "debug", "stacktrace", "exception", "error details"). If any indicator is found, appends a medium-severity finding to self.results describing the exposed debugging information.
        """
        try:
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if response:
                debug_indicators = ['debug', 'stacktrace', 'exception', 'error details']
                content_lower = response.text.lower()
                
                for indicator in debug_indicators:
                    if indicator in content_lower:
                        self.results.append({
                            'type': 'A04:2021 - Insecure Design',
                            'severity': 'medium',
                            'indicator': indicator,
                            'description': f'Debugging information exposed: {indicator}'
                        })
                        break
        except Exception:
            pass
    
    def test_security_misconfiguration(self):
        """
        Detects common security misconfigurations revealed by HTTP response headers.
        
        Checks the target response for 'Server' and 'X-Powered-By' headers and, when found,
        appends low-severity findings to self.results describing the disclosed server version
        or technology stack.
        """
        try:
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if response:
                if 'server' in response.headers:
                    self.results.append({
                        'type': 'A05:2021 - Security Misconfiguration',
                        'severity': 'low',
                        'header': 'Server',
                        'value': response.headers['server'],
                        'description': 'Server version disclosed in headers'
                    })
                
                if 'x-powered-by' in response.headers:
                    self.results.append({
                        'type': 'A05:2021 - Security Misconfiguration',
                        'severity': 'low',
                        'header': 'X-Powered-By',
                        'value': response.headers['x-powered-by'],
                        'description': 'Technology stack disclosed in headers'
                    })
        except Exception:
            pass
    
    def test_vulnerable_components(self):
        """
        Detect publicly exposed application version information via /site.json.
        
        Sends a request to the target's /site.json and, if the response contains a JSON `version` field, appends an info-severity finding to `self.results` with the detected version and a suggestion to check for known CVEs.
        """
        try:
            site_url = urljoin(self.scanner.target_url, '/site.json')
            response = self.scanner.make_request(site_url, timeout=5)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    version = data.get('version', '')
                    
                    if version:
                        self.results.append({
                            'type': 'A06:2021 - Vulnerable Components',
                            'severity': 'info',
                            'version': version,
                            'description': f'Discourse version detected: {version} - Check for known CVEs'
                        })
                except Exception:
                    pass
        except Exception:
            pass
    
    def test_authentication_failures(self):
        """
        Checks the application's authentication endpoint for missing rate limiting that would allow brute-force attempts.
        
        Sends repeated login attempts to the '/session' endpoint; if five consecutive attempts are accepted (no 429 Too Many Requests response), appends a high-severity finding to self.results indicating the login endpoint lacks rate limiting. The check stops early if a 429 response or an error occurs.
        """
        try:
            login_url = urljoin(self.scanner.target_url, '/session')
            
            for i in range(5):
                response = self.scanner.make_request(
                    login_url,
                    method='POST',
                    json={'login': 'admin', 'password': 'test'},
                    timeout=5
                )
                
                if response and response.status_code != 429:
                    if i == 4:
                        self.results.append({
                            'type': 'A07:2021 - Authentication Failures',
                            'severity': 'high',
                            'description': 'No rate limiting on login endpoint - brute force possible'
                        })
                else:
                    break
                
                time.sleep(0.5)
        except Exception:
            pass
    
    def test_integrity_failures(self):
        """
        Detects software and data integrity failures by checking for external scripts loaded without Subresource Integrity (SRI).
        
        If the target page contains a <script src=> tag and no `integrity=` attribute is present within the first 5000 characters of the response body, appends a medium-severity finding to `self.results` with type "A08:2021 - Integrity Failures" and a description noting external scripts loaded without SRI.
        """
        try:
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if response:
                content = response.text
                
                if '<script src=' in content and 'integrity=' not in content[:5000]:
                    self.results.append({
                        'type': 'A08:2021 - Integrity Failures',
                        'severity': 'medium',
                        'description': 'External scripts loaded without Subresource Integrity (SRI)'
                    })
        except Exception:
            pass
    
    def test_logging_monitoring(self):
        """
        Checks common log-related endpoints for public accessibility and records findings when logs are reachable without authentication.
        
        If an endpoint responds with HTTP 200, appends a medium-severity finding to self.results containing the keys: `type` (A09:2021 - Logging Failures), `severity`, `endpoint`, and `description`.
        """
        try:
            logs_endpoints = ['/admin/logs', '/logs', '/admin/staff_action_logs']
            
            for endpoint in logs_endpoints:
                url = urljoin(self.scanner.target_url, endpoint)
                response = self.scanner.make_request(url, timeout=5)
                
                if response and response.status_code == 200:
                    self.results.append({
                        'type': 'A09:2021 - Logging Failures',
                        'severity': 'medium',
                        'endpoint': endpoint,
                        'description': f'Logs accessible without authentication: {endpoint}'
                    })
        except Exception:
            pass
    
    def test_ssrf_vulnerabilities(self):
        """
        Probe common endpoints for Server-Side Request Forgery (SSRF) by submitting internal and local resource URLs and record findings when the server appears to fetch them.
        
        Sends requests to known SSRF-prone endpoints with payloads targeting localhost, metadata services, and local files; on responses indicating a fetch (HTTP 200, 301, or 302) appends a critical-severity finding to self.results describing the endpoint and payload.
        """
        try:
            ssrf_endpoints = ['/oneboxer', '/uploads', '/thumbnail']
            ssrf_payloads = [
                'http://localhost',
                'http://127.0.0.1',
                'http://169.254.169.254',
                'file:///etc/passwd'
            ]
            
            for endpoint in ssrf_endpoints:
                for payload in ssrf_payloads:
                    url = urljoin(self.scanner.target_url, endpoint)
                    response = self.scanner.make_request(
                        url,
                        params={'url': payload},
                        timeout=5
                    )
                    
                    if response and response.status_code in [200, 301, 302]:
                        self.results.append({
                            'type': 'A10:2021 - SSRF',
                            'severity': 'critical',
                            'endpoint': endpoint,
                            'payload': payload,
                            'description': f'Potential SSRF vulnerability at {endpoint}'
                        })
                        break
        except Exception:
            pass