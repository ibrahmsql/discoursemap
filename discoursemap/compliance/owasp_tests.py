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
        Initialize the OWASPTests instance with a scanner and prepare an empty results list.
        
        Parameters:
            scanner: An external scanner object used to perform HTTP requests and provide the target URL; stored on the instance as `self.scanner`.
        """
        self.scanner = scanner
        self.results = []
    
    def run_all_tests(self):
        """
        Run all OWASP Top 10 (2021) test methods in sequence and collect findings.
        
        Returns:
            results (list[dict]): Accumulated result dictionaries describing findings discovered by the tests.
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
        Detects publicly accessible admin endpoints and records high-severity findings for any that return HTTP 200.
        
        Scans a predefined set of admin-like paths on the scanner's target and, for each endpoint that is reachable and responds with status code 200, appends a finding dictionary to self.results describing the endpoint, category (A01:2021 - Broken Access Control) and severity.
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
        Detects transport-layer cryptographic issues on the configured target.
        
        If the target URL does not use HTTPS, appends a critical finding to self.results indicating cleartext transmission. Then requests the target and, if the response is present but lacks a Strict-Transport-Security header, appends a high-severity finding about missing HSTS.
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
        Detects injection vulnerabilities by probing the target's search endpoint with common payloads.
        
        Sends a set of common injection payloads to the site's search endpoint and records findings in self.results when observable indications of injection are detected. Appends a high-severity finding if a payload causes a server error (HTTP 500) and a medium-severity finding if a payload is reflected in the response body.
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
        Detects exposed debugging or error information in the target's HTTP response.
        
        Searches the response body for indicators such as "debug", "stacktrace", "exception", and "error details" and, if any are found, appends a medium-severity finding describing the exposed indicator.
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
        Detects disclosure of server or framework information in HTTP response headers.
        
        If the target response includes a Server or X-Powered-By header, appends a low-severity finding to self.results containing the header name, its value, the OWASP category (A05:2021), and a short description.
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
        Detects the application's version from /site.json and records it for vulnerable-component checks.
        
        Sends a request to the target's /site.json; if a 200 response contains a JSON `version` value, appends an info-severity result entry with the detected version and a recommendation to check for known CVEs.
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
        Check the application's login endpoint for missing rate limiting.
        
        Sends repeated login attempts to the session endpoint and records a high-severity finding in self.results if five consecutive attempts succeed without encountering rate limiting (HTTP 429). Stops early if a request is rate-limited or no response is received.
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
        Detects external scripts loaded without Subresource Integrity (SRI) and records a medium-severity finding when such scripts are present.
        
        If the page contains a script tag with a src attribute and no `integrity` attribute within the first 5000 characters of the response, a result entry is appended to the instance's results describing the missing SRI.
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
        Scan common log endpoints and record findings when logs are accessible without authentication.
        
        Checks a set of known log-related paths on the target using the provided scanner; when an endpoint returns HTTP 200, appends a medium-severity result describing the exposed logs.
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
        Detects potential Server-Side Request Forgery (SSRF) by sending external and internal URL payloads to common endpoints and recording findings.
        
        Sends requests to a set of SSRF-prone endpoints with payloads targeting localhost, metadata services, and file URIs. If a request returns status 200, 301, or 302, appends a critical-severity result to self.results with keys: `type` (A10:2021 - SSRF), `severity`, `endpoint`, `payload`, and `description`.
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