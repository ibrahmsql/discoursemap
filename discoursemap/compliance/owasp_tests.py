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
        self.scanner = scanner
        self.results = []
    
    def run_all_tests(self):
        """Execute all OWASP Top 10 tests"""
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
        """A01:2021 - Broken Access Control"""
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
        """A02:2021 - Cryptographic Failures"""
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
        """A03:2021 - Injection"""
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
        """A04:2021 - Insecure Design"""
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
        """A05:2021 - Security Misconfiguration"""
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
        """A06:2021 - Vulnerable and Outdated Components"""
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
        """A07:2021 - Identification and Authentication Failures"""
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
        """A08:2021 - Software and Data Integrity Failures"""
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
        """A09:2021 - Security Logging and Monitoring Failures"""
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
        """A10:2021 - Server-Side Request Forgery (SSRF)"""
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
