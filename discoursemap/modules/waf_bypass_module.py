#!/usr/bin/env python3
"""
Discourse Security Scanner - WAF Bypass Module

Web Application Firewall bypass testing for Discourse forums
For educational and authorized testing purposes only

Author: ibrahimsql
Version: 1.0.0
"""

import time
import random
import base64
import urllib.parse
from urllib.parse import urljoin, quote, unquote
from .utils import make_request, random_user_agent

class WAFBypassModule:
    """WAF bypass testing module for Discourse forums"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'WAF Bypass Testing',
            'target': scanner.target_url,
            'waf_detected': [],
            'bypass_techniques': [],
            'successful_bypasses': [],
            'payload_encodings': [],
            'rate_limit_bypasses': [],
            'ip_rotation_tests': [],
            'tests_performed': 0,
            'scan_time': 0
        }
    
    def run(self):
        """Run WAF bypass tests"""
        print(f"{self.scanner.colors['info']}[*] Starting WAF bypass testing...{self.scanner.colors['reset']}")
        start_time = time.time()
        
        try:
            # WAF Detection
            self._detect_waf()
            
            # Payload Encoding Tests
            self._test_payload_encodings()
            
            # Rate Limiting Bypass
            self._test_rate_limit_bypass()
            
            # IP Rotation Tests
            self._test_ip_rotation()
            
            # Advanced Bypass Techniques
            self._test_advanced_bypasses()
            
        except Exception as e:
            self.scanner.log(f"Error in WAF bypass module: {str(e)}", 'error')
        
        finally:
            self.results['scan_time'] = time.time() - start_time
            self.scanner.log(f"WAF bypass testing completed in {self.results['scan_time']:.2f} seconds", 'success')
        
        return self.results
    
    def _detect_waf(self):
        """Detect Web Application Firewall"""
        print(f"{self.scanner.colors['info']}[*] Detecting WAF presence...{self.scanner.colors['reset']}")
        
        # Common WAF detection payloads
        waf_payloads = [
            "<script>alert('xss')</script>",
            "' OR '1'='1",
            "../../../etc/passwd",
            "<?php phpinfo(); ?>",
            "<img src=x onerror=alert(1)>"
        ]
        
        waf_signatures = {
            'cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'aws_waf': ['x-amzn-requestid', 'x-amz-cf-id'],
            'akamai': ['akamai', 'ak-bmsc'],
            'incapsula': ['incap_ses', 'visid_incap'],
            'sucuri': ['sucuri', 'x-sucuri-id'],
            'barracuda': ['barra', 'barracuda'],
            'f5_bigip': ['bigip', 'f5-bigip'],
            'fortinet': ['fortigate', 'fortiweb']
        }
        
        for payload in waf_payloads:
            url = urljoin(self.scanner.target_url, f"/search?q={quote(payload)}")
            response = make_request(self.scanner.session, 'GET', url)
            
            if response:
                # Check response headers for WAF signatures
                for waf_name, signatures in waf_signatures.items():
                    for signature in signatures:
                        if any(signature.lower() in header.lower() for header in response.headers.keys()):
                            waf_info = {
                                'waf_name': waf_name,
                                'signature': signature,
                                'status_code': response.status_code,
                                'payload': payload
                            }
                            self.results['waf_detected'].append(waf_info)
                            print(f"{self.scanner.colors['warning']}[!] WAF detected: {waf_name}{self.scanner.colors['reset']}")
                
                # Check for common WAF response patterns
                if response.status_code in [403, 406, 429, 503]:
                    blocked_keywords = ['blocked', 'forbidden', 'security', 'firewall', 'protection']
                    if any(keyword in response.text.lower() for keyword in blocked_keywords):
                        self.results['waf_detected'].append({
                            'waf_name': 'generic',
                            'status_code': response.status_code,
                            'payload': payload,
                            'response_snippet': response.text[:200]
                        })
            
            time.sleep(self.scanner.delay)
            self.results['tests_performed'] += 1
    
    def _test_payload_encodings(self):
        """Test various payload encoding techniques"""
        print(f"{self.scanner.colors['info']}[*] Testing payload encoding bypasses...{self.scanner.colors['reset']}")
        
        base_payload = "<script>alert('xss')</script>"
        
        encoding_techniques = {
            'url_encoding': lambda p: quote(p),
            'double_url_encoding': lambda p: quote(quote(p)),
            'html_encoding': lambda p: ''.join(f'&#{ord(c)};' for c in p),
            'hex_encoding': lambda p: ''.join(f'\\x{ord(c):02x}' for c in p),
            'unicode_encoding': lambda p: ''.join(f'\\u{ord(c):04x}' for c in p),
            'base64_encoding': lambda p: base64.b64encode(p.encode()).decode(),
            'mixed_case': lambda p: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
            'comment_injection': lambda p: p.replace('script', 'scr/**/ipt')
        }
        
        for technique_name, encoder in encoding_techniques.items():
            try:
                encoded_payload = encoder(base_payload)
                url = urljoin(self.scanner.target_url, f"/search?q={encoded_payload}")
                response = make_request(self.scanner.session, 'GET', url)
                
                if response:
                    bypass_result = {
                        'technique': technique_name,
                        'original_payload': base_payload,
                        'encoded_payload': encoded_payload,
                        'status_code': response.status_code,
                        'bypassed': response.status_code == 200 and 'blocked' not in response.text.lower()
                    }
                    
                    self.results['payload_encodings'].append(bypass_result)
                    
                    if bypass_result['bypassed']:
                        print(f"{self.scanner.colors['success']}[+] Bypass successful: {technique_name}{self.scanner.colors['reset']}")
                        self.results['successful_bypasses'].append(bypass_result)
                
                time.sleep(self.scanner.delay)
                self.results['tests_performed'] += 1
                
            except Exception as e:
                self.scanner.log(f"Error testing {technique_name}: {str(e)}", 'debug')
    
    def _test_rate_limit_bypass(self):
        """Test rate limiting bypass techniques"""
        print(f"{self.scanner.colors['info']}[*] Testing rate limit bypasses...{self.scanner.colors['reset']}")
        
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Cluster-Client-IP': '127.0.0.1'}
        ]
        
        # Test rapid requests without headers
        baseline_responses = []
        for i in range(10):
            response = make_request(self.scanner.session, 'GET', self.scanner.target_url)
            if response:
                baseline_responses.append(response.status_code)
            time.sleep(0.1)
        
        # Test with bypass headers
        for headers in bypass_headers:
            bypass_responses = []
            for i in range(10):
                response = make_request(self.scanner.session, 'GET', self.scanner.target_url, headers=headers)
                if response:
                    bypass_responses.append(response.status_code)
                time.sleep(0.1)
            
            # Analyze if bypass was successful
            baseline_blocked = sum(1 for code in baseline_responses if code in [429, 503])
            bypass_blocked = sum(1 for code in bypass_responses if code in [429, 503])
            
            bypass_result = {
                'headers': headers,
                'baseline_blocked': baseline_blocked,
                'bypass_blocked': bypass_blocked,
                'successful': bypass_blocked < baseline_blocked
            }
            
            self.results['rate_limit_bypasses'].append(bypass_result)
            
            if bypass_result['successful']:
                print(f"{self.scanner.colors['success']}[+] Rate limit bypass successful with: {headers}{self.scanner.colors['reset']}")
            
            self.results['tests_performed'] += 1
    
    def _test_ip_rotation(self):
        """Test IP rotation techniques"""
        print(f"{self.scanner.colors['info']}[*] Testing IP rotation bypasses...{self.scanner.colors['reset']}")
        
        # Generate random IP addresses
        fake_ips = []
        for _ in range(5):
            ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            fake_ips.append(ip)
        
        for ip in fake_ips:
            headers = {
                'X-Forwarded-For': ip,
                'X-Real-IP': ip,
                'User-Agent': random_user_agent()
            }
            
            response = make_request(self.scanner.session, 'GET', self.scanner.target_url, headers=headers)
            
            if response:
                rotation_result = {
                    'fake_ip': ip,
                    'status_code': response.status_code,
                    'successful': response.status_code == 200
                }
                
                self.results['ip_rotation_tests'].append(rotation_result)
                
                if rotation_result['successful']:
                    print(f"{self.scanner.colors['success']}[+] IP rotation successful: {ip}{self.scanner.colors['reset']}")
            
            time.sleep(self.scanner.delay)
            self.results['tests_performed'] += 1
    
    def _test_advanced_bypasses(self):
        """Test advanced WAF bypass techniques"""
        print(f"{self.scanner.colors['info']}[*] Testing advanced bypass techniques...{self.scanner.colors['reset']}")
        
        advanced_techniques = [
            {
                'name': 'HTTP Parameter Pollution',
                'payload': 'search?q=normal&q=<script>alert(1)</script>'
            },
            {
                'name': 'HTTP Method Override',
                'payload': 'search',
                'headers': {'X-HTTP-Method-Override': 'POST'}
            },
            {
                'name': 'Content-Type Confusion',
                'payload': 'search',
                'headers': {'Content-Type': 'application/json'},
                'data': '{"q": "<script>alert(1)</script>"}'
            },
            {
                'name': 'Chunked Transfer Encoding',
                'payload': 'search',
                'headers': {'Transfer-Encoding': 'chunked'}
            }
        ]
        
        for technique in advanced_techniques:
            try:
                url = urljoin(self.scanner.target_url, technique['payload'])
                headers = technique.get('headers', {})
                data = technique.get('data')
                
                response = make_request(self.scanner.session, 'GET', url, headers=headers, data=data)
                
                if response:
                    bypass_result = {
                        'technique': technique['name'],
                        'status_code': response.status_code,
                        'bypassed': response.status_code == 200 and 'blocked' not in response.text.lower()
                    }
                    
                    self.results['bypass_techniques'].append(bypass_result)
                    
                    if bypass_result['bypassed']:
                        print(f"{self.scanner.colors['success']}[+] Advanced bypass successful: {technique['name']}{self.scanner.colors['reset']}")
                        self.results['successful_bypasses'].append(bypass_result)
                
                time.sleep(self.scanner.delay)
                self.results['tests_performed'] += 1
                
            except Exception as e:
                self.scanner.log(f"Error testing {technique['name']}: {str(e)}", 'debug')