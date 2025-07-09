#!/usr/bin/env python3
"""
Discourse API Security Testing Module

This module tests API-specific security vulnerabilities in Discourse forums,
including authentication, authorization, rate limiting, and data exposure issues.

Author: ibrahimsql
Version: 2.0
"""

import requests
import json
import time
import random
import base64
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

class APISecurityModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.target_url = scanner.target_url
        self.session = scanner.session
        self.results = {
            'module_name': 'API Security Testing',
            'target': self.target_url,
            'vulnerabilities': [],
            'api_endpoints': [],
            'authentication_issues': [],
            'authorization_issues': [],
            'rate_limiting_issues': [],
            'data_exposure_issues': [],
            'api_abuse_issues': []
        }
        
        # Common API endpoints in Discourse
        self.api_endpoints = [
            '/admin/api',
            '/admin/api/keys',
            '/admin/api/web_hooks',
            '/admin/users.json',
            '/admin/groups.json',
            '/admin/site_settings.json',
            '/admin/customize/themes.json',
            '/admin/plugins.json',
            '/admin/logs.json',
            '/admin/reports.json',
            '/admin/dashboard.json',
            '/admin/flags.json',
            '/admin/email.json',
            '/admin/backups.json',
            '/categories.json',
            '/latest.json',
            '/top.json',
            '/users.json',
            '/groups.json',
            '/badges.json',
            '/tags.json',
            '/search.json',
            '/posts.json',
            '/topics.json',
            '/notifications.json',
            '/user_actions.json',
            '/directory_items.json',
            '/site.json',
            '/site/statistics.json',
            '/site/basic-info.json',
            '/about.json',
            '/stylesheets.json',
            '/theme-javascripts.json',
            '/uploads.json',
            '/session/current.json',
            '/session/csrf.json',
            '/clicks/track.json',
            '/draft.json',
            '/presence/get.json',
            '/reviewables.json',
            '/user-cards.json',
            '/user_avatar.json',
            '/invites.json',
            '/bookmarks.json',
            '/user_status.json',
            '/watched_words.json',
            '/email/unsubscribe.json',
            '/webhooks.json',
            '/csp_reports.json',
            '/exception.json'
        ]
        
        # API methods to test
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        
        # Rate limiting test parameters
        self.rate_limit_requests = 100
        self.rate_limit_threads = 10
        
    def run(self):
        """Run API security testing module (main entry point)"""
        return self.run_scan()
    
    def run_scan(self):
        """Run comprehensive API security testing"""
        print(f"[*] Starting API security testing for {self.target_url}")
        
        try:
            # API Discovery
            self._discover_api_endpoints()
            
            # Authentication Testing
            self._test_api_authentication()
            
            # Authorization Testing
            self._test_api_authorization()
            
            # Rate Limiting Testing
            self._test_rate_limiting()
            
            # Data Exposure Testing
            self._test_data_exposure()
            
            # API Abuse Testing
            self._test_api_abuse()
            
            # HTTP Method Testing
            self._test_http_methods()
            
            # Parameter Pollution Testing
            self._test_parameter_pollution()
            
            # API Versioning Testing
            self._test_api_versioning()
            
            # Content Type Testing
            self._test_content_types()
            
            # CORS Testing
            self._test_cors_issues()
            
            # GraphQL Testing (if available)
            self._test_graphql_security()
            
            print(f"[+] API security testing completed")
            
        except Exception as e:
            print(f"[!] Error during API security testing: {str(e)}")
            self.results['vulnerabilities'].append({
                'type': 'API Testing Error',
                'severity': 'info',
                'description': f'Error during API testing: {str(e)}'
            })
        
        return self.results
    
    def _discover_api_endpoints(self):
        """Discover available API endpoints"""
        print("[*] Discovering API endpoints...")
        
        discovered_endpoints = []
        
        for endpoint in self.api_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url, timeout=10)
                
                endpoint_info = {
                    'endpoint': endpoint,
                    'url': url,
                    'status_code': response.status_code,
                    'accessible': response.status_code != 404,
                    'requires_auth': response.status_code == 401 or response.status_code == 403,
                    'content_type': response.headers.get('content-type', ''),
                    'response_size': len(response.content)
                }
                
                # Check for sensitive information in response
                if response.status_code == 200:
                    content = response.text.lower()
                    if any(keyword in content for keyword in ['password', 'secret', 'key', 'token', 'api_key']):
                        endpoint_info['contains_sensitive_data'] = True
                        self.results['vulnerabilities'].append({
                            'type': 'Sensitive Data Exposure',
                            'severity': 'medium',
                            'endpoint': endpoint,
                            'description': f'API endpoint {endpoint} may expose sensitive information'
                        })
                
                discovered_endpoints.append(endpoint_info)
                
                # Small delay to avoid overwhelming the server
                time.sleep(0.1)
                
            except Exception as e:
                print(f"[!] Error testing endpoint {endpoint}: {str(e)}")
        
        self.results['api_endpoints'] = discovered_endpoints
        print(f"[+] Discovered {len([e for e in discovered_endpoints if e['accessible']])} accessible API endpoints")
    
    def _test_api_authentication(self):
        """Test API authentication mechanisms"""
        print("[*] Testing API authentication...")
        
        # Test unauthenticated access to protected endpoints
        protected_endpoints = ['/admin/api', '/admin/users.json', '/admin/site_settings.json']
        
        for endpoint in protected_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                
                # Test without authentication
                response = self.session.get(url)
                if response.status_code == 200:
                    self.results['authentication_issues'].append({
                        'type': 'Unauthenticated Access',
                        'severity': 'high',
                        'endpoint': endpoint,
                        'description': f'Protected endpoint {endpoint} accessible without authentication'
                    })
                
                # Test with invalid API key
                headers = {'Api-Key': 'invalid_key', 'Api-Username': 'admin'}
                response = self.session.get(url, headers=headers)
                if response.status_code == 200:
                    self.results['authentication_issues'].append({
                        'type': 'Invalid API Key Bypass',
                        'severity': 'critical',
                        'endpoint': endpoint,
                        'description': f'Endpoint {endpoint} accessible with invalid API key'
                    })
                
                # Test with empty API key
                headers = {'Api-Key': '', 'Api-Username': 'admin'}
                response = self.session.get(url, headers=headers)
                if response.status_code == 200:
                    self.results['authentication_issues'].append({
                        'type': 'Empty API Key Bypass',
                        'severity': 'critical',
                        'endpoint': endpoint,
                        'description': f'Endpoint {endpoint} accessible with empty API key'
                    })
                
                # Test API key in URL parameter
                test_url = f"{url}?api_key=test_key&api_username=admin"
                response = self.session.get(test_url)
                if response.status_code != 401:
                    self.results['authentication_issues'].append({
                        'type': 'API Key in URL',
                        'severity': 'medium',
                        'endpoint': endpoint,
                        'description': f'Endpoint {endpoint} accepts API key in URL parameters (potential logging exposure)'
                    })
                
            except Exception as e:
                print(f"[!] Error testing authentication for {endpoint}: {str(e)}")
    
    def _test_api_authorization(self):
        """Test API authorization and privilege escalation"""
        print("[*] Testing API authorization...")
        
        # Test horizontal privilege escalation
        user_endpoints = [
            '/users/1.json',
            '/users/2.json',
            '/users/admin.json',
            '/u/admin.json',
            '/u/moderator.json'
        ]
        
        for endpoint in user_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'user' in data and 'email' in data['user']:
                            self.results['authorization_issues'].append({
                                'type': 'User Data Exposure',
                                'severity': 'medium',
                                'endpoint': endpoint,
                                'description': f'User endpoint {endpoint} exposes sensitive user data including email'
                            })
                    except:
                        pass
                
            except Exception as e:
                print(f"[!] Error testing authorization for {endpoint}: {str(e)}")
        
        # Test admin endpoint access with regular user credentials
        admin_endpoints = ['/admin/users.json', '/admin/site_settings.json', '/admin/api/keys.json']
        
        for endpoint in admin_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                
                # Test with various user role headers
                test_headers = [
                    {'Api-Username': 'user', 'Api-Key': 'user_key'},
                    {'Api-Username': 'moderator', 'Api-Key': 'mod_key'},
                    {'X-User-Role': 'admin'},
                    {'X-Admin': 'true'},
                    {'Is-Admin': '1'}
                ]
                
                for headers in test_headers:
                    response = self.session.get(url, headers=headers)
                    if response.status_code == 200:
                        self.results['authorization_issues'].append({
                            'type': 'Privilege Escalation',
                            'severity': 'critical',
                            'endpoint': endpoint,
                            'headers': headers,
                            'description': f'Admin endpoint {endpoint} accessible with non-admin credentials'
                        })
                
            except Exception as e:
                print(f"[!] Error testing admin access for {endpoint}: {str(e)}")
    
    def _test_rate_limiting(self):
        """Test API rate limiting mechanisms"""
        print("[*] Testing API rate limiting...")
        
        test_endpoints = ['/latest.json', '/search.json', '/users.json']
        
        for endpoint in test_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                
                # Test rapid requests
                start_time = time.time()
                successful_requests = 0
                rate_limited = False
                
                def make_request():
                    nonlocal successful_requests, rate_limited
                    try:
                        response = self.session.get(url, timeout=5)
                        if response.status_code == 429:  # Too Many Requests
                            rate_limited = True
                        elif response.status_code == 200:
                            successful_requests += 1
                    except:
                        pass
                
                # Make concurrent requests
                with ThreadPoolExecutor(max_workers=self.rate_limit_threads) as executor:
                    futures = [executor.submit(make_request) for _ in range(self.rate_limit_requests)]
                    for future in as_completed(futures):
                        future.result()
                
                end_time = time.time()
                duration = end_time - start_time
                requests_per_second = successful_requests / duration if duration > 0 else 0
                
                if not rate_limited and successful_requests > 50:
                    self.results['rate_limiting_issues'].append({
                        'type': 'No Rate Limiting',
                        'severity': 'medium',
                        'endpoint': endpoint,
                        'successful_requests': successful_requests,
                        'requests_per_second': round(requests_per_second, 2),
                        'description': f'Endpoint {endpoint} has no rate limiting (processed {successful_requests} requests)'
                    })
                
            except Exception as e:
                print(f"[!] Error testing rate limiting for {endpoint}: {str(e)}")
    
    def _test_data_exposure(self):
        """Test for sensitive data exposure in API responses"""
        print("[*] Testing for data exposure...")
        
        sensitive_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'api_key': r'[a-f0-9]{32,}',
            'password_hash': r'\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}',
            'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*',
            'private_key': r'-----BEGIN (RSA )?PRIVATE KEY-----',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'github_token': r'ghp_[a-zA-Z0-9]{36}'
        }
        
        test_endpoints = ['/site.json', '/about.json', '/users.json', '/latest.json']
        
        for endpoint in test_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    content = response.text
                    
                    for data_type, pattern in sensitive_patterns.items():
                        import re
                        matches = re.findall(pattern, content)
                        if matches:
                            self.results['data_exposure_issues'].append({
                                'type': f'Sensitive Data Exposure - {data_type.title()}',
                                'severity': 'high' if data_type in ['api_key', 'password_hash', 'private_key'] else 'medium',
                                'endpoint': endpoint,
                                'data_type': data_type,
                                'matches_count': len(matches),
                                'description': f'Endpoint {endpoint} exposes {data_type} in response'
                            })
                
            except Exception as e:
                print(f"[!] Error testing data exposure for {endpoint}: {str(e)}")
    
    def _test_api_abuse(self):
        """Test for API abuse vulnerabilities"""
        print("[*] Testing for API abuse...")
        
        # Test for SQL injection in API parameters
        sql_payloads = ["'", "' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT 1,2,3 --"]
        
        test_endpoints = ['/search.json', '/users.json', '/categories.json']
        
        for endpoint in test_endpoints:
            for payload in sql_payloads:
                try:
                    url = urljoin(self.target_url, endpoint)
                    params = {'q': payload, 'term': payload, 'filter': payload}
                    
                    response = self.session.get(url, params=params)
                    
                    # Check for SQL error messages
                    error_indicators = ['sql', 'mysql', 'postgresql', 'sqlite', 'syntax error', 'database']
                    if any(indicator in response.text.lower() for indicator in error_indicators):
                        self.results['api_abuse_issues'].append({
                            'type': 'SQL Injection',
                            'severity': 'critical',
                            'endpoint': endpoint,
                            'payload': payload,
                            'description': f'Potential SQL injection in {endpoint} with payload: {payload}'
                        })
                
                except Exception as e:
                    print(f"[!] Error testing SQL injection for {endpoint}: {str(e)}")
        
        # Test for XSS in API responses
        xss_payloads = ['<script>alert(1)</script>', '"><script>alert(1)</script>', "'><script>alert(1)</script>"]
        
        for endpoint in test_endpoints:
            for payload in xss_payloads:
                try:
                    url = urljoin(self.target_url, endpoint)
                    params = {'q': payload, 'term': payload, 'name': payload}
                    
                    response = self.session.get(url, params=params)
                    
                    if payload in response.text and 'application/json' not in response.headers.get('content-type', ''):
                        self.results['api_abuse_issues'].append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'high',
                            'endpoint': endpoint,
                            'payload': payload,
                            'description': f'Potential XSS in {endpoint} with payload: {payload}'
                        })
                
                except Exception as e:
                    print(f"[!] Error testing XSS for {endpoint}: {str(e)}")
    
    def _test_http_methods(self):
        """Test different HTTP methods on API endpoints"""
        print("[*] Testing HTTP methods...")
        
        test_endpoints = ['/users.json', '/categories.json', '/admin/users.json']
        
        for endpoint in test_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            for method in self.http_methods:
                try:
                    response = self.session.request(method, url)
                    
                    # Check for unexpected method support
                    if method in ['PUT', 'DELETE', 'PATCH'] and response.status_code not in [405, 501]:
                        self.results['vulnerabilities'].append({
                            'type': 'Unexpected HTTP Method Support',
                            'severity': 'medium',
                            'endpoint': endpoint,
                            'method': method,
                            'status_code': response.status_code,
                            'description': f'Endpoint {endpoint} supports {method} method unexpectedly'
                        })
                    
                    # Check for method override
                    if method == 'POST':
                        override_headers = {
                            'X-HTTP-Method-Override': 'DELETE',
                            'X-Method-Override': 'PUT',
                            '_method': 'DELETE'
                        }
                        
                        for header, value in override_headers.items():
                            override_response = self.session.post(url, headers={header: value})
                            if override_response.status_code != response.status_code:
                                self.results['vulnerabilities'].append({
                                    'type': 'HTTP Method Override',
                                    'severity': 'medium',
                                    'endpoint': endpoint,
                                    'override_header': header,
                                    'description': f'Endpoint {endpoint} supports HTTP method override via {header}'
                                })
                
                except Exception as e:
                    print(f"[!] Error testing {method} method for {endpoint}: {str(e)}")
    
    def _test_parameter_pollution(self):
        """Test for HTTP parameter pollution vulnerabilities"""
        print("[*] Testing parameter pollution...")
        
        test_endpoints = ['/search.json', '/users.json']
        
        for endpoint in test_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                
                # Test duplicate parameters
                polluted_url = f"{url}?q=safe&q=<script>alert(1)</script>&q=admin"
                response = self.session.get(polluted_url)
                
                if '<script>' in response.text:
                    self.results['vulnerabilities'].append({
                        'type': 'HTTP Parameter Pollution - XSS',
                        'severity': 'high',
                        'endpoint': endpoint,
                        'description': f'Parameter pollution in {endpoint} leads to XSS'
                    })
                
                # Test parameter precedence
                test_params = 'user=normal&user=admin&role=user&role=admin'
                test_url = f"{url}?{test_params}"
                response = self.session.get(test_url)
                
                if response.status_code == 200:
                    self.results['vulnerabilities'].append({
                        'type': 'HTTP Parameter Pollution',
                        'severity': 'medium',
                        'endpoint': endpoint,
                        'description': f'Endpoint {endpoint} may be vulnerable to parameter pollution'
                    })
            
            except Exception as e:
                print(f"[!] Error testing parameter pollution for {endpoint}: {str(e)}")
    
    def _test_api_versioning(self):
        """Test API versioning security issues"""
        print("[*] Testing API versioning...")
        
        version_patterns = [
            '/v1/users.json',
            '/v2/users.json',
            '/api/v1/users.json',
            '/api/v2/users.json',
            '/api/1.0/users.json',
            '/api/2.0/users.json'
        ]
        
        for version_endpoint in version_patterns:
            try:
                url = urljoin(self.target_url, version_endpoint)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    self.results['vulnerabilities'].append({
                        'type': 'API Version Discovery',
                        'severity': 'info',
                        'endpoint': version_endpoint,
                        'description': f'API version endpoint {version_endpoint} is accessible'
                    })
                    
                    # Check for deprecated version warnings
                    if 'deprecated' in response.text.lower() or 'obsolete' in response.text.lower():
                        self.results['vulnerabilities'].append({
                            'type': 'Deprecated API Version',
                            'severity': 'medium',
                            'endpoint': version_endpoint,
                            'description': f'Deprecated API version {version_endpoint} is still accessible'
                        })
            
            except Exception as e:
                print(f"[!] Error testing API version {version_endpoint}: {str(e)}")
    
    def _test_content_types(self):
        """Test different content types for API abuse"""
        print("[*] Testing content types...")
        
        test_endpoints = ['/posts.json', '/users.json']
        content_types = [
            'application/json',
            'application/xml',
            'text/xml',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain',
            'application/yaml'
        ]
        
        for endpoint in test_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            for content_type in content_types:
                try:
                    headers = {'Content-Type': content_type}
                    data = '{"test": "data"}' if 'json' in content_type else 'test=data'
                    
                    response = self.session.post(url, headers=headers, data=data)
                    
                    if response.status_code not in [400, 415, 405]:  # Not bad request, unsupported media type, or method not allowed
                        self.results['vulnerabilities'].append({
                            'type': 'Unexpected Content Type Support',
                            'severity': 'low',
                            'endpoint': endpoint,
                            'content_type': content_type,
                            'status_code': response.status_code,
                            'description': f'Endpoint {endpoint} accepts unexpected content type: {content_type}'
                        })
                
                except Exception as e:
                    print(f"[!] Error testing content type {content_type} for {endpoint}: {str(e)}")
    
    def _test_cors_issues(self):
        """Test for CORS misconfigurations"""
        print("[*] Testing CORS issues...")
        
        test_endpoints = ['/latest.json', '/users.json', '/admin/users.json']
        
        for endpoint in test_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                
                # Test with malicious origin
                headers = {'Origin': 'https://evil.com'}
                response = self.session.get(url, headers=headers)
                
                cors_headers = {
                    'access-control-allow-origin': response.headers.get('Access-Control-Allow-Origin'),
                    'access-control-allow-credentials': response.headers.get('Access-Control-Allow-Credentials'),
                    'access-control-allow-methods': response.headers.get('Access-Control-Allow-Methods'),
                    'access-control-allow-headers': response.headers.get('Access-Control-Allow-Headers')
                }
                
                # Check for wildcard with credentials
                if (cors_headers['access-control-allow-origin'] == '*' and 
                    cors_headers['access-control-allow-credentials'] == 'true'):
                    self.results['vulnerabilities'].append({
                        'type': 'CORS Misconfiguration - Wildcard with Credentials',
                        'severity': 'high',
                        'endpoint': endpoint,
                        'description': f'Endpoint {endpoint} allows wildcard origin with credentials'
                    })
                
                # Check for reflected origin
                if cors_headers['access-control-allow-origin'] == 'https://evil.com':
                    self.results['vulnerabilities'].append({
                        'type': 'CORS Misconfiguration - Reflected Origin',
                        'severity': 'medium',
                        'endpoint': endpoint,
                        'description': f'Endpoint {endpoint} reflects arbitrary origins'
                    })
                
                # Check for overly permissive methods
                allowed_methods = cors_headers.get('access-control-allow-methods', '')
                dangerous_methods = ['DELETE', 'PUT', 'PATCH']
                if any(method in allowed_methods for method in dangerous_methods):
                    self.results['vulnerabilities'].append({
                        'type': 'CORS Misconfiguration - Dangerous Methods',
                        'severity': 'medium',
                        'endpoint': endpoint,
                        'allowed_methods': allowed_methods,
                        'description': f'Endpoint {endpoint} allows dangerous HTTP methods via CORS'
                    })
            
            except Exception as e:
                print(f"[!] Error testing CORS for {endpoint}: {str(e)}")
    
    def _test_graphql_security(self):
        """Test GraphQL security if available"""
        print("[*] Testing GraphQL security...")
        
        graphql_endpoints = ['/graphql', '/api/graphql', '/admin/graphql']
        
        for endpoint in graphql_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                
                # Test GraphQL introspection
                introspection_query = {
                    "query": "query IntrospectionQuery { __schema { queryType { name } } }"
                }
                
                response = self.session.post(url, json=introspection_query)
                
                if response.status_code == 200 and 'queryType' in response.text:
                    self.results['vulnerabilities'].append({
                        'type': 'GraphQL Introspection Enabled',
                        'severity': 'medium',
                        'endpoint': endpoint,
                        'description': f'GraphQL introspection is enabled at {endpoint}'
                    })
                    
                    # Test for sensitive schema information
                    full_introspection = {
                        "query": "query IntrospectionQuery { __schema { types { name fields { name type { name } } } } }"
                    }
                    
                    full_response = self.session.post(url, json=full_introspection)
                    if 'password' in full_response.text.lower() or 'secret' in full_response.text.lower():
                        self.results['vulnerabilities'].append({
                            'type': 'GraphQL Sensitive Schema',
                            'severity': 'high',
                            'endpoint': endpoint,
                            'description': f'GraphQL schema at {endpoint} exposes sensitive field names'
                        })
                
                # Test GraphQL query depth
                deep_query = {
                    "query": "query { " + "user { " * 20 + "id" + " }" * 20 + " }"
                }
                
                response = self.session.post(url, json=deep_query)
                if response.status_code == 200:
                    self.results['vulnerabilities'].append({
                        'type': 'GraphQL Query Depth Not Limited',
                        'severity': 'medium',
                        'endpoint': endpoint,
                        'description': f'GraphQL endpoint {endpoint} does not limit query depth'
                    })
            
            except Exception as e:
                print(f"[!] Error testing GraphQL for {endpoint}: {str(e)}")

if __name__ == "__main__":
    # Test the module
    class MockScanner:
        def __init__(self):
            self.target_url = "https://discourse.example.com"
            self.session = requests.Session()
    
    scanner = MockScanner()
    api_module = APISecurityModule(scanner)
    results = api_module.run_scan()
    
    print(json.dumps(results, indent=2))