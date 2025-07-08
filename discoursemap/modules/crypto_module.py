#!/usr/bin/env python3
"""
Discourse Security Scanner - Cryptographic Security Module

Tests cryptographic implementations and security
"""

import re
import time
import json
import base64
import hashlib
import hmac
from urllib.parse import urljoin, quote
from bs4 import BeautifulSoup
from .utils import extract_csrf_token, make_request

class CryptoModule:
    """Cryptographic security testing module for Discourse forums"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Cryptographic Security Testing',
            'target': scanner.target_url,
            'weak_hashing': [],
            'weak_encryption': [],
            'jwt_vulnerabilities': [],
            'session_security': [],
            'csrf_analysis': [],
            'crypto_misconfig': [],
            'key_exposure': [],
            'random_analysis': [],
            'signature_bypass': [],
            'timing_attacks': []
        }
        
    def run_scan(self):
        """Run complete cryptographic security scan"""
        print(f"\n{self.scanner.colors['info']}[*] Starting cryptographic security scan...{self.scanner.colors['reset']}")
        
        # Weak hash algorithms
        self._test_weak_hashing()
        
        # Weak encryption
        self._test_weak_encryption()
        
        # JWT vulnerabilities
        self._test_jwt_vulnerabilities()
        
        # Session security
        self._test_session_security()
        
        # CSRF analysis
        self._analyze_csrf_protection()
        
        # Crypto misconfiguration
        self._test_crypto_misconfig()
        
        # Key exposure
        self._test_key_exposure()
        
        # Randomness analysis
        self._test_randomness()
        
        # Signature bypass
        self._test_signature_bypass()
        
        # Timing attacks
        self._test_timing_attacks()
        
        return self.results
    
    def _test_weak_hashing(self):
        """Test for weak hashing algorithms"""
        print(f"{self.scanner.colors['info']}[*] Testing weak hash algorithms...{self.scanner.colors['reset']}")
        
        # Test password reset functionality
        reset_url = urljoin(self.scanner.target_url, '/password-reset')
        response = make_request(self.scanner.session, 'GET', reset_url)
        
        if response and response.status_code == 200:
            # Look for hash patterns in response
            hash_patterns = {
                'MD5': r'[a-f0-9]{32}',
                'SHA1': r'[a-f0-9]{40}',
                'Weak_Hash': r'\b[a-f0-9]{8,16}\b'
            }
            
            for hash_type, pattern in hash_patterns.items():
                matches = re.findall(pattern, response.text)
                if matches:
                    self.results['weak_hashing'].append({
                        'hash_type': hash_type,
                        'location': 'password_reset',
                        'samples': matches[:3],  # First 3 samples
                        'severity': 'High' if hash_type in ['MD5', 'SHA1'] else 'Medium',
                        'description': f'{hash_type} hashes detected in password reset'
                    })
        
        # Test user profile pages for hash exposure
        user_urls = [
            '/u/admin',
            '/u/system',
            '/users/1.json',
            '/admin/users.json'
        ]
        
        for user_url in user_urls:
            url = urljoin(self.scanner.target_url, user_url)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                # Check for exposed password hashes
                if 'password' in response.text.lower() or 'hash' in response.text.lower():
                    # Look for hash-like patterns
                    potential_hashes = re.findall(r'[a-f0-9]{32,128}', response.text)
                    if potential_hashes:
                        self.results['weak_hashing'].append({
                            'location': user_url,
                            'potential_hashes': len(potential_hashes),
                            'severity': 'Critical',
                            'description': f'Potential password hashes exposed at {user_url}'
                        })
    
    def _test_weak_encryption(self):
        """Test for weak encryption implementations"""
        print(f"{self.scanner.colors['info']}[*] Testing weak encryption...{self.scanner.colors['reset']}")
        
        # Test for weak cookie encryption
        response = make_request(self.scanner.session, 'GET', self.scanner.target_url)
        
        if response:
            cookies = response.cookies
            
            for cookie in cookies:
                cookie_value = cookie.value
                
                # Check for base64 encoded values (potential encrypted data)
                if self._is_base64(cookie_value):
                    try:
                        decoded = base64.b64decode(cookie_value)
                        
                        # Check for patterns indicating weak encryption
                        if len(decoded) % 8 == 0:  # DES block size
                            self.results['weak_encryption'].append({
                                'cookie_name': cookie.name,
                                'issue': 'Potential DES encryption (8-byte blocks)',
                                'severity': 'High',
                                'description': f'Cookie {cookie.name} may use weak DES encryption'
                            })
                        
                        # Check for ECB mode patterns (repeated blocks)
                        if len(decoded) >= 32:
                            blocks = [decoded[i:i+16] for i in range(0, len(decoded), 16)]
                            if len(blocks) != len(set(blocks)):  # Duplicate blocks
                                self.results['weak_encryption'].append({
                                    'cookie_name': cookie.name,
                                    'issue': 'Potential ECB mode encryption',
                                    'severity': 'Medium',
                                    'description': f'Cookie {cookie.name} shows ECB mode patterns'
                                })
                    except:
                        pass
                
                # Check for simple encoding (not encryption)
                if self._is_simple_encoding(cookie_value):
                    self.results['weak_encryption'].append({
                        'cookie_name': cookie.name,
                        'issue': 'Simple encoding instead of encryption',
                        'severity': 'Medium',
                        'description': f'Cookie {cookie.name} uses simple encoding'
                    })
        
        # Test API endpoints for encryption info
        api_endpoints = [
            '/admin/api/keys.json',
            '/admin/site_settings.json',
            '/site.json'
        ]
        
        for endpoint in api_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    self._analyze_crypto_config(endpoint, data)
                except json.JSONDecodeError:
                    pass
    
    def _analyze_crypto_config(self, endpoint, data):
        """Analyze cryptographic configuration in JSON data"""
        weak_crypto_indicators = [
            'des', 'rc4', 'md5', 'sha1', 'ecb', 'cbc_without_iv'
        ]
        
        def search_crypto_config(obj, path=''):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    # Check key names for crypto indicators
                    if any(indicator in key.lower() for indicator in ['encrypt', 'cipher', 'hash', 'crypto']):
                        if isinstance(value, str):
                            for weak_indicator in weak_crypto_indicators:
                                if weak_indicator in value.lower():
                                    self.results['weak_encryption'].append({
                                        'endpoint': endpoint,
                                        'config_path': current_path,
                                        'weak_crypto': weak_indicator,
                                        'value': value,
                                        'severity': 'High',
                                        'description': f'Weak cryptographic configuration at {current_path}'
                                    })
                    
                    search_crypto_config(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    search_crypto_config(item, f"{path}[{i}]")
        
        search_crypto_config(data)
    
    def _test_jwt_vulnerabilities(self):
        """Test for JWT vulnerabilities"""
        print(f"{self.scanner.colors['info']}[*] Testing JWT vulnerabilities...{self.scanner.colors['reset']}")
        
        # Look for JWT tokens in responses
        response = make_request(self.scanner.session, 'GET', self.scanner.target_url)
        
        if response:
            # Search for JWT patterns
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
            jwt_tokens = re.findall(jwt_pattern, response.text)
            
            for token in jwt_tokens:
                self._analyze_jwt_token(token)
        
        # Test API endpoints that might return JWTs
        jwt_endpoints = [
            '/session/current.json',
            '/admin/api/keys.json',
            '/auth/jwt',
            '/api/auth/token'
        ]
        
        for endpoint in jwt_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                jwt_tokens = re.findall(jwt_pattern, response.text)
                for token in jwt_tokens:
                    self._analyze_jwt_token(token, endpoint)
    
    def _analyze_jwt_token(self, token, source='unknown'):
        """Analyze JWT token for vulnerabilities"""
        try:
            # Split JWT into parts
            parts = token.split('.')
            if len(parts) != 3:
                return
            
            header_b64, payload_b64, signature_b64 = parts
            
            # Decode header
            try:
                header_padding = header_b64 + '=' * (4 - len(header_b64) % 4)
                header = json.loads(base64.b64decode(header_padding))
            except:
                return
            
            # Decode payload
            try:
                payload_padding = payload_b64 + '=' * (4 - len(payload_b64) % 4)
                payload = json.loads(base64.b64decode(payload_padding))
            except:
                return
            
            # Check for vulnerabilities
            
            # 1. Algorithm confusion
            alg = header.get('alg', '').lower()
            if alg == 'none':
                self.results['jwt_vulnerabilities'].append({
                    'vulnerability': 'None algorithm',
                    'source': source,
                    'severity': 'Critical',
                    'description': 'JWT uses "none" algorithm, allowing signature bypass'
                })
            
            elif alg in ['hs256', 'hs384', 'hs512']:
                # HMAC algorithms - test for weak secrets
                self.results['jwt_vulnerabilities'].append({
                    'vulnerability': 'HMAC algorithm detected',
                    'algorithm': alg,
                    'source': source,
                    'severity': 'Medium',
                    'description': 'JWT uses HMAC algorithm - vulnerable to key confusion attacks'
                })
            
            # 2. Weak claims
            if 'exp' not in payload:
                self.results['jwt_vulnerabilities'].append({
                    'vulnerability': 'No expiration claim',
                    'source': source,
                    'severity': 'Medium',
                    'description': 'JWT lacks expiration claim (exp)'
                })
            
            # 3. Sensitive information in payload
            sensitive_keys = ['password', 'secret', 'key', 'token', 'private']
            for key in payload.keys():
                if any(sensitive in key.lower() for sensitive in sensitive_keys):
                    self.results['jwt_vulnerabilities'].append({
                        'vulnerability': 'Sensitive information in payload',
                        'claim': key,
                        'source': source,
                        'severity': 'High',
                        'description': f'JWT payload contains sensitive claim: {key}'
                    })
            
            # 4. Test algorithm confusion attack
            self._test_jwt_algorithm_confusion(token, header, payload)
            
        except Exception as e:
            pass
    
    def _test_jwt_algorithm_confusion(self, original_token, header, payload):
        """Test JWT algorithm confusion attack"""
        try:
            # Create a new JWT with 'none' algorithm
            none_header = header.copy()
            none_header['alg'] = 'none'
            
            # Encode new header and payload
            new_header_b64 = base64.b64encode(json.dumps(none_header).encode()).decode().rstrip('=')
            new_payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            
            # Create token with no signature
            none_token = f"{new_header_b64}.{new_payload_b64}."
            
            # Test the modified token
            test_endpoints = [
                '/admin/dashboard',
                '/admin/users.json',
                '/api/user/current'
            ]
            
            for endpoint in test_endpoints:
                url = urljoin(self.scanner.target_url, endpoint)
                headers = {'Authorization': f'Bearer {none_token}'}
                response = make_request(self.scanner.session, 'GET', url, headers=headers)
                
                if response and response.status_code == 200:
                    self.results['jwt_vulnerabilities'].append({
                        'vulnerability': 'Algorithm confusion attack successful',
                        'endpoint': endpoint,
                        'severity': 'Critical',
                        'description': f'JWT algorithm confusion attack succeeded at {endpoint}'
                    })
                    break
                    
        except Exception:
            pass
    
    def _test_session_security(self):
        """Test session security implementation"""
        print(f"{self.scanner.colors['info']}[*] Testing session security...{self.scanner.colors['reset']}")
        
        # Get initial session
        response = make_request(self.scanner.session, 'GET', self.scanner.target_url)
        
        if response:
            session_cookies = []
            
            for cookie in response.cookies:
                if any(keyword in cookie.name.lower() for keyword in ['session', 'auth', 'token']):
                    session_cookies.append(cookie)
            
            for cookie in session_cookies:
                # Test session cookie security
                cookie_analysis = {
                    'cookie_name': cookie.name,
                    'issues': []
                }
                
                # Check secure flag
                if not cookie.secure:
                    cookie_analysis['issues'].append({
                        'issue': 'Missing Secure flag',
                        'severity': 'Medium',
                        'description': 'Session cookie lacks Secure flag'
                    })
                
                # Check HttpOnly flag
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    cookie_analysis['issues'].append({
                        'issue': 'Missing HttpOnly flag',
                        'severity': 'High',
                        'description': 'Session cookie lacks HttpOnly flag'
                    })
                
                # Check SameSite attribute
                samesite = cookie.get_nonstandard_attr('SameSite')
                if not samesite or samesite.lower() not in ['strict', 'lax']:
                    cookie_analysis['issues'].append({
                        'issue': 'Missing or weak SameSite attribute',
                        'severity': 'Medium',
                        'description': 'Session cookie lacks proper SameSite protection'
                    })
                
                # Analyze session ID entropy
                session_id = cookie.value
                entropy_analysis = self._analyze_session_entropy(session_id)
                if entropy_analysis:
                    cookie_analysis['issues'].append(entropy_analysis)
                
                if cookie_analysis['issues']:
                    self.results['session_security'].append(cookie_analysis)
        
        # Test session fixation
        self._test_session_fixation()
        
        # Test session hijacking resistance
        self._test_session_hijacking()
    
    def _analyze_session_entropy(self, session_id):
        """Analyze session ID entropy"""
        if len(session_id) < 16:
            return {
                'issue': 'Short session ID',
                'length': len(session_id),
                'severity': 'High',
                'description': f'Session ID too short: {len(session_id)} characters'
            }
        
        # Check for patterns
        if session_id.isdigit():
            return {
                'issue': 'Numeric-only session ID',
                'severity': 'High',
                'description': 'Session ID contains only digits'
            }
        
        # Check for sequential patterns
        if self._has_sequential_pattern(session_id):
            return {
                'issue': 'Sequential pattern in session ID',
                'severity': 'Medium',
                'description': 'Session ID contains sequential patterns'
            }
        
        return None
    
    def _has_sequential_pattern(self, session_id):
        """Check for sequential patterns in session ID"""
        # Convert to lowercase for analysis
        sid = session_id.lower()
        
        # Check for consecutive characters
        consecutive_count = 0
        for i in range(len(sid) - 1):
            if ord(sid[i+1]) == ord(sid[i]) + 1:
                consecutive_count += 1
                if consecutive_count >= 3:  # 4 consecutive chars
                    return True
            else:
                consecutive_count = 0
        
        return False
    
    def _test_session_fixation(self):
        """Test for session fixation vulnerabilities"""
        # Get initial session ID
        response1 = make_request(self.scanner.session, 'GET', self.scanner.target_url)
        initial_session = None
        
        if response1:
            for cookie in response1.cookies:
                if 'session' in cookie.name.lower():
                    initial_session = cookie.value
                    break
        
        if initial_session:
            # Attempt login (this would normally change session ID)
            login_url = urljoin(self.scanner.target_url, '/session')
            csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
            
            login_data = {
                'login': 'test@example.com',
                'password': 'testpassword',
                'authenticity_token': csrf_token
            }
            
            response2 = make_request(self.scanner.session, 'POST', login_url, data=login_data)
            
            if response2:
                # Check if session ID changed
                new_session = None
                for cookie in response2.cookies:
                    if 'session' in cookie.name.lower():
                        new_session = cookie.value
                        break
                
                if new_session and new_session == initial_session:
                    self.results['session_security'].append({
                        'vulnerability': 'Session fixation',
                        'severity': 'High',
                        'description': 'Session ID does not change after login attempt'
                    })
    
    def _test_session_hijacking(self):
        """Test session hijacking resistance"""
        # Test if session works from different IP (simulated)
        # This is a simplified test - in reality, you'd need different IPs
        
        # Test with different User-Agent
        original_ua = self.scanner.session.headers.get('User-Agent', '')
        
        # Change User-Agent
        self.scanner.session.headers['User-Agent'] = 'DifferentBrowser/1.0'
        
        response = make_request(self.scanner.session, 'GET', self.scanner.target_url)
        
        # Restore original User-Agent
        self.scanner.session.headers['User-Agent'] = original_ua
        
        if response and response.status_code == 200:
            # Check if session is still valid (this is a basic test)
            if 'login' not in response.text.lower():
                self.results['session_security'].append({
                    'vulnerability': 'Weak session binding',
                    'severity': 'Medium',
                    'description': 'Session not properly bound to client characteristics'
                })
    
    def _analyze_csrf_protection(self):
        """Analyze CSRF protection implementation"""
        print(f"{self.scanner.colors['info']}[*] Analyzing CSRF protection...{self.scanner.colors['reset']}")
        
        # Get CSRF token
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        if csrf_token:
            # Analyze CSRF token
            token_analysis = {
                'token_present': True,
                'token_length': len(csrf_token),
                'issues': []
            }
            
            # Check token length
            if len(csrf_token) < 16:
                token_analysis['issues'].append({
                    'issue': 'Short CSRF token',
                    'severity': 'Medium',
                    'description': f'CSRF token too short: {len(csrf_token)} characters'
                })
            
            # Check if token is predictable
            if csrf_token.isdigit() or csrf_token.isalpha():
                token_analysis['issues'].append({
                    'issue': 'Predictable CSRF token',
                    'severity': 'High',
                    'description': 'CSRF token uses predictable pattern'
                })
            
            # Test CSRF token reuse
            self._test_csrf_token_reuse(csrf_token)
            
            # Test CSRF bypass techniques
            self._test_csrf_bypass()
            
            self.results['csrf_analysis'].append(token_analysis)
        else:
            self.results['csrf_analysis'].append({
                'token_present': False,
                'severity': 'Critical',
                'description': 'No CSRF protection detected'
            })
    
    def _test_csrf_token_reuse(self, csrf_token):
        """Test if CSRF tokens can be reused"""
        # Make multiple requests with the same token
        test_url = urljoin(self.scanner.target_url, '/session')
        
        for i in range(3):
            data = {
                'authenticity_token': csrf_token,
                'test_param': f'test_value_{i}'
            }
            
            response = make_request(self.scanner.session, 'POST', test_url, data=data)
            
            if response and response.status_code == 200:
                if i > 0:  # Second or third request
                    self.results['csrf_analysis'].append({
                        'vulnerability': 'CSRF token reuse',
                        'severity': 'Medium',
                        'description': 'CSRF token can be reused multiple times'
                    })
                    break
    
    def _test_csrf_bypass(self):
        """Test CSRF bypass techniques"""
        bypass_tests = [
            {
                'name': 'Empty token',
                'token': '',
                'description': 'CSRF protection bypassed with empty token'
            },
            {
                'name': 'Invalid token',
                'token': 'invalid_token_123',
                'description': 'CSRF protection bypassed with invalid token'
            },
            {
                'name': 'Wrong parameter name',
                'token': 'csrf_token',  # Wrong parameter name
                'description': 'CSRF protection bypassed with wrong parameter name'
            }
        ]
        
        test_url = urljoin(self.scanner.target_url, '/session')
        
        for test in bypass_tests:
            data = {
                'authenticity_token': test['token'],
                'test_param': 'test_value'
            }
            
            response = make_request(self.scanner.session, 'POST', test_url, data=data)
            
            if response and response.status_code == 200 and 'error' not in response.text.lower():
                self.results['csrf_analysis'].append({
                    'vulnerability': f'CSRF bypass: {test["name"]}',
                    'severity': 'High',
                    'description': test['description']
                })
    
    def _test_crypto_misconfig(self):
        """Test for cryptographic misconfigurations"""
        print(f"{self.scanner.colors['info']}[*] Testing crypto misconfiguration...{self.scanner.colors['reset']}")
        
        # Test SSL/TLS configuration
        response = make_request(self.scanner.session, 'GET', self.scanner.target_url)
        
        if response:
            # Check for weak SSL ciphers in headers
            server_header = response.headers.get('Server', '')
            if 'RC4' in server_header or 'DES' in server_header:
                self.results['crypto_misconfig'].append({
                    'issue': 'Weak cipher advertised',
                    'header': server_header,
                    'severity': 'High',
                    'description': 'Server advertises weak cryptographic ciphers'
                })
        
        # Test for hardcoded cryptographic values
        config_endpoints = [
            '/assets/application.js',
            '/assets/discourse.js',
            '/.well-known/security.txt'
        ]
        
        for endpoint in config_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                # Look for hardcoded keys/secrets
                hardcoded_patterns = [
                    r'secret[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9+/=]{20,}',
                    r'api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9+/=]{20,}',
                    r'private[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9+/=]{20,}'
                ]
                
                for pattern in hardcoded_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    if matches:
                        self.results['crypto_misconfig'].append({
                            'issue': 'Hardcoded cryptographic material',
                            'endpoint': endpoint,
                            'matches': len(matches),
                            'severity': 'Critical',
                            'description': f'Hardcoded cryptographic keys found in {endpoint}'
                        })
    
    def _test_key_exposure(self):
        """Test for cryptographic key exposure"""
        print(f"{self.scanner.colors['info']}[*] Testing key exposure...{self.scanner.colors['reset']}")
        
        # Common paths where keys might be exposed
        key_paths = [
            '/.env',
            '/config/secrets.yml',
            '/config/application.yml',
            '/private.key',
            '/server.key',
            '/ssl.key',
            '/id_rsa',
            '/id_dsa',
            '/.ssh/id_rsa',
            '/backup/keys/',
            '/keys/',
            '/certs/'
        ]
        
        for path in key_paths:
            url = urljoin(self.scanner.target_url, path)
            response = make_request(self.scanner.session, 'GET', url)
            
            if response and response.status_code == 200:
                content = response.text
                
                # Check for private key patterns
                key_patterns = [
                    r'-----BEGIN (RSA )?PRIVATE KEY-----',
                    r'-----BEGIN DSA PRIVATE KEY-----',
                    r'-----BEGIN EC PRIVATE KEY-----',
                    r'-----BEGIN OPENSSH PRIVATE KEY-----'
                ]
                
                for pattern in key_patterns:
                    if re.search(pattern, content):
                        self.results['key_exposure'].append({
                            'path': path,
                            'key_type': 'Private Key',
                            'severity': 'Critical',
                            'description': f'Private key exposed at {path}'
                        })
                        break
                
                # Check for API keys and secrets
                secret_patterns = [
                    r'secret_key_base\s*[:=]\s*["\']([a-zA-Z0-9+/=]{40,})',
                    r'api_key\s*[:=]\s*["\']([a-zA-Z0-9+/=]{20,})',
                    r'aws_secret_access_key\s*[:=]\s*["\']([a-zA-Z0-9+/=]{20,})'
                ]
                
                for pattern in secret_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        self.results['key_exposure'].append({
                            'path': path,
                            'key_type': 'Secret Key',
                            'count': len(matches),
                            'severity': 'Critical',
                            'description': f'Secret keys exposed at {path}'
                        })
    
    def _test_randomness(self):
        """Test randomness quality"""
        print(f"{self.scanner.colors['info']}[*] Testing randomness quality...{self.scanner.colors['reset']}")
        
        # Collect multiple CSRF tokens to analyze randomness
        tokens = []
        
        for i in range(10):
            # Get fresh session
            temp_session = self.scanner.session.__class__()
            token = extract_csrf_token(temp_session, self.scanner.target_url)
            if token:
                tokens.append(token)
            time.sleep(0.5)
        
        if len(tokens) >= 5:
            # Analyze token randomness
            randomness_analysis = self._analyze_token_randomness(tokens)
            if randomness_analysis:
                self.results['random_analysis'].append(randomness_analysis)
    
    def _analyze_token_randomness(self, tokens):
        """Analyze randomness of tokens"""
        issues = []
        
        # Check for duplicate tokens
        if len(tokens) != len(set(tokens)):
            issues.append({
                'issue': 'Duplicate tokens generated',
                'severity': 'Critical',
                'description': 'Random number generator produces duplicate values'
            })
        
        # Check for sequential patterns
        for i, token in enumerate(tokens):
            if i > 0:
                # Compare with previous token
                similarity = self._calculate_similarity(tokens[i-1], token)
                if similarity > 0.8:  # 80% similarity
                    issues.append({
                        'issue': 'High similarity between tokens',
                        'similarity': f'{similarity*100:.1f}%',
                        'severity': 'High',
                        'description': 'Consecutive tokens show high similarity'
                    })
                    break
        
        # Check character distribution
        all_chars = ''.join(tokens)
        char_freq = {}
        for char in all_chars:
            char_freq[char] = char_freq.get(char, 0) + 1
        
        # Check for biased character distribution
        total_chars = len(all_chars)
        expected_freq = total_chars / len(set(all_chars))
        
        for char, freq in char_freq.items():
            if freq > expected_freq * 2:  # More than 2x expected frequency
                issues.append({
                    'issue': 'Biased character distribution',
                    'biased_char': char,
                    'frequency': freq,
                    'severity': 'Medium',
                    'description': f'Character "{char}" appears {freq} times (bias detected)'
                })
                break
        
        return {
            'tokens_analyzed': len(tokens),
            'issues': issues
        } if issues else None
    
    def _calculate_similarity(self, str1, str2):
        """Calculate similarity between two strings"""
        if len(str1) != len(str2):
            return 0.0
        
        matches = sum(1 for a, b in zip(str1, str2) if a == b)
        return matches / len(str1)
    
    def _test_signature_bypass(self):
        """Test for signature bypass vulnerabilities"""
        print(f"{self.scanner.colors['info']}[*] Testing signature bypass...{self.scanner.colors['reset']}")
        
        # Test API endpoints that might use signatures
        api_endpoints = [
            '/admin/api/keys',
            '/webhooks/receive',
            '/api/auth/callback'
        ]
        
        for endpoint in api_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            
            # Test without signature
            response1 = make_request(self.scanner.session, 'POST', url, data={'test': 'data'})
            
            # Test with invalid signature
            headers = {'X-Signature': 'invalid_signature'}
            response2 = make_request(self.scanner.session, 'POST', url, data={'test': 'data'}, headers=headers)
            
            # Test with empty signature
            headers = {'X-Signature': ''}
            response3 = make_request(self.scanner.session, 'POST', url, data={'test': 'data'}, headers=headers)
            
            # Analyze responses
            if response1 and response1.status_code == 200:
                self.results['signature_bypass'].append({
                    'endpoint': endpoint,
                    'bypass_method': 'No signature required',
                    'severity': 'High',
                    'description': f'Endpoint {endpoint} accepts requests without signature'
                })
            
            if response2 and response2.status_code == 200:
                self.results['signature_bypass'].append({
                    'endpoint': endpoint,
                    'bypass_method': 'Invalid signature accepted',
                    'severity': 'Critical',
                    'description': f'Endpoint {endpoint} accepts invalid signatures'
                })
    
    def _test_timing_attacks(self):
        """Test for timing attack vulnerabilities"""
        print(f"{self.scanner.colors['info']}[*] Testing timing attacks...{self.scanner.colors['reset']}")
        
        # Test login endpoint for timing differences
        login_url = urljoin(self.scanner.target_url, '/session')
        csrf_token = extract_csrf_token(self.scanner.session, self.scanner.target_url)
        
        if csrf_token:
            # Test with valid username, invalid password
            valid_user_times = []
            for i in range(5):
                start_time = time.time()
                
                data = {
                    'login': 'admin',  # Common username
                    'password': 'wrong_password',
                    'authenticity_token': csrf_token
                }
                
                response = make_request(self.scanner.session, 'POST', login_url, data=data)
                end_time = time.time()
                
                if response:
                    valid_user_times.append(end_time - start_time)
                
                time.sleep(1)
            
            # Test with invalid username
            invalid_user_times = []
            for i in range(5):
                start_time = time.time()
                
                data = {
                    'login': 'nonexistent_user_12345',
                    'password': 'wrong_password',
                    'authenticity_token': csrf_token
                }
                
                response = make_request(self.scanner.session, 'POST', login_url, data=data)
                end_time = time.time()
                
                if response:
                    invalid_user_times.append(end_time - start_time)
                
                time.sleep(1)
            
            # Analyze timing differences
            if valid_user_times and invalid_user_times:
                avg_valid = sum(valid_user_times) / len(valid_user_times)
                avg_invalid = sum(invalid_user_times) / len(invalid_user_times)
                
                time_diff = abs(avg_valid - avg_invalid)
                
                if time_diff > 0.1:  # 100ms difference
                    self.results['timing_attacks'].append({
                        'endpoint': '/session',
                        'vulnerability': 'Username enumeration via timing',
                        'time_difference': f'{time_diff:.3f}s',
                        'severity': 'Medium',
                        'description': f'Login timing differs by {time_diff:.3f}s between valid and invalid usernames'
                    })
    
    def _is_base64(self, s):
        """Check if string is base64 encoded"""
        try:
            if len(s) % 4 == 0:
                base64.b64decode(s)
                return True
        except:
            pass
        return False
    
    def _is_simple_encoding(self, s):
        """Check if string uses simple encoding (hex, base64, etc.)"""
        # Check for hex encoding
        if re.match(r'^[a-fA-F0-9]+$', s) and len(s) % 2 == 0:
            return True
        
        # Check for URL encoding
        if '%' in s and re.search(r'%[0-9a-fA-F]{2}', s):
            return True
        
        return False