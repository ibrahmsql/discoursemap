#!/usr/bin/env python3
"""
Discourse Asset File Security Checker Module

Specialized security scanner for Discourse forum asset files.
Checks JavaScript, CSS, and other asset files for security vulnerabilities
specific to Discourse platform installations.

Author: ibrahimsql
Platform: Discourse Forum Security Scanner
"""

import requests
import os
import re
from urllib.parse import urljoin, urlparse
from .malicious_pattern_checker import MaliciousPatternChecker

class AssetFileChecker:
    """Checks asset files for security vulnerabilities and malicious content"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.malicious_checker = MaliciousPatternChecker()
        self.results = {
            'module_name': 'Asset File Security Checker',
            'target': scanner.target_url,
            'asset_files': [],
            'security_issues': [],
            'malicious_patterns': [],
            'external_resources': [],
            'obfuscated_files': [],
            'sensitive_data': [],
            'total_files_checked': 0,
            'scan_time': 0
        }
    
    def run(self):
        """Run  asset file security check"""
        print("\n[*] Starting  asset file security check...")
        
        try:
            # Get main page content
            response = self.session.get(self.scanner.target_url, timeout=10)
            if response.status_code != 200:
                print(f"[!] Could not access target URL: {response.status_code}")
                return self.results
            
            # Extract asset files from main page
            asset_files = self._extract_asset_files(response.text, self.scanner.target_url)
            
            # Check each asset file
            for asset_file in asset_files:
                self._check_asset_file(asset_file)
            
            # Generate summary
            self.results['summary'] = self._generate_summary()
            
        except Exception as e:
            print(f"[!] Error in asset file checker: {e}")
        
        return self.results
    
    def check_asset_files(self):
        """Check  asset files for security issues"""
        try:
            # Get main page
            response = self.session.get(self.scanner.target_url, timeout=10)
            if not response or response.status_code != 200:
                return []
            
            # Extract asset files
            asset_files = self._extract_asset_files(response.text, self.scanner.target_url)
            
            all_issues = []
            
            for asset_file in asset_files:
                try:
                    asset_url = urljoin(self.scanner.target_url, asset_file)
                    asset_response = self.session.get(asset_url, timeout=10)
                    
                    if asset_response.status_code == 200:
                        issues = self._check_asset_content(asset_file, asset_response.text, asset_url)
                        all_issues.extend(issues)
                        
                        self.results['asset_files'].append({
                            'file': asset_file,
                            'url': asset_url,
                            'size': len(asset_response.content),
                            'content_type': asset_response.headers.get('Content-Type', ''),
                            'issues_found': len(issues)
                        })
                        
                        self.results['total_files_checked'] += 1
                        
                except Exception as e:
                    print(f"[!] Error checking asset file {asset_file}: {e}")
                    continue
            
            self.results['security_issues'] = all_issues
            return all_issues
            
        except Exception as e:
            print(f"[!] Error in asset file checking: {e}")
            return []
    
    def _extract_asset_files(self, content, base_path):
        """Extract  asset file URLs from HTML content"""
        asset_files = set()
        
        # JavaScript files
        js_pattern = r'<script[^>]+src=["\']([^"\'>]+)["\'][^>]*>'
        js_matches = re.findall(js_pattern, content, re.IGNORECASE)
        asset_files.update(js_matches)
        
        # CSS files
        css_pattern = r'<link[^>]+href=["\']([^"\'>]+\.css[^"\'>]*)["\'][^>]*>'
        css_matches = re.findall(css_pattern, content, re.IGNORECASE)
        asset_files.update(css_matches)
        
        # Filter out external URLs and keep only relative paths
        filtered_assets = []
        for asset in asset_files:
            if not asset.startswith(('http://', 'https://', '//', 'data:')):
                filtered_assets.append(asset)
        
        return filtered_assets
    
    def _check_asset_content(self, asset_file, content, url):
        """Check asset file content for security issues"""
        issues = []
        
        # Check for malicious patterns
        malicious_results = self.malicious_checker.check_content(content)
        for result in malicious_results:
            if result['risk_level'] in ['High', 'Critical']:
                issues.append({
                    'type': 'malicious_pattern',
                    'file': asset_file,
                    'url': url,
                    'severity': result['risk_level'],
                    'description': result['description'],
                    'pattern': result['pattern_type']
                })
        
        # Check for obfuscated code
        obfuscation_indicators = [
            r'[a-zA-Z0-9]{50,}',
            r'\\x[0-9a-fA-F]{2}',
            r'\\u[0-9a-fA-F]{4}',
            r'String\.fromCharCode\s*\(',
            r'eval\s*\(',
            r'Function\s*\(',
            r'[a-zA-Z_$][a-zA-Z0-9_$]*\[\s*["\'][^"\'\'\n\r]{1,3}["\']\s*\]'
        ]
        
        obfuscation_score = 0
        for pattern in obfuscation_indicators:
            matches = re.findall(pattern, content)
            obfuscation_score += len(matches)
        
        if obfuscation_score > 10:
            issues.append({
                'type': 'obfuscated_code',
                'file': asset_file,
                'url': url,
                'severity': 'High',
                'description': f'Asset file appears to contain obfuscated code (score: {obfuscation_score})',
                'obfuscation_score': obfuscation_score
            })
        
        # Check for external resource loading
        external_patterns = [
            r'src\s*=\s*["\']https?://[^"\'\'\\n\\r]+["\']',
            r'href\s*=\s*["\']https?://[^"\'\'\\n\\r]+["\']',
            r'url\s*\(\s*["\']?https?://[^"\')\\n\\r]+["\']?\)',
            r'@import\s+["\']https?://[^"\'\'\\n\\r]+["\']'
        ]
        
        for pattern in external_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                issues.append({
                    'type': 'external_resource',
                    'file': asset_file,
                    'url': url,
                    'severity': 'Low',
                    'description': f'Asset file loads external resource: {match}',
                    'resource': match
                })
        
        # Check for hardcoded credentials or sensitive data
        sensitive_patterns = [
            r'password\s*[=:]\s*["\'][^"\'\'\\n\\r]{6,}["\']',
            r'api_key\s*[=:]\s*["\'][^"\'\'\\n\\r]{16,}["\']',
            r'secret\s*[=:]\s*["\'][^"\'\'\\n\\r]{16,}["\']',
            r'token\s*[=:]\s*["\'][^"\'\'\\n\\r]{16,}["\']',
            r'key\s*[=:]\s*["\'][^"\'\'\\n\\r]{16,}["\']'
        ]
        
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                issues.append({
                    'type': 'sensitive_data',
                    'file': asset_file,
                    'url': url,
                    'severity': 'High',
                    'description': f'Asset file contains potential sensitive data: {match[:50]}...',
                    'data_type': 'credentials'
                })
        
        # Check for suspicious function calls
        suspicious_functions = [
            r'eval\s*\(',
            r'Function\s*\(',
            r'setTimeout\s*\([^,]*["\'][^"\'\'\\]*["\']',
            r'setInterval\s*\([^,]*["\'][^"\'\'\\]*["\']',
            r'document\.write\s*\(',
            r'innerHTML\s*=\s*[^;]+'
        ]
        
        for pattern in suspicious_functions:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                issues.append({
                    'type': 'suspicious_function',
                    'file': asset_file,
                    'url': url,
                    'severity': 'Medium',
                    'description': f'Asset file uses potentially dangerous function: {pattern}',
                    'function_count': len(matches)
                })
        
        return issues
    
    def _check_asset_file(self, asset_file):
        """Check individual asset file"""
        try:
            asset_url = urljoin(self.scanner.target_url, asset_file)
            response = self.session.get(asset_url, timeout=10)
            
            if response.status_code == 200:
                # Basic file info
                file_info = {
                    'file': asset_file,
                    'url': asset_url,
                    'size': len(response.content),
                    'content_type': response.headers.get('Content-Type', ''),
                    'status_code': response.status_code
                }
                
                # Security checks
                issues = self._check_asset_content(asset_file, response.text, asset_url)
                file_info['issues'] = issues
                file_info['issue_count'] = len(issues)
                
                self.results['asset_files'].append(file_info)
                self.results['total_files_checked'] += 1
                
                if issues:
                    print(f"[!] Found {len(issues)} issues in {asset_file}")
                
        except Exception as e:
            print(f"[!] Error checking asset file {asset_file}: {e}")
    
    def get_asset_security_summary(self, all_issues):
        """Generate security summary for asset files"""
        summary = {
            'total_issues': len(all_issues),
            'critical_issues': len([i for i in all_issues if i.get('severity') == 'Critical']),
            'high_issues': len([i for i in all_issues if i.get('severity') == 'High']),
            'medium_issues': len([i for i in all_issues if i.get('severity') == 'Medium']),
            'low_issues': len([i for i in all_issues if i.get('severity') == 'Low']),
            'issue_types': {
                'malicious_patterns': len([i for i in all_issues if i.get('type') == 'malicious_pattern']),
                'obfuscated_code': len([i for i in all_issues if i.get('type') == 'obfuscated_code']),
                'external_resources': len([i for i in all_issues if i.get('type') == 'external_resource']),
                'sensitive_data': len([i for i in all_issues if i.get('type') == 'sensitive_data']),
                'suspicious_functions': len([i for i in all_issues if i.get('type') == 'suspicious_function'])
            }
        }
        
        return summary
    
    def analyze_javascript_endpoints(self):
        """Analyze JavaScript files for endpoint references"""
        js_files = [
            '/js/app.js', '/js/main.js', '/js/script.js',
            '/assets/js/app.js', '/static/js/main.js',
            '/public/js/app.js', '/dist/js/app.js'
        ]
        
        found_endpoints = []
        
        for js_file in js_files:
            try:
                url = urljoin(self.scanner.target_url, js_file)
                js_response = self.session.get(url, timeout=10)
            
                if js_response and js_response.status_code == 200:
                    # Look for API endpoints in JavaScript
                    endpoint_patterns = [
                        r'["\']([a-zA-Z0-9/_-]+\.json)["\']',
                        r'["\'](\/api\/[a-zA-Z0-9/_-]+)["\']',
                        r'["\'](\/admin\/[a-zA-Z0-9/_-]+)["\']',
                        r'url:\s*["\']([^"\'\'\\]+)["\']',
                        r'endpoint:\s*["\']([^"\'\'\\]+)["\']'
                    ]
                    
                    for pattern in endpoint_patterns:
                        endpoints = re.findall(pattern, js_response.text)
                        for endpoint in endpoints[:10]:  # Limit endpoints per script
                            if endpoint.startswith('/') and len(endpoint) > 1:
                                found_endpoints.append({
                                    'endpoint': endpoint,
                                    'source_file': js_file,
                                    'url': url
                                })
            
            except Exception:
                continue
        
        return found_endpoints
    
    def analyze_discourse_robots_sitemap(self):
        """Analyze Discourse robots.txt and sitemap for additional endpoints"""
        found_endpoints = []
        
        # Check robots.txt for Discourse-specific paths
        try:
            robots_url = urljoin(self.scanner.target_url, '/robots.txt')
            robots_response = self.session.get(robots_url, timeout=10)
            
            if robots_response.status_code == 200:
                # Extract disallowed paths from robots.txt
                disallow_pattern = r'Disallow:\s*([^\s]+)'
                disallowed_paths = re.findall(disallow_pattern, robots_response.text)
                
                for path in disallowed_paths[:20]:  # Limit to first 20
                    if path.startswith('/') and len(path) > 1:
                        found_endpoints.append({
                            'endpoint': path,
                            'source': 'robots.txt',
                            'type': 'disallowed'
                        })
                
                # Look for sitemap references
                sitemap_pattern = r'Sitemap:\s*([^\s]+)'
                sitemaps = re.findall(sitemap_pattern, robots_response.text)
                
                for sitemap_url in sitemaps[:5]:  # Limit to first 5
                    try:
                        sitemap_response = self.session.get(sitemap_url, timeout=10)
                        if sitemap_response.status_code == 200:
                            # Extract URLs from sitemap
                            url_pattern = r'<loc>([^<]+)</loc>'
                            urls = re.findall(url_pattern, sitemap_response.text)
                            
                            for url in urls[:50]:  # Limit to first 50
                                parsed_url = urlparse(url)
                                if parsed_url.path and parsed_url.path != '/':
                                    found_endpoints.append({
                                        'endpoint': parsed_url.path,
                                        'source': 'sitemap',
                                        'type': 'sitemap_url'
                                    })
                    except Exception:
                        continue
        
        except Exception:
            pass
        
        return found_endpoints

    def _generate_summary(self):
        """Generate scan summary"""
        all_issues = []
        for asset_file in self.results['asset_files']:
            all_issues.extend(asset_file.get('issues', []))
        
        return {
            'total_files_checked': self.results['total_files_checked'],
            'total_issues_found': len(all_issues),
            'files_with_issues': len([f for f in self.results['asset_files'] if f.get('issue_count', 0) > 0]),
            'security_summary': self.get_asset_security_summary(all_issues)
        }