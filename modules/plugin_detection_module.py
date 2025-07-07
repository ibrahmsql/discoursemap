#!/usr/bin/env python3
"""
Discoursemap - Plugin Detection Module

plugin and technology detection using fingerprinting techniques

"""

import re
import json
import hashlib
import requests
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
            'fingerprints': []
        }
        
        # Plugin detection signatures
        self.plugin_signatures = {
            'discourse-chat-integration': {
                'files': ['/plugins/discourse-chat-integration/assets/javascripts/discourse-chat-integration.js'],
                'html_patterns': [r'data-chat-integration', r'chat-integration-provider'],
                'js_patterns': [r'ChatIntegration', r'discourse-chat-integration']
            },
            'discourse-solved': {
                'files': ['/plugins/discourse-solved/assets/javascripts/discourse-solved.js'],
                'html_patterns': [r'accepted-answer', r'solved-status'],
                'js_patterns': [r'DiscourseSolved', r'accepted_answer']
            },
            'discourse-voting': {
                'files': ['/plugins/discourse-voting/assets/javascripts/discourse-voting.js'],
                'html_patterns': [r'voting-wrapper', r'vote-count'],
                'js_patterns': [r'DiscourseVoting', r'vote-button']
            },
            'discourse-calendar': {
                'files': ['/plugins/discourse-calendar/assets/javascripts/discourse-calendar.js'],
                'html_patterns': [r'discourse-calendar', r'calendar-event'],
                'js_patterns': [r'DiscourseCalendar', r'calendar-widget']
            },
            'discourse-data-explorer': {
                'files': ['/plugins/discourse-data-explorer/assets/javascripts/discourse-data-explorer.js'],
                'html_patterns': [r'data-explorer', r'query-result'],
                'js_patterns': [r'DataExplorer', r'discourse-data-explorer']
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
            'discourse-saml': {
                'files': ['/auth/saml/callback', '/auth/saml/metadata'],
                'html_patterns': [r'saml-auth', r'saml-login'],
                'js_patterns': [r'SamlAuth']
            },
            'discourse-ldap-auth': {
                'files': ['/auth/ldap/callback'],
                'html_patterns': [r'ldap-auth', r'ldap-login'],
                'js_patterns': [r'LdapAuth']
            },
            'discourse-akismet': {
                'files': ['/plugins/discourse-akismet/assets/javascripts/discourse-akismet.js'],
                'html_patterns': [r'akismet-spam', r'spam-detection'],
                'js_patterns': [r'Akismet', r'spam-checker']
            },
            'discourse-math': {
                'files': ['/plugins/discourse-math/assets/javascripts/discourse-math.js'],
                'html_patterns': [r'math-container', r'katex', r'mathjax'],
                'js_patterns': [r'DiscourseMath', r'math-renderer']
            },
            'discourse-spoiler-alert': {
                'files': ['/plugins/discourse-spoiler-alert/assets/javascripts/discourse-spoiler-alert.js'],
                'html_patterns': [r'spoiler-alert', r'spoiled'],
                'js_patterns': [r'SpoilerAlert', r'spoiler-wrapper']
            },
            'discourse-checklist': {
                'files': ['/plugins/discourse-checklist/assets/javascripts/discourse-checklist.js'],
                'html_patterns': [r'checklist-item', r'task-list'],
                'js_patterns': [r'DiscourseChecklist', r'checklist-widget']
            },
            'discourse-assign': {
                'files': ['/plugins/discourse-assign/assets/javascripts/discourse-assign.js'],
                'html_patterns': [r'assigned-to', r'assignment-wrapper'],
                'js_patterns': [r'DiscourseAssign', r'assign-user']
            }
        }
        
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
    
    def run(self):
        """Run complete plugin detection scan"""
        # Removed print statement for cleaner output
        
        # Ana sayfa analizi
        self._analyze_main_page()
        
        # Plugin tespiti
        self._detect_plugins()
        
        # Tema tespiti
        self._detect_themes()
        
        # Teknoloji stack tespiti
        self._detect_technology_stack()
        
        # JavaScript kütüphaneleri
        self._detect_javascript_libraries()
        
        # CSS frameworks
        self._detect_css_frameworks()
        
        # Server information
        self._gather_server_info()
        
        # Meta information
        self._extract_meta_information()
        
        # Fingerprint generation
        self._generate_fingerprints()
        
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
    
    def _detect_plugins(self):
        """Detect installed plugins using various techniques"""
        # Removed print statement for cleaner output
        
        for plugin_name, signatures in self.plugin_signatures.items():
            detection_methods = []
            confidence = 0
            
            # File-based detection
            if 'files' in signatures:
                for file_path in signatures['files']:
                    file_url = urljoin(self.scanner.target_url, file_path)
                    response = make_request(self.scanner.session, 'GET', file_url)
                    if response and response.status_code == 200:
                        detection_methods.append(f'file:{file_path}')
                        confidence += 30
            
            # HTML pattern detection
            if 'html_patterns' in signatures and hasattr(self, 'main_page_content'):
                for pattern in signatures['html_patterns']:
                    if re.search(pattern, self.main_page_content, re.IGNORECASE):
                        detection_methods.append(f'html_pattern:{pattern}')
                        confidence += 20
            
            # JavaScript pattern detection
            if 'js_patterns' in signatures and hasattr(self, 'main_page_content'):
                for pattern in signatures['js_patterns']:
                    if re.search(pattern, self.main_page_content, re.IGNORECASE):
                        detection_methods.append(f'js_pattern:{pattern}')
                        confidence += 25
            
            # Response header detection
            if 'response_headers' in signatures and hasattr(self, 'main_page_headers'):
                for header in signatures['response_headers']:
                    if header.lower() in [h.lower() for h in self.main_page_headers.keys()]:
                        detection_methods.append(f'header:{header}')
                        confidence += 35
            
            # Plugin detected if confidence > 20
            if confidence > 20:
                plugin_info = {
                    'name': plugin_name,
                    'confidence': confidence,
                    'detection_methods': detection_methods,
                    'version': self._detect_plugin_version(plugin_name),
                    'status': 'detected'
                }
                self.results['detected_plugins'].append(plugin_info)
                print(f"{Fore.GREEN}[+] Plugin detected: {plugin_name} (confidence: {confidence}%){Style.RESET_ALL}")
    
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
    
    def _detect_plugin_version(self, plugin_name):
        """Detect plugin version"""
        # Try to get version from plugin file
        plugin_js_url = urljoin(self.scanner.target_url, f'/plugins/{plugin_name}/assets/javascripts/{plugin_name}.js')
        response = make_request(self.scanner.session, 'GET', plugin_js_url)
        
        if response and response.status_code == 200:
            # Look for version patterns
            version_patterns = [
                r'version["\']?\s*[:=]\s*["\']([^"\'\']+)["\']',
                r'VERSION\s*=\s*["\']([^"\'\']+)["\']',
                r'@version\s+([\d\.]+)'
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        return 'Unknown'
    
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