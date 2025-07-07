#!/usr/bin/env python3
"""
Discourse Security Scanner - Information Gathering Module

Collects basic information about the target Discourse forum
"""

import re
import json
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from .utils import extract_discourse_version, extract_csrf_token

class InfoModule:
    """Information gathering module for Discourse forums"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Information Gathering',
            'target': scanner.target_url,
            'discourse_info': {},
            'server_info': {},
            'plugins': [],
            'admin_access': False,
            'users_found': [],
            'categories': [],
            'scan_time': 0
        }
        self.start_time = time.time()
    
    def run(self):
        """Run information gathering module"""
        self.scanner.log("Starting information gathering...")
        
        # Basic Discourse detection and version
        self._detect_discourse_version()
        
        # Server information
        self._gather_server_info()
        
        # Plugin detection
        self._detect_plugins()
        
        # Admin panel detection
        self._check_admin_access()
        
        # User enumeration
        self._enumerate_users()
        
        # Category enumeration
        self._enumerate_categories()
        
        # Site configuration
        self._gather_site_config()
        
        self.results['scan_time'] = time.time() - self.start_time
        return self.results
    
    def _detect_discourse_version(self):
        """Detect Discourse version and basic info"""
        self.scanner.log("Detecting Discourse version...", 'debug')
        
        response = self.scanner.make_request(self.scanner.target_url)
        if not response:
            return
        
        # Extract version from HTML
        version = extract_discourse_version(response.text)
        if version:
            self.results['discourse_info']['version'] = version
            self.scanner.log(f"Discourse version detected: {version}", 'success')
        else:
            self.scanner.log("Could not detect Discourse version", 'warning')
        
        # Check for Discourse indicators
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Meta tags
        generator = soup.find('meta', {'name': 'generator'})
        if generator:
            self.results['discourse_info']['generator'] = generator.get('content')
        
        # Site title
        title = soup.find('title')
        if title:
            self.results['discourse_info']['site_title'] = title.get_text().strip()
        
        # Check for Discourse-specific elements
        discourse_indicators = {
            'ember_app': bool(soup.find('div', {'id': 'ember-app'})),
            'discourse_css': bool(soup.find('link', {'href': re.compile(r'discourse.*\.css')})),
            'discourse_js': bool(soup.find('script', {'src': re.compile(r'discourse.*\.js')})),
            'csrf_token': extract_csrf_token(response.text) is not None
        }
        
        self.results['discourse_info']['indicators'] = discourse_indicators
    
    def _gather_server_info(self):
        """Gather server and hosting information"""
        self.scanner.log("Gathering server information...", 'debug')
        
        response = self.scanner.make_request(self.scanner.target_url)
        if not response:
            return
        
        # Server headers
        headers = dict(response.headers)
        server_info = {
            'server': headers.get('Server', 'Unknown'),
            'powered_by': headers.get('X-Powered-By', 'Unknown'),
            'content_type': headers.get('Content-Type', 'Unknown'),
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds()
        }
        
        # Security headers
        security_headers = {
            'x_frame_options': headers.get('X-Frame-Options'),
            'x_content_type_options': headers.get('X-Content-Type-Options'),
            'x_xss_protection': headers.get('X-XSS-Protection'),
            'strict_transport_security': headers.get('Strict-Transport-Security'),
            'content_security_policy': headers.get('Content-Security-Policy'),
            'referrer_policy': headers.get('Referrer-Policy')
        }
        
        server_info['security_headers'] = security_headers
        self.results['server_info'] = server_info
    
    def _detect_plugins(self):
        """Detect installed Discourse plugins"""
        self.scanner.log("Detecting installed plugins...", 'debug')
        
        # Common plugin endpoints and indicators
        plugin_checks = {
            'chat': '/chat',
            'calendar': '/calendar',
            'bbcode': '/admin/plugins/discourse-bbcode',
            'math': '/admin/plugins/discourse-math',
            'poll': '/admin/plugins/poll',
            'solved': '/admin/plugins/discourse-solved',
            'voting': '/admin/plugins/discourse-voting',
            'assign': '/admin/plugins/discourse-assign',
            'checklist': '/admin/plugins/discourse-checklist',
            'data_explorer': '/admin/plugins/discourse-data-explorer',
            'github': '/admin/plugins/discourse-github',
            'slack': '/admin/plugins/discourse-slack-official'
        }
        
        detected_plugins = []
        
        for plugin_name, endpoint in plugin_checks.items():
            url = urljoin(self.scanner.target_url, endpoint)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                detected_plugins.append({
                    'name': plugin_name,
                    'endpoint': endpoint,
                    'status': 'detected'
                })
                self.scanner.log(f"Plugin detected: {plugin_name}", 'success')
            
            time.sleep(0.1)
        
        # Check main page for plugin indicators
        response = self.scanner.make_request(self.scanner.target_url)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for plugin-specific CSS/JS
            plugin_patterns = {
                'chat': r'discourse-chat',
                'calendar': r'discourse-calendar',
                'bbcode': r'bbcode',
                'math': r'discourse-math',
                'poll': r'poll',
                'solved': r'solved',
                'voting': r'voting'
            }
            
            for plugin_name, pattern in plugin_patterns.items():
                if re.search(pattern, response.text, re.IGNORECASE):
                    if not any(p['name'] == plugin_name for p in detected_plugins):
                        detected_plugins.append({
                            'name': plugin_name,
                            'endpoint': 'detected_in_source',
                            'status': 'likely_installed'
                        })
        
        self.results['plugins'] = detected_plugins
    
    def _check_admin_access(self):
        """Check if admin panel is accessible"""
        self.scanner.log("Checking admin panel access...", 'debug')
        
        admin_endpoints = [
            '/admin',
            '/admin/dashboard',
            '/admin/users',
            '/admin/site_settings'
        ]
        
        for endpoint in admin_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = self.scanner.make_request(url)
            
            if response:
                if response.status_code == 200 and 'admin' in response.text.lower():
                    self.results['admin_access'] = True
                    self.scanner.log(f"Admin panel accessible: {endpoint}", 'warning')
                    break
                elif response.status_code == 403:
                    self.scanner.log(f"Admin panel found but access denied: {endpoint}", 'info')
            
            time.sleep(0.1)
    
    def _enumerate_users(self):
        """Enumerate users from public endpoints"""
        self.scanner.log("Enumerating users...", 'debug')
        
        users_found = []
        
        # Check users directory
        users_url = urljoin(self.scanner.target_url, '/directory_items.json?period=all&order=likes_received')
        response = self.scanner.make_request(users_url)
        
        if response and response.status_code == 200:
            try:
                data = response.json()
                if 'directory_items' in data:
                    for item in data['directory_items'][:10]:  # Limit to first 10
                        user_info = item.get('user', {})
                        if user_info:
                            users_found.append({
                                'username': user_info.get('username'),
                                'name': user_info.get('name'),
                                'avatar_template': user_info.get('avatar_template'),
                                'trust_level': user_info.get('trust_level')
                            })
            except json.JSONDecodeError:
                pass
        
        # Check about page for staff
        about_url = urljoin(self.scanner.target_url, '/about.json')
        response = self.scanner.make_request(about_url)
        
        if response and response.status_code == 200:
            try:
                data = response.json()
                if 'about' in data and 'moderators' in data['about']:
                    for mod in data['about']['moderators']:
                        if not any(u['username'] == mod.get('username') for u in users_found):
                            users_found.append({
                                'username': mod.get('username'),
                                'name': mod.get('name'),
                                'role': 'moderator',
                                'avatar_template': mod.get('avatar_template')
                            })
                
                if 'about' in data and 'admins' in data['about']:
                    for admin in data['about']['admins']:
                        if not any(u['username'] == admin.get('username') for u in users_found):
                            users_found.append({
                                'username': admin.get('username'),
                                'name': admin.get('name'),
                                'role': 'admin',
                                'avatar_template': admin.get('avatar_template')
                            })
            except json.JSONDecodeError:
                pass
        
        self.results['users'] = users_found
        self.results['users_found'] = users_found  # Keep backward compatibility
        if users_found:
            self.scanner.log(f"Found {len(users_found)} users", 'success')
    
    def _enumerate_categories(self):
        """Enumerate forum categories"""
        self.scanner.log("Enumerating categories...", 'debug')
        
        categories_url = urljoin(self.scanner.target_url, '/categories.json')
        response = self.scanner.make_request(categories_url)
        
        categories = []
        
        if response and response.status_code == 200:
            try:
                data = response.json()
                if 'category_list' in data and 'categories' in data['category_list']:
                    for cat in data['category_list']['categories']:
                        categories.append({
                            'id': cat.get('id'),
                            'name': cat.get('name'),
                            'slug': cat.get('slug'),
                            'description': cat.get('description_text'),
                            'topic_count': cat.get('topic_count'),
                            'post_count': cat.get('post_count'),
                            'read_restricted': cat.get('read_restricted', False)
                        })
            except json.JSONDecodeError:
                pass
        
        self.results['categories'] = categories
        if categories:
            self.scanner.log(f"Found {len(categories)} categories", 'success')
    
    def _gather_site_config(self):
        """Gather site configuration information"""
        self.scanner.log("Gathering site configuration...", 'debug')
        
        # Check site.json for configuration
        site_url = urljoin(self.scanner.target_url, '/site.json')
        response = self.scanner.make_request(site_url)
        
        if response and response.status_code == 200:
            try:
                data = response.json()
                
                config_info = {
                    'default_locale': data.get('default_locale'),
                    'title': data.get('title'),
                    'description': data.get('description'),
                    'logo_url': data.get('logo_url'),
                    'mobile_logo_url': data.get('mobile_logo_url'),
                    'favicon_url': data.get('favicon_url'),
                    'apple_touch_icon_url': data.get('apple_touch_icon_url')
                }
                
                # Authentication settings
                if 'auth_providers' in data:
                    config_info['auth_providers'] = data['auth_providers']
                
                # Trust levels
                if 'trust_levels' in data:
                    config_info['trust_levels'] = data['trust_levels']
                
                self.results['discourse_info']['site_config'] = config_info
                
            except json.JSONDecodeError:
                pass