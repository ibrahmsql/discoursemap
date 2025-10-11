#!/usr/bin/env python3
"""
Configuration Parser Module

Handles parsing of various configuration formats.
"""

import json
import yaml
from urllib.parse import urljoin
from bs4 import BeautifulSoup


class ConfigParser:
    """Configuration parsing utilities"""
    
    def __init__(self, scanner):
        self.scanner = scanner
    
    def parse_site_settings(self):
        """Parse Discourse site settings"""
        settings = {}
        
        try:
            site_url = urljoin(self.scanner.target_url, '/site.json')
            response = self.scanner.make_request(site_url, timeout=10)
            
            if response and response.status_code == 200:
                data = response.json()
                settings = {
                    'title': data.get('title'),
                    'description': data.get('description'),
                    'version': data.get('version'),
                    'default_locale': data.get('default_locale'),
                    'auth_providers': data.get('auth_providers', []),
                    'categories': len(data.get('categories', [])),
                    'groups': len(data.get('groups', []))
                }
        except Exception:
            pass
        
        return settings
    
    def parse_about_json(self):
        """Parse /about.json for configuration info"""
        config_info = {}
        
        try:
            about_url = urljoin(self.scanner.target_url, '/about.json')
            response = self.scanner.make_request(about_url, timeout=10)
            
            if response and response.status_code == 200:
                data = response.json()
                about_data = data.get('about', {})
                
                config_info = {
                    'discourse_version': about_data.get('version'),
                    'admins': len(about_data.get('admins', [])),
                    'moderators': len(about_data.get('moderators', [])),
                    'stats': about_data.get('stats', {})
                }
        except Exception:
            pass
        
        return config_info
    
    def detect_plugins(self):
        """Detect installed plugins"""
        plugins = []
        
        try:
            # Try to get plugin info from site.json
            site_url = urljoin(self.scanner.target_url, '/site.json')
            response = self.scanner.make_request(site_url, timeout=10)
            
            if response and response.status_code == 200:
                data = response.json()
                plugins_data = data.get('plugins', [])
                
                for plugin in plugins_data:
                    plugins.append({
                        'name': plugin.get('name'),
                        'version': plugin.get('version'),
                        'enabled': plugin.get('enabled', True)
                    })
        except Exception:
            pass
        
        return plugins
    
    def extract_html_config(self):
        """Extract configuration from HTML"""
        config = {}
        
        try:
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract meta tags
                meta_tags = soup.find_all('meta')
                config['meta'] = {}
                
                for tag in meta_tags:
                    name = tag.get('name', tag.get('property', ''))
                    content = tag.get('content', '')
                    if name and content:
                        config['meta'][name] = content
                
                # Look for config in script tags
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.string and 'PreloadStore' in script.string:
                        config['has_preload_store'] = True
                        break
        except Exception:
            pass
        
        return config
