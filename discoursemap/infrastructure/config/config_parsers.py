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
        """
        Create a ConfigParser instance bound to a scanner used to fetch site JSON and HTML.
        
        Parameters:
            scanner: An object responsible for making HTTP requests and exposing the target URL.
                It is expected to provide a `make_request(url, timeout=...)` method and a
                `target_url` attribute used by parsing methods.
        """
        self.scanner = scanner
    
    def parse_site_settings(self):
        """
        Extract site settings from the target site's /site.json.
        
        Returns:
            dict: Mapping with keys:
                - title: Site title or None
                - description: Site description or None
                - version: Site version string or None
                - default_locale: Default locale string or None
                - auth_providers: List of authentication providers (may be empty)
                - categories: Number of categories (int)
                - groups: Number of groups (int)
            Returns an empty dict if the settings cannot be retrieved or parsed.
        """
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
        """
        Parse Discourse /about.json and extract basic site information.
        
        Returns:
            config_info (dict): Dictionary containing:
                - 'discourse_version': version string or None
                - 'admins': integer count of admins
                - 'moderators': integer count of moderators
                - 'stats': dict of statistics (empty dict if unavailable)
            Returns an empty dict if the request or parsing fails.
        """
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
        """
        Detect installed plugins available on the target site.
        
        Returns:
            plugins (list): A list of plugin descriptors. Each descriptor is a dict with keys:
                - 'name' (str or None): Plugin name.
                - 'version' (str or None): Plugin version.
                - 'enabled' (bool): `True` if the plugin is enabled, `False` otherwise.
        """
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
        """
        Extract configuration-relevant data from the target page's HTML.
        
        Parses the page at the scanner's target URL for meta tags and script-based configuration markers.
        
        Returns:
            config (dict): A dictionary that may contain:
                - 'meta' (dict): mapping of meta tag names/properties to their content values.
                - 'has_preload_store' (bool): True if any script tag contains the substring 'PreloadStore'.
            The dictionary will be empty if no response was obtained or no relevant data was found.
        """
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