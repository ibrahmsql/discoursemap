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
        Initialize the parser with a scanner used to perform HTTP requests and provide the target URL.
        
        Parameters:
        	scanner: An object that performs HTTP requests and exposes the scanner's target URL (expected to provide a `make_request` method and a `target_url` attribute).
        """
        self.scanner = scanner
    
    def parse_site_settings(self):
        """
        Retrieve core site settings from the target site's /site.json endpoint.
        
        Queries the scanner's target URL for /site.json and extracts primary site metadata and counts.
        Returns an empty dict if the endpoint is unavailable or parsing fails.
        
        Returns:
            dict: Settings with keys:
                - title: site title or None
                - description: site description or None
                - version: site version string or None
                - default_locale: default locale string or None
                - auth_providers: list of authentication providers (empty list if missing)
                - categories: integer count of categories
                - groups: integer count of groups
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
        Parse the site's /about.json and extract high-level configuration information.
        
        Returns:
            config_info (dict): Parsed about data with keys:
                - discourse_version (str or None): Version string from the about payload.
                - admins (int): Number of admins.
                - moderators (int): Number of moderators.
                - stats (dict): Stats object from the about payload (empty dict if missing).
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
        Detect installed plugins declared in the site's /site.json endpoint.
        
        Returns:
            plugins (list): A list of dictionaries describing each plugin with keys:
                - 'name' (str or None): Plugin name.
                - 'version' (str or None): Plugin version.
                - 'enabled' (bool): Whether the plugin is enabled (defaults to True if not present).
            Returns an empty list if plugin information cannot be retrieved.
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
        Extracts HTML-embedded configuration from the target page.
        
        Parses the page at the scanner's target URL for meta tag values and detects whether a script containing the string "PreloadStore" is present. The returned dictionary may include:
        - "meta": a mapping of meta tag `name` or `property` attributes to their `content` values.
        - "has_preload_store": `True` if a script containing "PreloadStore" was found.
        
        Returns:
            config (dict): A dictionary with parsed HTML configuration keys described above; empty if nothing was found.
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