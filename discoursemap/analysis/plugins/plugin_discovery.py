#!/usr/bin/env python3
"""
Plugin Discovery Module

Handles plugin and theme discovery functionality.
"""

import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup


class PluginDiscovery:
    """Plugin and theme discovery functionality"""
    
    def __init__(self, scanner):
        self.scanner = scanner
    
    def discover_plugins(self):
        """Discover installed plugins"""
        plugins = []
        
        try:
            # Try admin plugins page
            admin_url = urljoin(self.scanner.target_url, '/admin/plugins')
            response = self.scanner.make_request(admin_url)
            
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Look for plugin information
                plugin_elements = soup.find_all(['div', 'tr'], class_=lambda x: x and 'plugin' in x.lower())
                
                for element in plugin_elements:
                    plugin_info = self._extract_plugin_info(element)
                    if plugin_info:
                        plugins.append(plugin_info)
            
            # Try API endpoint
            api_url = urljoin(self.scanner.target_url, '/admin/plugins.json')
            response = self.scanner.make_request(api_url)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if 'plugins' in data:
                        for plugin in data['plugins']:
                            plugin_info = {
                                'name': plugin.get('name', ''),
                                'version': plugin.get('version', ''),
                                'enabled': plugin.get('enabled', False),
                                'url': plugin.get('url', ''),
                                'author': plugin.get('author', ''),
                                'description': plugin.get('description', '')
                            }
                            plugins.append(plugin_info)
                except:
                    pass
            
        except Exception as e:
            self.scanner.log(f"Error discovering plugins: {e}", 'debug')
        
        return plugins
    
    def discover_themes(self):
        """Discover installed themes"""
        themes = []
        
        try:
            # Try admin themes page
            admin_url = urljoin(self.scanner.target_url, '/admin/customize/themes')
            response = self.scanner.make_request(admin_url)
            
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Look for theme information
                theme_elements = soup.find_all(['div', 'tr'], class_=lambda x: x and 'theme' in x.lower())
                
                for element in theme_elements:
                    theme_info = self._extract_theme_info(element)
                    if theme_info:
                        themes.append(theme_info)
            
            # Try API endpoint
            api_url = urljoin(self.scanner.target_url, '/admin/themes.json')
            response = self.scanner.make_request(api_url)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if 'themes' in data:
                        for theme in data['themes']:
                            theme_info = {
                                'id': theme.get('id', ''),
                                'name': theme.get('name', ''),
                                'default': theme.get('default', False),
                                'user_selectable': theme.get('user_selectable', False),
                                'color_scheme_id': theme.get('color_scheme_id'),
                                'remote_theme': theme.get('remote_theme', {})
                            }
                            themes.append(theme_info)
                except:
                    pass
            
        except Exception as e:
            self.scanner.log(f"Error discovering themes: {e}", 'debug')
        
        return themes
    
    def _extract_plugin_info(self, element):
        """Extract plugin information from HTML element"""
        try:
            plugin_info = {}
            
            # Try to extract name
            name_elem = element.find(['h3', 'h4', 'span'], class_=lambda x: x and 'name' in x.lower())
            if name_elem:
                plugin_info['name'] = name_elem.get_text(strip=True)
            
            # Try to extract version
            version_elem = element.find(['span', 'div'], class_=lambda x: x and 'version' in x.lower())
            if version_elem:
                plugin_info['version'] = version_elem.get_text(strip=True)
            
            # Try to extract status
            status_elem = element.find(['span', 'div'], class_=lambda x: x and ('enabled' in x.lower() or 'disabled' in x.lower()))
            if status_elem:
                plugin_info['enabled'] = 'enabled' in status_elem.get_text().lower()
            
            return plugin_info if plugin_info else None
            
        except Exception:
            return None
    
    def _extract_theme_info(self, element):
        """Extract theme information from HTML element"""
        try:
            theme_info = {}
            
            # Try to extract name
            name_elem = element.find(['h3', 'h4', 'span'], class_=lambda x: x and 'name' in x.lower())
            if name_elem:
                theme_info['name'] = name_elem.get_text(strip=True)
            
            # Try to extract default status
            default_elem = element.find(['span', 'div'], class_=lambda x: x and 'default' in x.lower())
            if default_elem:
                theme_info['default'] = True
            
            return theme_info if theme_info else None
            
        except Exception:
            return None
    
    def check_plugin_endpoints(self, plugins):
        """Check plugin-specific endpoints"""
        endpoints = []
        
        for plugin in plugins:
            plugin_name = plugin.get('name', '').lower().replace(' ', '-')
            
            # Common plugin endpoints
            test_endpoints = [
                f'/admin/plugins/{plugin_name}',
                f'/admin/plugins/{plugin_name}/settings',
                f'/plugins/{plugin_name}',
                f'/plugins/{plugin_name}/admin'
            ]
            
            for endpoint in test_endpoints:
                try:
                    url = urljoin(self.scanner.target_url, endpoint)
                    response = self.scanner.make_request(url)
                    
                    if response and response.status_code == 200:
                        endpoint_info = {
                            'plugin': plugin_name,
                            'endpoint': endpoint,
                            'accessible': True,
                            'content_length': len(response.text)
                        }
                        endpoints.append(endpoint_info)
                        
                except Exception:
                    continue
        
        return endpoints