#!/usr/bin/env python3
"""
Scanner Configuration Module

Manages scanner configuration and settings.
"""

import json
import yaml
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import os


class ScannerConfig:
    """Scanner configuration management"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.config = self._load_default_config()
        
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        
        return {
            'scanner': {
                'timeout': 10,
                'max_retries': 3,
                'delay_between_requests': 0.1,
                'user_agent': 'DiscourseMap/1.0',
                'follow_redirects': True,
                'verify_ssl': True
            },
            'modules': {
                'enabled': [
                    'info_module',
                    'endpoint_module',
                    'vulnerability_module',
                    'auth_module'
                ],
                'disabled': [],
                'custom_modules': []
            },
            'output': {
                'format': 'json',
                'file': None,
                'verbose': False,
                'save_raw_responses': False
            },
            'rate_limiting': {
                'enabled': True,
                'requests_per_second': 10,
                'burst_limit': 50
            },
            'authentication': {
                'username': None,
                'password': None,
                'api_key': None,
                'session_cookie': None
            },
            'proxy': {
                'enabled': False,
                'http_proxy': None,
                'https_proxy': None,
                'socks_proxy': None
            },
            'advanced': {
                'custom_headers': {},
                'exclude_endpoints': [],
                'include_only': [],
                'max_depth': 5,
                'follow_external_links': False
            }
        }
    
    def load_config(self, config_file: str) -> bool:
        """Load configuration from file"""
        
        try:
            file_path = Path(config_file)
            
            if not file_path.exists():
                raise FileNotFoundError(f"Config file not found: {config_file}")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.suffix.lower() in ['.yml', '.yaml']:
                    loaded_config = yaml.safe_load(f)
                else:
                    loaded_config = json.load(f)
            
            # Merge with default config
            self._merge_config(self.config, loaded_config)
            
            return True
            
        except Exception as e:
            print(f"Error loading config: {e}")
            return False
    
    def save_config(self, config_file: str, format: str = 'json') -> bool:
        """Save current configuration to file"""
        
        try:
            file_path = Path(config_file)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                if format.lower() in ['yml', 'yaml']:
                    yaml.dump(self.config, f, default_flow_style=False, indent=2)
                else:
                    json.dump(self.config, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def _merge_config(self, default: Dict[str, Any], loaded: Dict[str, Any]) -> None:
        """Recursively merge loaded config with default"""
        
        for key, value in loaded.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_config(default[key], value)
            else:
                default[key] = value
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        
        keys = key_path.split('.')
        current = self.config
        
        try:
            for key in keys:
                current = current[key]
            return current
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any) -> None:
        """Set configuration value using dot notation"""
        
        keys = key_path.split('.')
        current = self.config
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def enable_module(self, module_name: str) -> None:
        """Enable a scanner module"""
        
        enabled = self.get('modules.enabled', [])
        disabled = self.get('modules.disabled', [])
        
        if module_name not in enabled:
            enabled.append(module_name)
        
        if module_name in disabled:
            disabled.remove(module_name)
        
        self.set('modules.enabled', enabled)
        self.set('modules.disabled', disabled)
    
    def disable_module(self, module_name: str) -> None:
        """Disable a scanner module"""
        
        enabled = self.get('modules.enabled', [])
        disabled = self.get('modules.disabled', [])
        
        if module_name in enabled:
            enabled.remove(module_name)
        
        if module_name not in disabled:
            disabled.append(module_name)
        
        self.set('modules.enabled', enabled)
        self.set('modules.disabled', disabled)
    
    def is_module_enabled(self, module_name: str) -> bool:
        """Check if a module is enabled"""
        
        enabled = self.get('modules.enabled', [])
        disabled = self.get('modules.disabled', [])
        
        return module_name in enabled and module_name not in disabled
    
    def set_authentication(self, username: str = None, password: str = None,
                          api_key: str = None, session_cookie: str = None) -> None:
        """Set authentication credentials"""
        
        auth_config = {
            'username': username,
            'password': password,
            'api_key': api_key,
            'session_cookie': session_cookie
        }
        
        for key, value in auth_config.items():
            if value is not None:
                self.set(f'authentication.{key}', value)
    
    def set_proxy(self, http_proxy: str = None, https_proxy: str = None,
                  socks_proxy: str = None) -> None:
        """Set proxy configuration"""
        
        self.set('proxy.enabled', True)
        
        if http_proxy:
            self.set('proxy.http_proxy', http_proxy)
        if https_proxy:
            self.set('proxy.https_proxy', https_proxy)
        if socks_proxy:
            self.set('proxy.socks_proxy', socks_proxy)
    
    def disable_proxy(self) -> None:
        """Disable proxy"""
        
        self.set('proxy.enabled', False)
    
    def add_custom_header(self, name: str, value: str) -> None:
        """Add custom HTTP header"""
        
        headers = self.get('advanced.custom_headers', {})
        headers[name] = value
        self.set('advanced.custom_headers', headers)
    
    def remove_custom_header(self, name: str) -> None:
        """Remove custom HTTP header"""
        
        headers = self.get('advanced.custom_headers', {})
        if name in headers:
            del headers[name]
            self.set('advanced.custom_headers', headers)
    
    def exclude_endpoint(self, endpoint: str) -> None:
        """Add endpoint to exclusion list"""
        
        excluded = self.get('advanced.exclude_endpoints', [])
        if endpoint not in excluded:
            excluded.append(endpoint)
            self.set('advanced.exclude_endpoints', excluded)
    
    def include_only_endpoint(self, endpoint: str) -> None:
        """Add endpoint to include-only list"""
        
        included = self.get('advanced.include_only', [])
        if endpoint not in included:
            included.append(endpoint)
            self.set('advanced.include_only', included)
    
    def validate_config(self) -> Dict[str, List[str]]:
        """Validate configuration and return any issues"""
        
        issues = {
            'errors': [],
            'warnings': []
        }
        
        # Check required fields
        timeout = self.get('scanner.timeout')
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            issues['errors'].append('scanner.timeout must be a positive number')
        
        # Check module configuration
        enabled_modules = self.get('modules.enabled', [])
        if not enabled_modules:
            issues['warnings'].append('No modules are enabled')
        
        # Check authentication
        username = self.get('authentication.username')
        password = self.get('authentication.password')
        
        if username and not password:
            issues['warnings'].append('Username provided without password')
        
        # Check proxy configuration
        if self.get('proxy.enabled'):
            has_proxy = any([
                self.get('proxy.http_proxy'),
                self.get('proxy.https_proxy'),
                self.get('proxy.socks_proxy')
            ])
            
            if not has_proxy:
                issues['errors'].append('Proxy enabled but no proxy servers configured')
        
        return issues
    
    def get_requests_config(self) -> Dict[str, Any]:
        """Get configuration for requests library"""
        
        config = {
            'timeout': self.get('scanner.timeout', 10),
            'allow_redirects': self.get('scanner.follow_redirects', True),
            'verify': self.get('scanner.verify_ssl', True),
            'headers': {
                'User-Agent': self.get('scanner.user_agent', 'DiscourseMap/1.0')
            }
        }
        
        # Add custom headers
        custom_headers = self.get('advanced.custom_headers', {})
        config['headers'].update(custom_headers)
        
        # Add proxy configuration
        if self.get('proxy.enabled'):
            proxies = {}
            
            if self.get('proxy.http_proxy'):
                proxies['http'] = self.get('proxy.http_proxy')
            if self.get('proxy.https_proxy'):
                proxies['https'] = self.get('proxy.https_proxy')
            
            if proxies:
                config['proxies'] = proxies
        
        return config