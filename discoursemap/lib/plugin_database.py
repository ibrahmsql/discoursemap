#!/usr/bin/env python3
"""
Plugin Database Manager

Fetches and caches Discourse plugin information from GitHub.
"""

import os
import json
import time
import requests
from typing import Dict, List, Optional
from pathlib import Path

class PluginDatabase:
    """Manages plugin information database"""
    
    def __init__(self, cache_dir: str = None, cache_ttl: int = 86400):
        """
        Initialize plugin database.
        
        Args:
            cache_dir: Directory to store cache files
            cache_ttl: Cache time-to-live in seconds (default: 24 hours)
        """
        if cache_dir is None:
            # Use data directory in project root
            self.cache_dir = Path(__file__).parent.parent.parent / 'data' / 'plugin_cache'
        else:
            self.cache_dir = Path(cache_dir)
            
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = cache_ttl
        
        # GitHub URLs for plugin lists
        self.official_plugins_url = "https://raw.githubusercontent.com/discourse/all-the-plugins/main/official.txt"
        self.third_party_plugins_url = "https://raw.githubusercontent.com/discourse/all-the-plugins/main/third-party.txt"
        
    def _get_cache_file(self, name: str) -> Path:
        """Get cache file path"""
        return self.cache_dir / f"{name}.json"
        
    def _is_cache_valid(self, cache_file: Path) -> bool:
        """Check if cache file is still valid"""
        if not cache_file.exists():
            return False
            
        file_age = time.time() - cache_file.stat().st_mtime
        return file_age < self.cache_ttl
        
    def _fetch_plugin_list(self, url: str) -> List[str]:
        """Fetch plugin list from GitHub"""
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                # Parse lines, filter empty ones
                return [line.strip() for line in response.text.split('\n') if line.strip()]
        except Exception:
            pass
        return []
        
    def _fetch_plugin_version(self, plugin_repo: str) -> Optional[str]:
        """
        Fetch latest version for a plugin from GitHub API.
        
        Args:
            plugin_repo: Format 'owner/repo'
            
        Returns:
            Version string or None
        """
        try:
            url = f"https://api.github.com/repos/{plugin_repo}/releases/latest"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                tag_name = data.get('tag_name', '')
                # Strip 'v' prefix if present
                if tag_name.startswith('v'):
                    tag_name = tag_name[1:]
                return tag_name if tag_name else None
        except Exception:
            pass
        return None
        
    def get_all_plugins(self) -> Dict[str, Dict[str, any]]:
        """
        Get all plugins with their information.
        
        Returns:
            Dictionary mapping plugin name to plugin info
        """
        cache_file = self._get_cache_file('all_plugins')
        
        # Check cache
        if self._is_cache_valid(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
                
        # Fetch fresh data
        plugins_data = {}
        
        # Get official plugins
        official_list = self._fetch_plugin_list(self.official_plugins_url)
        for repo in official_list:
            plugin_name = repo.split('/')[-1]  # Extract repo name
            plugins_data[plugin_name] = {
                'repo': repo,
                'type': 'official',
                'version': None  # Will be fetched on demand
            }
            
        # Get third-party plugins
        third_party_list = self._fetch_plugin_list(self.third_party_plugins_url)
        for repo in third_party_list:
            plugin_name = repo.split('/')[-1]  # Extract repo name
            # Skip if already exists (official takes precedence)
            if plugin_name not in plugins_data:
                plugins_data[plugin_name] = {
                    'repo': repo,
                    'type': 'third-party',
                    'version': None
                }
                
        # Save to cache
        try:
            with open(cache_file, 'w') as f:
                json.dump(plugins_data, f, indent=2)
        except Exception:
            pass
            
        return plugins_data
        
    def get_plugin_version(self, plugin_name: str) -> Optional[str]:
        """
        Get version for a specific plugin.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Version string or None
        """
        # Get all plugins to find the repo
        all_plugins = self.get_all_plugins()
        
        if plugin_name not in all_plugins:
            return None
            
        plugin_info = all_plugins[plugin_name]
        repo = plugin_info.get('repo')
        
        if not repo:
            return None
            
        # Check version cache
        cache_file = self._get_cache_file(f'version_{plugin_name}')
        
        if self._is_cache_valid(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                    return data.get('version')
            except Exception:
                pass
                
        # Fetch version from GitHub API
        version = self._fetch_plugin_version(repo)
        
        # Cache the result
        if version:
            try:
                with open(cache_file, 'w') as f:
                    json.dump({'version': version, 'fetched_at': time.time()}, f)
            except Exception:
                pass
                
        return version
        
    def get_known_versions(self, plugin_names: List[str] = None) -> Dict[str, str]:
        """
        Get known versions for multiple plugins.
        
        Args:
            plugin_names: List of plugin names (or None for all)
            
        Returns:
            Dictionary mapping plugin name to version
        """
        all_plugins = self.get_all_plugins()
        
        if plugin_names is None:
            plugin_names = list(all_plugins.keys())
            
        versions = {}
        for plugin_name in plugin_names:
            version = self.get_plugin_version(plugin_name)
            if version:
                versions[plugin_name] = version
                
        return versions
