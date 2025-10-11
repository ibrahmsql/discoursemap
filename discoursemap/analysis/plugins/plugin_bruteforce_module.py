#!/usr/bin/env python3
"""
Discourse Plugin Bruteforce Module (Refactored)

Plugin discovery via bruteforce - split from 562 lines.
"""

from typing import Dict, Any
from colorama import Fore, Style
from urllib.parse import urljoin


class PluginBruteforceModule:
    """Plugin discovery via bruteforce (Refactored)"""
    
    def __init__(self, scanner):
        """
        Initialize the PluginBruteforceModule with a scanner and default state.
        
        Parameters:
            scanner: Scanner-like object providing a `target_url` attribute used as the discovery base URL.
        
        Attributes:
            scanner: The provided scanner object.
            results (dict): Module metadata and runtime counters:
                - module_name: 'Plugin Bruteforce'
                - target: scanner.target_url
                - plugins_found: list of discovered plugins (each as dict with keys `name`, `path`, `method`)
                - attempts: number of plugin checks performed
                - success_count: number of successful discoveries
            common_plugins (list): Predefined plugin names to probe (e.g., 'discourse-chat', 'discourse-calendar', etc.).
        """
        self.scanner = scanner
        self.results = {
            'module_name': 'Plugin Bruteforce',
            'target': scanner.target_url,
            'plugins_found': [],
            'attempts': 0,
            'success_count': 0
        }
        
        # Common plugin names to test
        self.common_plugins = [
            'discourse-chat', 'discourse-calendar', 'discourse-voting',
            'discourse-solved', 'discourse-signatures', 'discourse-bbcode',
            'discourse-spoiler-alert', 'discourse-mathjax', 'discourse-footnote'
        ]
    
    def run(self) -> Dict[str, Any]:
        """
        Run the plugin bruteforce workflow and collect discovery results.
        
        Performs probing of common plugin paths, updates the module's results, and prints progress messages.
        
        Returns:
            results (Dict[str, Any]): Dictionary with keys:
                - module_name: str, the module display name
                - target: str, the target URL tested
                - plugins_found: List[Dict[str, Any]], each entry contains 'name', 'path', and 'method'
                - attempts: int, total number of probe attempts performed
                - success_count: int, number of successful detections
        """
        print(f"{Fore.CYAN}[*] Starting Plugin Bruteforce...{Style.RESET_ALL}")
        
        self._bruteforce_plugins()
        
        print(f"{Fore.GREEN}[+] Found {self.results['success_count']} plugins via bruteforce{Style.RESET_ALL}")
        return self.results
    
    def _bruteforce_plugins(self):
        """
        Probe a set of common Discourse plugin paths and record any discoveries in self.results.
        
        For each name in self.common_plugins, increments self.results['attempts'], requests a set of common plugin paths constructed from that name, and on an HTTP 200 response appends a dictionary with keys 'name', 'path', and 'method' ('bruteforce') to self.results['plugins_found'] and increments self.results['success_count']. Exceptions raised during probing are suppressed.
        """
        try:
            import requests
            
            for plugin_name in self.common_plugins:
                self.results['attempts'] += 1
                
                # Try common plugin paths
                plugin_paths = [
                    f'/plugins/{plugin_name}',
                    f'/assets/plugins/{plugin_name}',
                    f'/admin/plugins/{plugin_name}'
                ]
                
                for path in plugin_paths:
                    url = urljoin(self.scanner.target_url, path)
                    response = requests.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        self.results['plugins_found'].append({
                            'name': plugin_name,
                            'path': path,
                            'method': 'bruteforce'
                        })
                        self.results['success_count'] += 1
                        break
        except:
            pass