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
        Initialize the plugin bruteforce module with a scanner and prepare default state.
        
        Initializes the module's state including a results dictionary (module_name, target, plugins_found list, attempts counter, success_count) and a list of common plugin names to test during bruteforce discovery.
        
        Parameters:
            scanner: An object exposing `target_url` that identifies the target to probe. The scanner is stored for use by the module.
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
        Run the plugin bruteforce process and populate the module's results.
        
        Executes attempts against common plugin paths for the configured target and records discoveries in the module's results dictionary.
        
        Returns:
            results (Dict[str, Any]): Dictionary with keys:
                - `module_name`: module identifier string
                - `target`: the scanned target URL
                - `plugins_found`: list of discovered plugin records (each contains `name`, `path`, and `method`)
                - `attempts`: total number of plugin attempts performed
                - `success_count`: number of successful discoveries
        """
        print(f"{Fore.CYAN}[*] Starting Plugin Bruteforce...{Style.RESET_ALL}")
        
        self._bruteforce_plugins()
        
        print(f"{Fore.GREEN}[+] Found {self.results['success_count']} plugins via bruteforce{Style.RESET_ALL}")
        return self.results
    
    def _bruteforce_plugins(self):
        """
        Attempt discovery of plugins from the module's common plugin list by probing common plugin URL paths and recording any positive responses.
        
        This method iterates the instance's `common_plugins`, tries typical plugin paths for each name, and for each successful HTTP 200 response appends a record to `self.results['plugins_found']` with keys `name`, `path`, and `method` set to `'bruteforce'`. It also increments `self.results['attempts']` for each plugin tested and `self.results['success_count']` for each successful discovery. Any exceptions raised during probing are suppressed.
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