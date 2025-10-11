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
        """Execute plugin bruteforce"""
        print(f"{Fore.CYAN}[*] Starting Plugin Bruteforce...{Style.RESET_ALL}")
        
        self._bruteforce_plugins()
        
        print(f"{Fore.GREEN}[+] Found {self.results['success_count']} plugins via bruteforce{Style.RESET_ALL}")
        return self.results
    
    def _bruteforce_plugins(self):
        """Bruteforce common plugin names"""
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
