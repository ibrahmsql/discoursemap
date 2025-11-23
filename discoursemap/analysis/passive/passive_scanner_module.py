#!/usr/bin/env python3
"""
Discourse Passive Scanner Module (Refactored)

Passive information gathering - split from 633 lines.
"""

from typing import Dict, Any, List
from colorama import Fore, Style
from urllib.parse import urljoin
import requests
import logging

# Module constants
DEFAULT_TIMEOUT = 10
SECURITY_HEADERS = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy'
]

logger = logging.getLogger(__name__)


class PassiveScannerModule:
    """Passive scanning (Refactored)"""
    
    def __init__(self, scanner):
        """
        Initialize the PassiveScannerModule and prepare the results structure for a given scanner.
        
        Parameters:
            scanner: An object representing the scanner; must expose a `target_url` attribute used as the scan target.
        
        Notes:
            Initializes `self.results` with keys: `module_name`, `target`, `headers`, `meta_info`, `technologies`, and `findings`.
        """
        self.scanner = scanner
        self.results: Dict[str, Any] = {
            'module_name': 'Passive Scanner',
            'target': scanner.target_url,
            'headers': {},
            'meta_info': {},
            'technologies': [],
            'findings': []
        }
    
    def run(self) -> Dict[str, Any]:
        """
        Perform a passive scan of the configured target by analyzing HTTP headers and collecting site metadata.
        
        Returns:
            results (Dict[str, Any]): Aggregated scan results containing:
                - module_name: Name of the module.
                - target: The scanned target URL.
                - headers: Retrieved response headers (dict).
                - meta_info: Site metadata such as title, version, and description (dict).
                - technologies: Detected technologies (list).
                - findings: Identified issues and observations (list).
        """
        print(f"{Fore.CYAN}[*] Starting Passive Scan...{Style.RESET_ALL}")
        
        self._analyze_headers()
        self._gather_meta_info()
        
        print(f"{Fore.GREEN}[+] Passive scan complete{Style.RESET_ALL}")
        return self.results
    
    def _analyze_headers(self) -> None:
        """
        Analyze the target's HTTP response headers and record any missing standard security headers.
        
        Stores the response headers in self.results['headers'] and appends a finding to self.results['findings'] for each missing header among: 'strict-transport-security', 'content-security-policy', and 'x-frame-options'. Each appended finding includes a 'type' of 'Missing Security Header', the 'header' name, and a 'severity' of 'medium'. Network or other errors during retrieval are ignored.
        """
        try:
            response = requests.get(
                self.scanner.target_url, 
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=True
            )
            
            if response:
                self.results['headers'] = dict(response.headers)
                
                # Check for security headers
                for header in SECURITY_HEADERS:
                    if header not in response.headers:
                        self.results['findings'].append({
                            'type': 'Missing Security Header',
                            'header': header,
                            'severity': 'medium'
                        })
                        
        except requests.Timeout:
            logger.error(f"Timeout while fetching headers from {self.scanner.target_url}")
        except requests.RequestException as e:
            logger.error(f"Request error during header analysis: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during header analysis: {e}")
    
    def _gather_meta_info(self) -> None:
        """
        Gather site metadata from the target's /site.json and store it in self.results['meta_info'].
        
        If a GET request to '<target>/site.json' returns a 200 status and valid JSON, sets self.results['meta_info'] to a dict with keys 'title', 'version', and 'description' populated from the JSON (values will be None if the fields are missing).
        """
        try:
            site_url = urljoin(self.scanner.target_url, '/site.json')
            response = requests.get(site_url, timeout=DEFAULT_TIMEOUT)
            
            if response and response.status_code == 200:
                data = response.json()
                self.results['meta_info'] = {
                    'title': data.get('title'),
                    'version': data.get('version'),
                    'description': data.get('description')
                }
                
        except requests.Timeout:
            logger.warning(f"Timeout while fetching site.json from {site_url}")
        except requests.JSONDecodeError:
            logger.warning(f"Invalid JSON returned from {site_url}")
        except requests.RequestException as e:
            logger.error(f"Request error during metadata gathering: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during metadata gathering: {e}")