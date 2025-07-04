#!/usr/bin/env python3
"""
Discourse Security Scanner - Main Scanner Engine

Core scanning functionality for Discourse forum security assessment
"""

import threading
import time
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style
from .utils import (
    make_request, extract_csrf_token, extract_discourse_version,
    generate_payloads, random_user_agent, print_progress,
    is_discourse_site, clean_url
)
from .info_module import InfoModule
from .vuln_module import VulnModule
from .endpoint_module import EndpointModule
from .user_module import UserModule

class DiscourseScanner:
    """Main Discourse security scanner class"""
    
    def __init__(self, target_url, threads=5, timeout=10, proxy=None,
                 user_agent=None, delay=0.5, verify_ssl=True, verbose=False, quiet=False):
        """
        Initialize the scanner
        
        Args:
            target_url (str): Target Discourse forum URL
            threads (int): Number of concurrent threads
            timeout (int): HTTP request timeout
            proxy (str): Proxy server URL
            user_agent (str): Custom User-Agent string
            delay (float): Delay between requests
            verify_ssl (bool): Verify SSL certificates
            verbose (bool): Enable verbose output
            quiet (bool): Quiet mode (minimal output)
        """
        self.target_url = clean_url(target_url)
        self.threads = threads
        self.timeout = timeout
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.user_agent = user_agent or random_user_agent()
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.quiet = quiet
        
        # Results storage
        self.results = {
            'target': self.target_url,
            'scan_info': {
                'start_time': None,
                'end_time': None,
                'duration': None,
                'threads_used': self.threads
            },
            'modules': {}
        }
        
        # Session for connection reuse
        self.session = None
        self._setup_session()
        
        # Initialize modules
        self.modules = {
            'info': InfoModule(self),
            'vuln': VulnModule(self),
            'endpoint': EndpointModule(self),
            'user': UserModule(self)
        }
    
    def _setup_session(self):
        """Setup HTTP session with configuration"""
        import requests
        self.session = requests.Session()
        
        # Set headers
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Set proxy if provided
        if self.proxy:
            self.session.proxies.update(self.proxy)
        
        # SSL verification
        self.session.verify = self.verify_ssl
    
    def log(self, message, level='info'):
        """Log message with appropriate formatting"""
        if self.quiet and level != 'error':
            return
        
        colors = {
            'info': Fore.CYAN,
            'success': Fore.GREEN,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'debug': Fore.MAGENTA
        }
        
        if level == 'debug' and not self.verbose:
            return
        
        color = colors.get(level, Fore.WHITE)
        prefix = {
            'info': '[*]',
            'success': '[+]',
            'warning': '[!]',
            'error': '[!]',
            'debug': '[DEBUG]'
        }.get(level, '[*]')
        
        print(f"{color}{prefix} {message}{Style.RESET_ALL}")
    
    def make_request(self, url, method='GET', **kwargs):
        """Make HTTP request using configured session"""
        try:
            # Add delay between requests
            if self.delay > 0:
                time.sleep(self.delay)
            
            # Use session for request
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                **kwargs
            )
            
            return response
            
        except Exception as e:
            self.log(f"Request failed for {url}: {str(e)}", 'debug')
            return None
    
    def verify_target(self):
        """Verify target is accessible and is Discourse"""
        self.log(f"Verifying target: {self.target_url}")
        
        # Check if target is accessible
        response = self.make_request(self.target_url)
        if not response:
            raise Exception(f"Target {self.target_url} is not accessible")
        
        if response.status_code != 200:
            self.log(f"Target returned status code: {response.status_code}", 'warning')
        
        # Check if target is Discourse
        if not is_discourse_site(self.target_url, self.timeout):
            self.log("Warning: Target may not be a Discourse forum", 'warning')
        else:
            self.log("Target confirmed as Discourse forum", 'success')
        
        return True
    
    def run_scan(self, modules_to_run=None):
        """Run the security scan"""
        if modules_to_run is None:
            modules_to_run = ['info', 'vuln', 'endpoint', 'user']
        
        self.log("Starting Discourse Security Scan", 'success')
        self.log(f"Target: {self.target_url}")
        self.log(f"Threads: {self.threads}")
        self.log(f"Modules: {', '.join(modules_to_run)}")
        
        # Record start time
        start_time = time.time()
        self.results['scan_info']['start_time'] = start_time
        
        try:
            # Verify target
            self.verify_target()
            
            # Run each module
            for module_name in modules_to_run:
                if module_name not in self.modules:
                    self.log(f"Unknown module: {module_name}", 'warning')
                    continue
                
                self.log(f"Running {module_name.upper()} module")
                
                try:
                    module_results = self.modules[module_name].run()
                    self.results['modules'][module_name] = module_results
                    
                    # Log module completion
                    if module_results.get('vulnerabilities'):
                        vuln_count = len(module_results['vulnerabilities'])
                        self.log(f"{module_name.upper()} module completed - {vuln_count} issues found", 'success')
                    else:
                        self.log(f"{module_name.upper()} module completed", 'success')
                        
                except Exception as e:
                    self.log(f"Error in {module_name} module: {str(e)}", 'error')
                    if self.verbose:
                        import traceback
                        traceback.print_exc()
            
            # Record end time
            end_time = time.time()
            duration = end_time - start_time
            
            self.results['scan_info']['end_time'] = end_time
            self.results['scan_info']['duration'] = duration
            
            self.log(f"Scan completed in {duration:.2f} seconds", 'success')
            
            # Print summary
            self._print_summary()
            
            return self.results
            
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", 'error')
            raise
        
        finally:
            # Close session
            if self.session:
                self.session.close()
    
    def _print_summary(self):
        """Print scan summary"""
        if self.quiet:
            return
        
        self.log("\n" + "="*60, 'info')
        self.log("SCAN SUMMARY", 'info')
        self.log("="*60, 'info')
        
        total_vulns = 0
        for module_name, module_results in self.results['modules'].items():
            if 'vulnerabilities' in module_results:
                vuln_count = len(module_results['vulnerabilities'])
                total_vulns += vuln_count
                
                if vuln_count > 0:
                    self.log(f"{module_name.upper()}: {vuln_count} vulnerabilities found", 'warning')
                else:
                    self.log(f"{module_name.upper()}: No vulnerabilities found", 'success')
        
        self.log(f"\nTotal vulnerabilities found: {total_vulns}", 'info')
        
        if total_vulns > 0:
            self.log("\nHigh-priority issues:", 'warning')
            for module_name, module_results in self.results['modules'].items():
                if 'vulnerabilities' in module_results:
                    for vuln in module_results['vulnerabilities']:
                        if vuln.get('severity') in ['high', 'critical']:
                            self.log(f"  - {vuln.get('title', 'Unknown')}", 'error')
        
        self.log("="*60, 'info')
    
    def get_base_url(self):
        """Get base URL for the target"""
        return self.target_url
    
    def get_session(self):
        """Get the HTTP session"""
        return self.session