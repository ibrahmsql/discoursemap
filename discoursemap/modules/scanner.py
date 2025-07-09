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
    is_discourse_site, clean_url, validate_url
)
from .info_module import InfoModule
from .vulnerability_module import VulnerabilityModule
from .endpoint_module import EndpointModule
from .user_module import UserModule
from .cve_exploit_module import CVEExploitModule
from .plugin_bruteforce_module import PluginBruteforceModule
from .plugin_detection_module import PluginDetectionModule
from .api_module import APISecurityModule
from .auth_module import AuthModule
from .config_module import ConfigModule
from .crypto_module import CryptoModule
from .network_module import NetworkModule
from .plugin_module import PluginModule
from .compliance_module import ComplianceModule
from .reporter import Reporter

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
            'vuln': VulnerabilityModule(self),
            'endpoint': EndpointModule(self),
            'user': UserModule(self),
            'cve': CVEExploitModule(self),
            'plugin_detection': PluginDetectionModule(self),
            'plugin_bruteforce': PluginBruteforceModule(self),
            'api': APISecurityModule(self),
            'auth': AuthModule(self),
            'config': ConfigModule(self),
            'crypto': CryptoModule(self),
            'network': NetworkModule(self),
            'plugin': PluginModule(self),
            # 'social': SocialEngineeringModule(self),
            'compliance': ComplianceModule(self)
        }
        
        # Initialize reporter
        self.reporter = Reporter(self.target_url)
    
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
            self.log("Error: Target is not a Discourse forum!", 'error')
            self.log("This tool is specifically designed for Discourse forums only.", 'error')
            raise Exception("Target is not a Discourse forum. Scan aborted.")
        else:
            self.log("Target confirmed as Discourse forum", 'success')
        
        return True
    
    def run_scan(self, modules_to_run=None):
        """Run the security scan"""
        if modules_to_run is None:
          modules_to_run = modules_to_run or ['info', 'vuln', 'endpoint', 'user', 'cve', 'plugin_detection', 'plugin_bruteforce', 
                                             'api', 'auth', 'config', 'crypto', 'network', 'plugin', 'compliance']
        
        self.log("Starting Discourse Security Scan", 'success')
        self.log(f"Target: {self.target_url}")
        self.log(f"Threads: {self.threads}")
        self.log(f"Modules: {', '.join(modules_to_run)}")
        
        # Record start time
        start_time = time.time()
        self.results['scan_info']['start_time'] = start_time
        self.reporter.scan_start_time = start_time
        
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
                    self.reporter.add_module_results(module_name, module_results)
                    
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
            self.reporter.scan_end_time = end_time
            
            self.log(f"Scan completed in {duration:.2f} seconds", 'success')
            
            # Finalize scan and generate reports
            self.reporter.finalize_scan()
            
            # Print summary is handled by finalize_scan
            # if not self.quiet:
            #     self.reporter.print_summary()
            
            return self.results
            
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", 'error')
            raise
        
        finally:
            # Close session
            if self.session:
                self.session.close()
    
    def generate_json_report(self, output_file=None):
        """Generate JSON report"""
        try:
            report_file = self.reporter.generate_json_report(output_file)
            self.log(f"JSON report generated: {report_file}", 'success')
            return report_file
        except Exception as e:
            self.log(f"Failed to generate JSON report: {e}", 'error')
            return None
    
    def generate_html_report(self, output_file=None):
        """Generate HTML report"""
        try:
            report_file = self.reporter.generate_html_report(output_file)
            self.log(f"HTML report generated: {report_file}", 'success')
            return report_file
        except Exception as e:
            self.log(f"Failed to generate HTML report: {e}", 'error')
            return None
    

    
    def get_base_url(self):
        """Get base URL for the target"""
        return self.target_url
    
    def get_session(self):
        """Get the HTTP session"""
        return self.session