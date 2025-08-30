#!/usr/bin/env python3
"""
Discourse Security Scanner - Main Scanner Engine

Core scanning functionality for Discourse forum security assessment
"""

import asyncio
import threading
import time
import queue
import gc
import weakref
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, BoundedSemaphore
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any, List, Union, Tuple
import requests
from ..lib.discourse_utils import (
    make_request, extract_csrf_token, extract_discourse_version,
    generate_payloads, random_user_agent, print_progress,
    is_discourse_site, clean_url, validate_url
)
from ..lib.http_client import HTTPClient
from ..lib.config_manager import ConfigManager
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
from .waf_bypass_module import WAFBypassModule
# BackupScannerModule integrated into EndpointModule
from .passive_scanner_module import PassiveScannerModule
from .file_integrity_module import FileIntegrityModule
from .reporter import Reporter

class DiscourseScanner:
    """Main Discourse security scanner class"""
    
    def __init__(self, 
                 target_url: str, 
                 threads: Optional[int] = None, 
                 timeout: Optional[int] = None, 
                 proxy: Optional[str] = None,
                 user_agent: Optional[str] = None, 
                 delay: Optional[float] = None, 
                 verify_ssl: Optional[bool] = None, 
                 verbose: bool = False, 
                 quiet: bool = False, 
                 config_file: Optional[str] = None) -> None:
        """
        Initialize the Discourse scanner.
        
        Args:
            target_url: Target Discourse forum URL
            threads: Number of threads for concurrent scanning
            timeout: Request timeout in seconds
            proxy: Proxy server URL
            user_agent: Custom User-Agent string
            delay: Delay between requests in seconds
            verify_ssl: Whether to verify SSL certificates
            verbose: Enable verbose logging
            quiet: Enable quiet mode (minimal output)
            config_file: Path to configuration file
        """
        
        # Initialize config manager
        self.config_manager = ConfigManager(config_file)
        
        # Use config values as defaults, override with provided parameters
        config = self.config_manager.scan_config
        """
        Initialize the scanner with threading and memory management
        
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
            config_file (str): Path to config file (optional)
        """
        self.target_url = clean_url(target_url)
        self.threads = min(threads if threads is not None else config.threads, 50)  # Increased max threads for better performance
        self.timeout = timeout if timeout is not None else config.timeout
        proxy_url = proxy if proxy is not None else config.proxy
        self.proxy = {'http': proxy_url, 'https': proxy_url} if proxy_url else None
        self.user_agent = user_agent if user_agent is not None else (config.user_agent or random_user_agent())
        self.delay = delay if delay is not None else config.delay
        self.verify_ssl = verify_ssl if verify_ssl is not None else config.verify_ssl
        self.verbose = verbose
        self.quiet = quiet
        
        # Threading controls with improved concurrency
        self.thread_semaphore = BoundedSemaphore(self.threads)
        self.request_lock = Lock()
        self.active_requests = 0
        self.max_concurrent_requests = self.threads * 3  # Increased multiplier
        
        # Memory management with adaptive caching
        self.response_cache = weakref.WeakValueDictionary()
        self.max_cache_size = 100  # Increased cache size
        self.memory_cleanup_interval = 50  # Less frequent cleanup
        self.request_count = 0
        
        # Adaptive rate limiting
        self.success_count = 0
        self.error_count = 0
        self.adaptive_delay = delay if delay is not None else 0.1  # Default to 0.1 if None
        
        # Color definitions for output formatting
        self.colors = {
            'info': Fore.CYAN,
            'success': Fore.GREEN,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'debug': Fore.MAGENTA,
            'reset': Style.RESET_ALL
        }
        
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
            'waf_bypass': WAFBypassModule(self),
            # 'social': SocialEngineeringModule(self),
            'compliance': ComplianceModule(self),
            # 'backup_scanner': BackupScannerModule(self), # Integrated into EndpointModule
            'passive_scanner': PassiveScannerModule(self),
            'file_integrity': FileIntegrityModule(self)
        }
        
        # Initialize reporter
        self.reporter = Reporter(self.target_url)
    
    def _setup_session(self):
        """Setup HTTP session with optimized connection pooling"""
        import requests
        self.session = requests.Session()
        
        # Setup aggressive retry strategy for better reliability
        retry_strategy = Retry(
            total=2,  # Reduced retries for speed
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
            backoff_factor=0.5  # Faster backoff
        )
        
        # Setup HTTP adapter with enhanced connection pooling
        adapter = HTTPAdapter(
            pool_connections=self.threads * 2,  # More connection pools
            pool_maxsize=self.threads * 4,     # Larger pool size
            max_retries=retry_strategy
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
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
    
    def log(self, message: str, level: str = 'info') -> None:
        """Log message with appropriate formatting
        
        Args:
            message: Message to log
            level: Log level (info, debug, warning, error)
        """
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
    
    def make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with adaptive rate limiting and improved threading
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            **kwargs: Additional request parameters
            
        Returns:
            Response object or None if request failed
        """
        with self.thread_semaphore:
            try:
                # Control concurrent requests
                with self.request_lock:
                    if self.active_requests >= self.max_concurrent_requests:
                        time.sleep(0.05)  # Reduced wait time
                    self.active_requests += 1
                    self.request_count += 1
                
                # Adaptive delay based on success rate
                current_delay = self._get_adaptive_delay()
                if current_delay > 0:
                    time.sleep(current_delay)
                
                # Use session for request
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.timeout,
                    **kwargs
                )
                
                # Track success
                with self.request_lock:
                    self.success_count += 1
                
                # Periodic memory cleanup (less frequent)
                if self.request_count % self.memory_cleanup_interval == 0:
                    self._cleanup_memory()
                
                return response
                
            except Exception as e:
                # Track errors for adaptive rate limiting
                with self.request_lock:
                    self.error_count += 1
                
                self.log(f"Request failed for {url}: {str(e)}", 'debug')
                return None
            finally:
                # Decrement active request counter
                with self.request_lock:
                    self.active_requests = max(0, self.active_requests - 1)
    
    async def make_async_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[Any]:
        """Make async HTTP request using HTTPClient
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            **kwargs: Additional request parameters
            
        Returns:
            Response object or None if request failed
        """
        try:
            # Use HTTPClient for async requests
            if not hasattr(self, 'http_client'):
                self.http_client = HTTPClient(
                    timeout=self.timeout,
                    proxy=self.proxy,
                    user_agent=self.user_agent,
                    verify_ssl=self.verify_ssl
                )
            
            response = await self.http_client.make_async_request(url, method, **kwargs)
            return response
            
        except Exception as e:
            self.log(f"Async request failed for {url}: {str(e)}", 'debug')
            return None
    
    async def batch_async_requests(self, urls: List[str], method: str = 'GET', concurrency: int = 10) -> List[Optional[Any]]:
        """Make multiple async HTTP requests concurrently
        
        Args:
            urls: List of URLs to request
            method: HTTP method
            concurrency: Maximum concurrent requests
            
        Returns:
            List of response objects
        """
        try:
            if not hasattr(self, 'http_client'):
                self.http_client = HTTPClient(
                    timeout=self.timeout,
                    proxy=self.proxy,
                    user_agent=self.user_agent,
                    verify_ssl=self.verify_ssl
                )
            
            responses = await self.http_client.batch_requests(urls, method, concurrency)
            return responses
            
        except Exception as e:
            self.log(f"Batch async requests failed: {str(e)}", 'debug')
            return [None] * len(urls)
    
    def _get_adaptive_delay(self) -> float:
        """Calculate adaptive delay based on success/error ratio
        
        Returns:
            Calculated delay in seconds
        """
        total_requests = self.success_count + self.error_count
        if total_requests < 10:  # Not enough data yet
            return self.adaptive_delay
        
        error_rate = self.error_count / total_requests
        
        if error_rate < 0.05:  # Less than 5% errors - speed up
            return max(0.01, self.adaptive_delay * 0.5)
        elif error_rate < 0.15:  # Less than 15% errors - normal speed
            return self.adaptive_delay
        elif error_rate < 0.30:  # High error rate - slow down
            return self.adaptive_delay * 2
        else:  # Very high error rate - slow down significantly
            return self.adaptive_delay * 4
    
    def _cleanup_memory(self) -> None:
        """Clean up memory to prevent leaks"""
        try:
            # Clear response cache if it gets too large
            if len(self.response_cache) > self.max_cache_size:
                self.response_cache.clear()
            
            # Force garbage collection
            gc.collect()
            
            if self.verbose:
                self.log(f"Memory cleanup performed (request #{self.request_count})", 'debug')
                
        except Exception as e:
            self.log(f"Memory cleanup error: {str(e)}", 'debug')
    
    def verify_target(self) -> bool:
        """Verify target is accessible and is Discourse
        
        Returns:
            True if target is a valid Discourse forum
            
        Raises:
            Exception: If target is not accessible or not a Discourse forum
        """
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
    
    def run_scan(self, modules_to_run: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run the security scan with specified modules
        
        Args:
            modules_to_run: List of module names to run. If None, runs all enabled modules
            
        Returns:
            Dictionary containing scan results
        """
        if modules_to_run is None:
            modules_to_run = ['info', 'vuln', 'endpoint', 'user', 'cve', 'plugin_detection', 'plugin_bruteforce', 
                             'api', 'auth', 'config', 'crypto', 'network', 'plugin', 'waf_bypass', 'compliance']
        
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
                
                self.log(f"Running {module_name} module")
                
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
            # Final memory cleanup
            self._cleanup_memory()
            
            # Close session properly
            if self.session:
                try:
                    self.session.close()
                except Exception as e:
                    self.log(f"Error closing session: {str(e)}", 'debug')
            
            # Final garbage collection
            gc.collect()
    
    def generate_json_report(self, output_file: Optional[str] = None) -> str:
        """Generate JSON report
        
        Args:
            output_file: Output file path. If None, uses default naming
            
        Returns:
            Path to generated report file
        """
        try:
            report_file = self.reporter.generate_json_report(output_file)
            self.log(f"JSON report generated: {report_file}", 'success')
            return report_file
        except Exception as e:
            self.log(f"Failed to generate JSON report: {e}", 'error')
            return None
    
    def generate_html_report(self, output_file: Optional[str] = None) -> str:
        """Generate HTML report
        
        Args:
            output_file: Output file path. If None, uses default naming
            
        Returns:
            Path to generated report file
        """
        try:
            report_file = self.reporter.generate_html_report(output_file)
            self.log(f"HTML report generated: {report_file}", 'success')
            return report_file
        except Exception as e:
            self.log(f"Failed to generate HTML report: {e}", 'error')
            return None
    
    async def run_async_scan(self, modules_to_run: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run async security scan with improved performance
        
        Args:
            modules_to_run: List of module names to run
            
        Returns:
            Dictionary containing scan results
        """
        if modules_to_run is None:
            modules_to_run = ['info', 'vuln', 'endpoint', 'user', 'cve', 'plugin_detection', 'plugin_bruteforce', 
                             'api', 'auth', 'config', 'crypto', 'network', 'plugin', 'waf_bypass', 'compliance']
        
        self.log("Starting Async Discourse Security Scan", 'success')
        self.log(f"Target: {self.target_url}")
        self.log(f"Async Mode: Enabled")
        
        start_time = time.time()
        
        # Initialize HTTP client for async operations
        if not hasattr(self, 'http_client'):
            self.http_client = HTTPClient(
                timeout=self.timeout,
                proxy=self.proxy,
                user_agent=self.user_agent,
                verify_ssl=self.verify_ssl
            )
        
        # Run modules that support async operations
        async_results = {}
        
        # For now, run modules sequentially but with async HTTP requests
        # Future enhancement: Make modules themselves async
        for module_name in modules_to_run:
            try:
                if module_name == 'info':
                    module = InfoModule(self)
                elif module_name == 'vuln':
                    module = VulnerabilityModule(self)
                elif module_name == 'endpoint':
                    module = EndpointModule(self)
                elif module_name == 'user':
                    module = UserModule(self)
                elif module_name == 'cve':
                    module = CVEExploitModule(self)
                elif module_name == 'plugin_detection':
                    module = PluginDetectionModule(self)
                elif module_name == 'plugin_bruteforce':
                    module = PluginBruteforceModule(self)
                elif module_name == 'api':
                    module = APISecurityModule(self)
                elif module_name == 'auth':
                    module = AuthModule(self)
                elif module_name == 'config':
                    module = ConfigModule(self)
                elif module_name == 'crypto':
                    module = CryptoModule(self)
                elif module_name == 'network':
                    module = NetworkModule(self)
                elif module_name == 'plugin':
                    module = PluginModule(self)
                elif module_name == 'waf_bypass':
                    module = WAFBypassModule(self)
                elif module_name == 'compliance':
                    module = ComplianceModule(self)
                else:
                    self.log(f"Unknown module: {module_name}", 'warning')
                    continue
                
                self.log(f"Running {module_name} module (async mode)...", 'info')
                
                # Run module (currently sync, but uses async HTTP client)
                result = module.run()
                async_results[module_name] = result
                
                self.log(f"Completed {module_name} module", 'success')
                
            except Exception as e:
                self.log(f"Error in {module_name} module: {str(e)}", 'error')
                async_results[module_name] = {'error': str(e)}
        
        # Close async HTTP client
        if hasattr(self, 'http_client'):
            await self.http_client.aclose()
        
        async_results['scan_time'] = time.time() - start_time
        async_results['async_mode'] = True
        
        self.log(f"Async scan completed in {async_results['scan_time']:.2f} seconds", 'success')
        
        return async_results
    

    
    def get_base_url(self) -> str:
        """Get base URL of the target
        
        Returns:
            Base URL of the target
        """
        return self.target_url
    
    def get_session(self) -> requests.Session:
        """Get the current session
        
        Returns:
            Current requests session
        """
        return self.session