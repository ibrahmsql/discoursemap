#!/usr/bin/env python3
"""
Base Scanner

Core scanning functionality and base class for Discourse security scanner.
"""

import time
import gc
import weakref
import threading
from threading import Lock, BoundedSemaphore
from typing import Optional, Dict, Any, List
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style

from ...lib.discourse_utils import (
    clean_url, validate_url, is_discourse_site, random_user_agent
)
from ...lib.config_manager import ConfigManager
from ...lib.http_client import HTTPClient


class BaseScanner:
    """Base scanner class with core functionality"""
    
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
        Initialize the base scanner.
        
        Args:
            target_url: Target URL
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
        config = self.config_manager.scan_config
        
        # Set configuration
        self.target_url = clean_url(target_url)
        self.threads = min(threads if threads is not None else config.threads, 50)
        self.timeout = timeout if timeout is not None else config.timeout
        proxy_url = proxy if proxy is not None else config.proxy
        self.proxy = {'http': proxy_url, 'https': proxy_url} if proxy_url else None
        self.user_agent = user_agent if user_agent is not None else (config.user_agent or random_user_agent())
        self.delay = delay if delay is not None else config.delay
        self.verify_ssl = verify_ssl if verify_ssl is not None else config.verify_ssl
        self.verbose = verbose
        self.quiet = quiet
        
        # Threading controls
        self.thread_semaphore = BoundedSemaphore(self.threads)
        self.request_lock = Lock()
        self.active_requests = 0
        self.max_concurrent_requests = self.threads * 3
        
        # Memory management
        self.response_cache = weakref.WeakValueDictionary()
        self.max_cache_size = 100
        self.memory_cleanup_interval = 50
        self.request_count = 0
        
        # Adaptive rate limiting
        self.success_count = 0
        self.error_count = 0
        self.adaptive_delay = delay if delay is not None else 0.1
        
        # Color definitions
        self.colors = {
            'info': Fore.CYAN,
            'success': Fore.GREEN,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'debug': Fore.MAGENTA,
            'reset': Style.RESET_ALL
        }
        
        # Session for connection reuse
        self.session = None
        self._setup_session()
    
    def _setup_session(self):
        """Setup HTTP session with optimized connection pooling"""
        self.session = requests.Session()
        
        # Setup retry strategy
        retry_strategy = Retry(
            total=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
            backoff_factor=0.5
        )
        
        # Setup HTTP adapter
        adapter = HTTPAdapter(
            pool_connections=self.threads * 2,
            pool_maxsize=self.threads * 4,
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
        """Standardized logging system"""
        if not hasattr(self, '_log_config'):
            self._log_config = {
                'enabled_levels': ['info', 'success', 'warning', 'error'] + (['debug'] if self.verbose else []),
                'quiet_mode': self.quiet,
                'colors': {
                    'info': Fore.CYAN,
                    'success': Fore.GREEN,
                    'warning': Fore.YELLOW,
                    'error': Fore.RED,
                    'debug': Fore.MAGENTA
                },
                'prefixes': {
                    'info': '[*]',
                    'success': '[+]',
                    'warning': '[!]',
                    'error': '[!]',
                    'debug': '[DEBUG]'
                }
            }
        
        # Filter based on configuration
        if self._log_config['quiet_mode'] and level not in ['error', 'warning']:
            return
        
        if level not in self._log_config['enabled_levels']:
            return
        
        # Format and output message
        color = self._log_config['colors'].get(level, Fore.WHITE)
        prefix = self._log_config['prefixes'].get(level, '[*]')
        
        print(f"{color}{prefix} {message}{Style.RESET_ALL}")
    
    def make_request(self, url: str, method: str = 'GET', timeout: Optional[int] = None, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with adaptive rate limiting"""
        with self.thread_semaphore:
            try:
                # Control concurrent requests
                with self.request_lock:
                    if self.active_requests >= self.max_concurrent_requests:
                        time.sleep(0.05)
                    self.active_requests += 1
                    self.request_count += 1
                
                # Adaptive delay
                current_delay = self._get_adaptive_delay()
                if current_delay > 0:
                    time.sleep(current_delay)
                
                # Make request
                request_timeout = timeout if timeout is not None else self.timeout
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=request_timeout,
                    **kwargs
                )
                
                # Track success
                with self.request_lock:
                    self.success_count += 1
                
                # Memory cleanup
                if self.request_count % (self.memory_cleanup_interval * 2) == 0:
                    self._cleanup_memory()
                
                return response
                
            except Exception as e:
                # Track errors
                with self.request_lock:
                    self.error_count += 1
                
                self.log(f"Request failed for {url}: {str(e)}", 'debug')
                return None
            finally:
                # Decrement active request counter
                with self.request_lock:
                    self.active_requests = max(0, self.active_requests - 1)
    
    def _get_adaptive_delay(self) -> float:
        """Calculate adaptive delay based on success/error ratio"""
        total_requests = self.success_count + self.error_count
        if total_requests < 10:
            return self.adaptive_delay
        
        error_rate = self.error_count / total_requests
        
        if error_rate < 0.05:
            return max(0.01, self.adaptive_delay * 0.5)
        elif error_rate < 0.15:
            return self.adaptive_delay
        elif error_rate < 0.30:
            return self.adaptive_delay * 2
        else:
            return self.adaptive_delay * 4
    
    def _cleanup_memory(self) -> None:
        """Clean up memory to prevent leaks"""
        try:
            # Clear response cache if it gets too large
            if len(self.response_cache) > self.max_cache_size:
                oldest_keys = list(self.response_cache.keys())[:len(self.response_cache)//2]
                for key in oldest_keys:
                    self.response_cache.pop(key, None)
            
            # Force garbage collection
            if self.request_count % (self.memory_cleanup_interval * 5) == 0:
                gc.collect()
                
        except Exception:
            pass
    
    def verify_target(self) -> bool:
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
            self.log("Scan aborted - target verification failed.", 'error')
            raise Exception("Target is not a Discourse forum. Scan aborted.")
        else:
            self.log("Target confirmed as Discourse forum", 'success')
        
        return True
    
    def get_base_url(self) -> str:
        """Get base URL of the target"""
        return self.target_url
    
    def get_session(self) -> requests.Session:
        """Get the current session"""
        return self.session
    
    def cleanup(self):
        """Cleanup resources"""
        self._cleanup_memory()
        
        if self.session:
            try:
                self.session.close()
            except Exception as e:
                self.log(f"Error closing session: {str(e)}", 'debug')
        
        gc.collect()