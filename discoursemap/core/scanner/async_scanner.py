#!/usr/bin/env python3
"""
Async Scanner

Asynchronous scanning functionality for improved performance.
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional

from ...lib.http_client import HTTPClient


class AsyncScanner:
    """Asynchronous scanner functionality"""
    
    def __init__(self, base_scanner, module_manager):
        """
        Initialize async scanner.
        
        Args:
            base_scanner: Base scanner instance
            module_manager: Module manager instance
        """
        self.scanner = base_scanner
        self.module_manager = module_manager
        self.http_client = None
    
    async def make_async_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[Any]:
        """Make async HTTP request using HTTPClient"""
        try:
            if not self.http_client:
                self.http_client = HTTPClient(
                    timeout=self.scanner.timeout,
                    proxy=self.scanner.proxy,
                    user_agent=self.scanner.user_agent,
                    verify_ssl=self.scanner.verify_ssl
                )
            
            response = await self.http_client.make_async_request(url, method, **kwargs)
            return response
            
        except Exception as e:
            self.scanner.log(f"Async request failed for {url}: {str(e)}", 'debug')
            return None
    
    async def batch_async_requests(self, urls: List[str], method: str = 'GET', concurrency: int = 10) -> List[Optional[Any]]:
        """Make multiple async HTTP requests concurrently"""
        try:
            if not self.http_client:
                self.http_client = HTTPClient(
                    timeout=self.scanner.timeout,
                    proxy=self.scanner.proxy,
                    user_agent=self.scanner.user_agent,
                    verify_ssl=self.scanner.verify_ssl
                )
            
            responses = await self.http_client.batch_requests(urls, method, concurrency)
            return responses
            
        except Exception as e:
            self.scanner.log(f"Batch async requests failed: {str(e)}", 'debug')
            return [None] * len(urls)
    
    async def run_async_scan(self, modules_to_run: Optional[List[str]] = None) -> Dict[str, Any]:
        """Execute security modules in parallel using a thread pool"""
        if modules_to_run is None:
            modules_to_run = self.module_manager.get_default_modules() + [
                'badge', 'category', 'trust_level', 'rate_limit', 'session', 
                'admin', 'webhook', 'email', 'search', 'cache'
            ]
        
        self.scanner.log("Starting Async Discourse Security Scan", 'success')
        self.scanner.log(f"Target: {self.scanner.target_url}")
        self.scanner.log(f"Modules: {len(modules_to_run)}")
        self.scanner.log(f"Parallel Workers: {min(len(modules_to_run), self.scanner.threads)}")
        self.scanner.log(f"True Async Mode: ENABLED ✓")
        
        start_time = time.time()
        
        # Initialize HTTP client for async operations
        if not self.http_client:
            self.http_client = HTTPClient(
                timeout=self.scanner.timeout,
                proxy=self.scanner.proxy,
                user_agent=self.scanner.user_agent,
                verify_ssl=self.scanner.verify_ssl
            )
        
        # Run modules concurrently using ThreadPoolExecutor
        async_results = {}
        
        with ThreadPoolExecutor(max_workers=min(len(modules_to_run), self.scanner.threads)) as executor:
            # Submit all module tasks
            future_to_module = {}
            
            for module_name in modules_to_run:
                try:
                    # Get module instance
                    module = self.module_manager.get_module(module_name)
                    if not module:
                        self.scanner.log(f"Unknown module: {module_name}", 'warning')
                        continue
                    
                    self.scanner.log(f"Submitting {module_name} module for async execution...", 'info')
                    
                    # Submit module execution to thread pool
                    future = executor.submit(self.module_manager.run_module_safe, module, module_name)
                    future_to_module[future] = module_name
                    
                except Exception as e:
                    self.scanner.log(f"Error submitting {module_name}: {str(e)}", 'error')
                    async_results[module_name] = {'error': str(e)}
            
            # Collect results as they complete
            for future in as_completed(future_to_module):
                module_name = future_to_module[future]
                try:
                    result = future.result()
                    async_results[module_name] = result
                    self.scanner.log(f"Completed {module_name} module", 'success')
                except Exception as e:
                    self.scanner.log(f"Error in {module_name} module: {str(e)}", 'error')
                    async_results[module_name] = {'error': str(e)}
        
        # Close async HTTP client
        if self.http_client:
            await self.http_client.aclose()
        
        async_results['scan_time'] = time.time() - start_time
        async_results['async_mode'] = True
        
        self.scanner.log(f"Async scan completed in {async_results['scan_time']:.2f} seconds", 'success')
        
        return async_results