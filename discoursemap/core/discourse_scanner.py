#!/usr/bin/env python3
"""
Discourse Security Scanner - Main Scanner Engine

Core scanning functionality for Discourse forum security assessment
"""

import time
from typing import Optional, Dict, Any, List
from .scanner.base_scanner import BaseScanner
from .scanner.module_manager import ModuleManager
from .scanner.async_scanner import AsyncScanner
from .reporter import Reporter


class DiscourseScanner(BaseScanner):
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
        
        # Initialize base scanner
        super().__init__(
            target_url=target_url,
            threads=threads,
            timeout=timeout,
            proxy=proxy,
            user_agent=user_agent,
            delay=delay,
            verify_ssl=verify_ssl,
            verbose=verbose,
            quiet=quiet,
            config_file=config_file
        )
        
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
        
        # Initialize module manager and async scanner
        self.module_manager = ModuleManager(self)
        self.async_scanner = AsyncScanner(self, self.module_manager)
        
        # Initialize reporter
        self.reporter = Reporter(self.target_url)

    
    def run_scan(self, modules_to_run: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run the security scan with specified modules"""
        if modules_to_run is None:
            modules_to_run = self.module_manager.get_default_modules()
        
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
                module = self.module_manager.get_module(module_name)
                if not module:
                    self.log(f"Unknown module: {module_name}", 'warning')
                    continue
                
                self.log(f"Running {module_name} module")
                
                try:
                    module_results = self.module_manager.run_module_safe(module, module_name)
                    self.results['modules'][module_name] = module_results
                    self.reporter.add_module_results(module_name, module_results)
                    
                    # Log module completion
                    if module_results.get('vulnerabilities'):
                        vuln_count = len(module_results['vulnerabilities'])
                        self.log(f"{module_name.upper()} module completed - {vuln_count} issues found", 'success')
                    else:
                        self.log(f"{module_name.upper()} module completed", 'success')
                        
                except Exception as e:
                    self.log(f"Unexpected error in {module_name} module: {str(e)}", 'error')
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
            
            return self.results
            
        except KeyboardInterrupt:
            self.log("Scan interrupted by user", 'warning')
            return self.results
        except Exception as e:
            self.log(f"Unexpected scan failure: {str(e)}", 'error')
            if self.verbose:
                import traceback
                traceback.print_exc()
            raise
        
        finally:
            # Cleanup resources
            self.cleanup()
    
    def generate_json_report(self, output_file: Optional[str] = None) -> str:
        """Generate JSON report"""
        try:
            report_file = self.reporter.generate_json_report(output_file)
            self.log(f"JSON report generated: {report_file}", 'success')
            return report_file
        except Exception as e:
            self.log(f"Error generating JSON report: {e}", 'error')
            return None
    
    def generate_html_report(self, output_file: Optional[str] = None) -> str:
        """Generate HTML report"""
        try:
            report_file = self.reporter.generate_html_report(output_file)
            self.log(f"HTML report generated: {report_file}", 'success')
            return report_file
        except Exception as e:
            self.log(f"Error generating HTML report: {e}", 'error')
            return None
    
    async def run_async_scan(self, modules_to_run: Optional[List[str]] = None) -> Dict[str, Any]:
        """Execute security modules in parallel using async scanner"""
        return await self.async_scanner.run_async_scan(modules_to_run)
    
    async def make_async_request(self, url: str, method: str = 'GET', **kwargs):
        """Make async HTTP request"""
        return await self.async_scanner.make_async_request(url, method, **kwargs)
    
    async def batch_async_requests(self, urls: List[str], method: str = 'GET', concurrency: int = 10):
        """Make multiple async HTTP requests concurrently"""
        return await self.async_scanner.batch_async_requests(urls, method, concurrency)