#!/usr/bin/env python3
"""
Load Testing Module

Tests server performance under various load conditions.
"""

import requests
import time
import threading
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin
import statistics


class LoadTester:
    """Tests server performance under load"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.results = []
        self.lock = threading.Lock()
    
    def run_load_test(self, concurrent_users: int = 10, duration: int = 30) -> Dict[str, Any]:
        """Run a load test with specified parameters"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting load test: {concurrent_users} users for {duration}s{Style.RESET_ALL}")
        
        self.results = []
        threads = []
        start_time = time.time()
        
        # Start worker threads
        for i in range(concurrent_users):
            thread = threading.Thread(
                target=self._worker_thread,
                args=(i, start_time, duration)
            )
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        return self._analyze_results()
    
    def _worker_thread(self, worker_id: int, start_time: float, duration: int):
        """Worker thread that makes requests"""
        endpoints = [
            '/',
            '/categories.json',
            '/latest.json',
            '/posts.json'
        ]
        
        while time.time() - start_time < duration:
            for endpoint in endpoints:
                try:
                    url = urljoin(self.target_url, endpoint)
                    request_start = time.time()
                    
                    response = self.session.get(url, timeout=10)
                    
                    request_end = time.time()
                    response_time = request_end - request_start
                    
                    with self.lock:
                        self.results.append({
                            'worker_id': worker_id,
                            'endpoint': endpoint,
                            'status_code': response.status_code,
                            'response_time': response_time,
                            'timestamp': request_start,
                            'success': response.status_code < 400
                        })
                
                except Exception as e:
                    with self.lock:
                        self.results.append({
                            'worker_id': worker_id,
                            'endpoint': endpoint,
                            'status_code': 0,
                            'response_time': 0,
                            'timestamp': time.time(),
                            'success': False,
                            'error': str(e)
                        })
                
                time.sleep(0.1)  # Small delay between requests
    
    def _analyze_results(self) -> Dict[str, Any]:
        """Analyze load test results"""
        if not self.results:
            return {'error': 'No results to analyze'}
        
        successful_requests = [r for r in self.results if r['success']]
        failed_requests = [r for r in self.results if not r['success']]
        
        response_times = [r['response_time'] for r in successful_requests]
        
        analysis = {
            'total_requests': len(self.results),
            'successful_requests': len(successful_requests),
            'failed_requests': len(failed_requests),
            'success_rate': len(successful_requests) / len(self.results) * 100,
            'requests_per_second': len(self.results) / (max([r['timestamp'] for r in self.results]) - min([r['timestamp'] for r in self.results])),
        }
        
        if response_times:
            analysis.update({
                'avg_response_time': statistics.mean(response_times),
                'min_response_time': min(response_times),
                'max_response_time': max(response_times),
                'median_response_time': statistics.median(response_times)
            })
            
            if len(response_times) > 1:
                analysis['std_dev_response_time'] = statistics.stdev(response_times)
        
        # Analyze by endpoint
        endpoint_stats = {}
        for endpoint in set([r['endpoint'] for r in self.results]):
            endpoint_results = [r for r in self.results if r['endpoint'] == endpoint]
            endpoint_successful = [r for r in endpoint_results if r['success']]
            endpoint_times = [r['response_time'] for r in endpoint_successful]
            
            endpoint_stats[endpoint] = {
                'total_requests': len(endpoint_results),
                'successful_requests': len(endpoint_successful),
                'success_rate': len(endpoint_successful) / len(endpoint_results) * 100 if endpoint_results else 0,
                'avg_response_time': statistics.mean(endpoint_times) if endpoint_times else 0
            }
        
        analysis['endpoint_stats'] = endpoint_stats
        
        return analysis
    
    def stress_test(self) -> Dict[str, Any]:
        """Run a stress test with increasing load"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Running stress test...{Style.RESET_ALL}")
        
        stress_results = []
        user_counts = [1, 5, 10, 20, 50]
        
        for user_count in user_counts:
            if self.verbose:
                print(f"{Fore.CYAN}[*] Testing with {user_count} concurrent users...{Style.RESET_ALL}")
            
            result = self.run_load_test(concurrent_users=user_count, duration=15)
            result['concurrent_users'] = user_count
            stress_results.append(result)
            
            time.sleep(5)  # Cool down between tests
        
        return {
            'stress_test_results': stress_results,
            'breaking_point': self._find_breaking_point(stress_results)
        }
    
    def _find_breaking_point(self, stress_results: List[Dict]) -> Optional[Dict]:
        """Find the breaking point where performance degrades significantly"""
        for i, result in enumerate(stress_results):
            if result.get('success_rate', 100) < 95 or result.get('avg_response_time', 0) > 5.0:
                return {
                    'concurrent_users': result['concurrent_users'],
                    'success_rate': result.get('success_rate'),
                    'avg_response_time': result.get('avg_response_time')
                }
        
        return None
    
    def memory_leak_test(self) -> Dict[str, Any]:
        """Test for potential memory leaks"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing for memory leaks...{Style.RESET_ALL}")
        
        # Make repeated requests to the same endpoint
        endpoint = urljoin(self.target_url, '/categories.json')
        response_times = []
        
        for i in range(100):
            try:
                start_time = time.time()
                response = self.session.get(endpoint, timeout=10)
                end_time = time.time()
                
                response_times.append(end_time - start_time)
                
                if i % 10 == 0 and self.verbose:
                    print(f"[*] Completed {i} requests...")
                
                time.sleep(0.1)
                
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error in memory leak test: {e}{Style.RESET_ALL}")
        
        # Analyze response time trend
        if len(response_times) >= 10:
            first_10 = response_times[:10]
            last_10 = response_times[-10:]
            
            avg_first = statistics.mean(first_10)
            avg_last = statistics.mean(last_10)
            
            degradation = ((avg_last - avg_first) / avg_first) * 100 if avg_first > 0 else 0
            
            return {
                'total_requests': len(response_times),
                'avg_response_time_first_10': avg_first,
                'avg_response_time_last_10': avg_last,
                'performance_degradation_percent': degradation,
                'potential_memory_leak': degradation > 20  # 20% degradation threshold
            }
        
        return {'error': 'Insufficient data for analysis'}