#!/usr/bin/env python3
"""
Response Time Analyzer

Analyzes server response times and performance metrics.
"""

import requests
import time
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin
import statistics


class ResponseAnalyzer:
    """Analyzes server response times and performance"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
    
    def analyze_endpoint_performance(self, endpoints: Optional[List[str]] = None) -> Dict[str, Any]:
        """Analyze performance of specific endpoints"""
        if endpoints is None:
            endpoints = [
                '/',
                '/categories.json',
                '/latest.json',
                '/posts.json',
                '/users.json',
                '/search.json'
            ]
        
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Analyzing endpoint performance...{Style.RESET_ALL}")
        
        results = {}
        
        for endpoint in endpoints:
            if self.verbose:
                print(f"[*] Testing {endpoint}...")
            
            endpoint_results = self._test_endpoint_performance(endpoint)
            results[endpoint] = endpoint_results
        
        return {
            'endpoint_analysis': results,
            'summary': self._generate_performance_summary(results)
        }
    
    def _test_endpoint_performance(self, endpoint: str, iterations: int = 10) -> Dict[str, Any]:
        """Test performance of a single endpoint"""
        url = urljoin(self.target_url, endpoint)
        response_times = []
        status_codes = []
        content_lengths = []
        
        for i in range(iterations):
            try:
                start_time = time.time()
                response = self.session.get(url, timeout=30)
                end_time = time.time()
                
                response_time = end_time - start_time
                response_times.append(response_time)
                status_codes.append(response.status_code)
                
                content_length = len(response.content)
                content_lengths.append(content_length)
                
                time.sleep(0.5)  # Small delay between requests
                
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing {endpoint}: {e}{Style.RESET_ALL}")
        
        if not response_times:
            return {'error': 'No successful requests'}
        
        return {
            'iterations': iterations,
            'successful_requests': len(response_times),
            'avg_response_time': statistics.mean(response_times),
            'min_response_time': min(response_times),
            'max_response_time': max(response_times),
            'median_response_time': statistics.median(response_times),
            'std_dev_response_time': statistics.stdev(response_times) if len(response_times) > 1 else 0,
            'avg_content_length': statistics.mean(content_lengths),
            'status_codes': list(set(status_codes)),
            'response_times': response_times
        }
    
    def _generate_performance_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of performance analysis"""
        all_response_times = []
        slow_endpoints = []
        fast_endpoints = []
        
        for endpoint, data in results.items():
            if 'avg_response_time' in data:
                avg_time = data['avg_response_time']
                all_response_times.append(avg_time)
                
                if avg_time > 2.0:  # Slow threshold: 2 seconds
                    slow_endpoints.append({
                        'endpoint': endpoint,
                        'avg_response_time': avg_time
                    })
                elif avg_time < 0.5:  # Fast threshold: 0.5 seconds
                    fast_endpoints.append({
                        'endpoint': endpoint,
                        'avg_response_time': avg_time
                    })
        
        summary = {
            'total_endpoints_tested': len(results),
            'slow_endpoints': slow_endpoints,
            'fast_endpoints': fast_endpoints,
        }
        
        if all_response_times:
            summary.update({
                'overall_avg_response_time': statistics.mean(all_response_times),
                'overall_median_response_time': statistics.median(all_response_times),
                'performance_rating': self._calculate_performance_rating(all_response_times)
            })
        
        return summary
    
    def _calculate_performance_rating(self, response_times: List[float]) -> str:
        """Calculate overall performance rating"""
        avg_time = statistics.mean(response_times)
        
        if avg_time < 0.5:
            return 'EXCELLENT'
        elif avg_time < 1.0:
            return 'GOOD'
        elif avg_time < 2.0:
            return 'FAIR'
        elif avg_time < 5.0:
            return 'POOR'
        else:
            return 'VERY_POOR'
    
    def analyze_caching_effectiveness(self) -> Dict[str, Any]:
        """Analyze caching effectiveness"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Analyzing caching effectiveness...{Style.RESET_ALL}")
        
        cache_test_endpoints = [
            '/categories.json',
            '/latest.json',
            '/assets/application.js',
            '/assets/application.css'
        ]
        
        caching_results = {}
        
        for endpoint in cache_test_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            try:
                # First request
                start_time = time.time()
                response1 = self.session.get(url, timeout=10)
                first_request_time = time.time() - start_time
                
                # Second request (should be cached)
                start_time = time.time()
                response2 = self.session.get(url, timeout=10)
                second_request_time = time.time() - start_time
                
                # Analyze caching headers
                cache_headers = {
                    'cache-control': response1.headers.get('Cache-Control'),
                    'etag': response1.headers.get('ETag'),
                    'last-modified': response1.headers.get('Last-Modified'),
                    'expires': response1.headers.get('Expires')
                }
                
                # Calculate improvement
                improvement = ((first_request_time - second_request_time) / first_request_time) * 100 if first_request_time > 0 else 0
                
                caching_results[endpoint] = {
                    'first_request_time': first_request_time,
                    'second_request_time': second_request_time,
                    'improvement_percent': improvement,
                    'cache_headers': cache_headers,
                    'likely_cached': improvement > 10  # 10% improvement threshold
                }
                
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing caching for {endpoint}: {e}{Style.RESET_ALL}")
        
        return {
            'caching_analysis': caching_results,
            'overall_caching_effectiveness': self._calculate_caching_effectiveness(caching_results)
        }
    
    def _calculate_caching_effectiveness(self, results: Dict[str, Any]) -> str:
        """Calculate overall caching effectiveness"""
        cached_endpoints = sum(1 for data in results.values() if data.get('likely_cached', False))
        total_endpoints = len(results)
        
        if total_endpoints == 0:
            return 'UNKNOWN'
        
        effectiveness_ratio = cached_endpoints / total_endpoints
        
        if effectiveness_ratio >= 0.8:
            return 'EXCELLENT'
        elif effectiveness_ratio >= 0.6:
            return 'GOOD'
        elif effectiveness_ratio >= 0.4:
            return 'FAIR'
        elif effectiveness_ratio >= 0.2:
            return 'POOR'
        else:
            return 'VERY_POOR'
    
    def analyze_compression(self) -> Dict[str, Any]:
        """Analyze response compression"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Analyzing response compression...{Style.RESET_ALL}")
        
        test_endpoints = [
            '/',
            '/categories.json',
            '/latest.json'
        ]
        
        compression_results = {}
        
        for endpoint in test_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            try:
                # Request without compression
                headers_no_compression = {'Accept-Encoding': 'identity'}
                response_uncompressed = self.session.get(url, headers=headers_no_compression, timeout=10)
                
                # Request with compression
                headers_compression = {'Accept-Encoding': 'gzip, deflate'}
                response_compressed = self.session.get(url, headers=headers_compression, timeout=10)
                
                uncompressed_size = len(response_uncompressed.content)
                compressed_size = len(response_compressed.content)
                
                compression_ratio = (1 - (compressed_size / uncompressed_size)) * 100 if uncompressed_size > 0 else 0
                
                compression_results[endpoint] = {
                    'uncompressed_size': uncompressed_size,
                    'compressed_size': compressed_size,
                    'compression_ratio': compression_ratio,
                    'compression_enabled': response_compressed.headers.get('Content-Encoding') is not None,
                    'content_encoding': response_compressed.headers.get('Content-Encoding')
                }
                
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing compression for {endpoint}: {e}{Style.RESET_ALL}")
        
        return {
            'compression_analysis': compression_results,
            'overall_compression_effectiveness': self._calculate_compression_effectiveness(compression_results)
        }
    
    def _calculate_compression_effectiveness(self, results: Dict[str, Any]) -> str:
        """Calculate overall compression effectiveness"""
        compression_ratios = [data.get('compression_ratio', 0) for data in results.values()]
        
        if not compression_ratios:
            return 'UNKNOWN'
        
        avg_compression = statistics.mean(compression_ratios)
        
        if avg_compression >= 70:
            return 'EXCELLENT'
        elif avg_compression >= 50:
            return 'GOOD'
        elif avg_compression >= 30:
            return 'FAIR'
        elif avg_compression >= 10:
            return 'POOR'
        else:
            return 'VERY_POOR'