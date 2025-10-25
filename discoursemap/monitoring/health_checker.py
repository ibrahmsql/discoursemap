#!/usr/bin/env python3
"""
Health Checker Module

Monitors Discourse instance health and availability.
"""

import requests
import time
import json
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin
import socket


class HealthChecker:
    """Monitors Discourse instance health"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
    
    def comprehensive_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] Performing comprehensive health check...{Style.RESET_ALL}")
        
        health_results = {
            'basic_connectivity': self.check_basic_connectivity(),
            'service_availability': self.check_service_availability(),
            'database_health': self.check_database_health(),
            'redis_health': self.check_redis_health(),
            'ssl_certificate': self.check_ssl_certificate(),
            'dns_resolution': self.check_dns_resolution(),
            'response_headers': self.check_response_headers(),
            'error_pages': self.check_error_pages()
        }
        
        # Calculate overall health score
        health_results['overall_health'] = self._calculate_health_score(health_results)
        
        return health_results
    
    def check_basic_connectivity(self) -> Dict[str, Any]:
        """Check basic HTTP connectivity"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking basic connectivity...{Style.RESET_ALL}")
        
        try:
            start_time = time.time()
            response = self.session.get(self.target_url, timeout=10)
            end_time = time.time()
            
            return {
                'status': 'healthy',
                'status_code': response.status_code,
                'response_time': end_time - start_time,
                'accessible': response.status_code < 400
            }
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'accessible': False
            }
    
    def check_service_availability(self) -> Dict[str, Any]:
        """Check availability of key Discourse services"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking service availability...{Style.RESET_ALL}")
        
        critical_endpoints = [
            '/',
            '/categories.json',
            '/latest.json',
            '/session/csrf'
        ]
        
        service_status = {}
        
        for endpoint in critical_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            try:
                response = self.session.get(url, timeout=10)
                service_status[endpoint] = {
                    'status': 'available',
                    'status_code': response.status_code,
                    'healthy': response.status_code < 400
                }
            except Exception as e:
                service_status[endpoint] = {
                    'status': 'unavailable',
                    'error': str(e),
                    'healthy': False
                }
        
        healthy_services = sum(1 for s in service_status.values() if s.get('healthy', False))
        total_services = len(service_status)
        
        return {
            'services': service_status,
            'healthy_services': healthy_services,
            'total_services': total_services,
            'availability_percentage': (healthy_services / total_services) * 100 if total_services > 0 else 0
        }
    
    def check_database_health(self) -> Dict[str, Any]:
        """Check database connectivity and health"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking database health...{Style.RESET_ALL}")
        
        # Test endpoints that require database access
        db_endpoints = [
            '/categories.json',
            '/users.json',
            '/posts.json'
        ]
        
        db_responses = []
        
        for endpoint in db_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            try:
                start_time = time.time()
                response = self.session.get(url, timeout=15)
                end_time = time.time()
                
                db_responses.append({
                    'endpoint': endpoint,
                    'status_code': response.status_code,
                    'response_time': end_time - start_time,
                    'success': response.status_code == 200
                })
                
            except Exception as e:
                db_responses.append({
                    'endpoint': endpoint,
                    'error': str(e),
                    'success': False
                })
        
        successful_queries = sum(1 for r in db_responses if r.get('success', False))
        avg_response_time = sum(r.get('response_time', 0) for r in db_responses if r.get('success', False))
        avg_response_time = avg_response_time / successful_queries if successful_queries > 0 else 0
        
        return {
            'database_accessible': successful_queries > 0,
            'successful_queries': successful_queries,
            'total_queries': len(db_responses),
            'avg_query_time': avg_response_time,
            'query_results': db_responses,
            'health_status': 'healthy' if successful_queries == len(db_responses) else 'degraded' if successful_queries > 0 else 'unhealthy'
        }
    
    def check_redis_health(self) -> Dict[str, Any]:
        """Check Redis connectivity and health"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking Redis health...{Style.RESET_ALL}")
        
        # Test session-related endpoints that typically use Redis
        redis_endpoints = [
            '/session/csrf',
            '/notifications.json'
        ]
        
        redis_responses = []
        
        for endpoint in redis_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            try:
                response = self.session.get(url, timeout=10)
                redis_responses.append({
                    'endpoint': endpoint,
                    'status_code': response.status_code,
                    'success': response.status_code < 500  # 5xx errors might indicate Redis issues
                })
                
            except Exception as e:
                redis_responses.append({
                    'endpoint': endpoint,
                    'error': str(e),
                    'success': False
                })
        
        successful_responses = sum(1 for r in redis_responses if r.get('success', False))
        
        return {
            'redis_accessible': successful_responses > 0,
            'successful_responses': successful_responses,
            'total_tests': len(redis_responses),
            'responses': redis_responses,
            'health_status': 'healthy' if successful_responses == len(redis_responses) else 'degraded' if successful_responses > 0 else 'unknown'
        }
    
    def check_ssl_certificate(self) -> Dict[str, Any]:
        """Check SSL certificate health"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking SSL certificate...{Style.RESET_ALL}")
        
        if not self.target_url.startswith('https://'):
            return {
                'ssl_enabled': False,
                'status': 'no_ssl'
            }
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=True)
            
            return {
                'ssl_enabled': True,
                'certificate_valid': True,
                'status': 'valid',
                'status_code': response.status_code
            }
            
        except requests.exceptions.SSLError as e:
            return {
                'ssl_enabled': True,
                'certificate_valid': False,
                'status': 'invalid',
                'error': str(e)
            }
        except Exception as e:
            return {
                'ssl_enabled': True,
                'certificate_valid': False,
                'status': 'error',
                'error': str(e)
            }
    
    def check_dns_resolution(self) -> Dict[str, Any]:
        """Check DNS resolution"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking DNS resolution...{Style.RESET_ALL}")
        
        try:
            # Extract hostname from URL
            from urllib.parse import urlparse
            parsed_url = urlparse(self.target_url)
            hostname = parsed_url.hostname
            
            if not hostname:
                return {'status': 'error', 'error': 'Could not extract hostname'}
            
            # Resolve DNS
            start_time = time.time()
            ip_address = socket.gethostbyname(hostname)
            end_time = time.time()
            
            return {
                'status': 'resolved',
                'hostname': hostname,
                'ip_address': ip_address,
                'resolution_time': end_time - start_time
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    def check_response_headers(self) -> Dict[str, Any]:
        """Check important response headers"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking response headers...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            important_headers = {
                'server': response.headers.get('Server'),
                'x_frame_options': response.headers.get('X-Frame-Options'),
                'x_content_type_options': response.headers.get('X-Content-Type-Options'),
                'x_xss_protection': response.headers.get('X-XSS-Protection'),
                'strict_transport_security': response.headers.get('Strict-Transport-Security'),
                'content_security_policy': response.headers.get('Content-Security-Policy'),
                'cache_control': response.headers.get('Cache-Control')
            }
            
            # Check for security headers
            security_score = 0
            security_headers = ['x_frame_options', 'x_content_type_options', 'x_xss_protection', 'strict_transport_security']
            
            for header in security_headers:
                if important_headers[header]:
                    security_score += 1
            
            return {
                'headers': important_headers,
                'security_headers_present': security_score,
                'total_security_headers': len(security_headers),
                'security_score': (security_score / len(security_headers)) * 100
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def check_error_pages(self) -> Dict[str, Any]:
        """Check error page handling"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking error page handling...{Style.RESET_ALL}")
        
        error_tests = [
            ('/nonexistent-page-12345', 404),
            ('/admin/secret-area', [401, 403, 404]),
            ('/api/nonexistent', 404)
        ]
        
        error_results = []
        
        for test_path, expected_codes in error_tests:
            url = urljoin(self.target_url, test_path)
            
            try:
                response = self.session.get(url, timeout=10)
                
                if isinstance(expected_codes, list):
                    correct_error = response.status_code in expected_codes
                else:
                    correct_error = response.status_code == expected_codes
                
                error_results.append({
                    'path': test_path,
                    'expected_codes': expected_codes,
                    'actual_code': response.status_code,
                    'correct_error_handling': correct_error,
                    'response_length': len(response.content)
                })
                
            except Exception as e:
                error_results.append({
                    'path': test_path,
                    'error': str(e),
                    'correct_error_handling': False
                })
        
        correct_errors = sum(1 for r in error_results if r.get('correct_error_handling', False))
        
        return {
            'error_tests': error_results,
            'correct_error_handling': correct_errors,
            'total_tests': len(error_results),
            'error_handling_score': (correct_errors / len(error_results)) * 100 if error_results else 0
        }
    
    def _calculate_health_score(self, health_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall health score"""
        scores = []
        
        # Basic connectivity (25% weight)
        if health_results['basic_connectivity'].get('accessible', False):
            scores.append(25)
        
        # Service availability (25% weight)
        availability = health_results['service_availability'].get('availability_percentage', 0)
        scores.append((availability / 100) * 25)
        
        # Database health (20% weight)
        db_health = health_results['database_health']
        if db_health.get('health_status') == 'healthy':
            scores.append(20)
        elif db_health.get('health_status') == 'degraded':
            scores.append(10)
        
        # SSL certificate (15% weight)
        ssl_check = health_results['ssl_certificate']
        if ssl_check.get('certificate_valid', False):
            scores.append(15)
        elif ssl_check.get('ssl_enabled', False):
            scores.append(7)
        
        # Security headers (10% weight)
        headers_check = health_results['response_headers']
        if 'security_score' in headers_check:
            scores.append((headers_check['security_score'] / 100) * 10)
        
        # Error handling (5% weight)
        error_check = health_results['error_pages']
        if 'error_handling_score' in error_check:
            scores.append((error_check['error_handling_score'] / 100) * 5)
        
        total_score = sum(scores)
        
        if total_score >= 90:
            status = 'EXCELLENT'
        elif total_score >= 75:
            status = 'GOOD'
        elif total_score >= 60:
            status = 'FAIR'
        elif total_score >= 40:
            status = 'POOR'
        else:
            status = 'CRITICAL'
        
        return {
            'overall_score': total_score,
            'max_score': 100,
            'health_status': status,
            'component_scores': scores
        }