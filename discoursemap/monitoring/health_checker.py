#!/usr/bin/env python3
"""
Health Checker Module

Monitors Discourse instance health and availability.
"""

import requests
from typing import Dict, List, Optional, Any
from colorama import Fore, Style

from .health_checks import HealthChecks


class HealthChecker:
    """Monitors Discourse instance health"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.checks = HealthChecks(self.target_url, self.session, self.verbose)
    
    def comprehensive_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] Performing comprehensive health check...{Style.RESET_ALL}")
        
        health_results = {
            'basic_connectivity': self.checks.check_basic_connectivity(),
            'service_availability': self.checks.check_service_availability(),
            'database_health': self.checks.check_database_health(),
            'redis_health': self.checks.check_redis_health(),
            'ssl_certificate': self.checks.check_ssl_certificate(),
            'dns_resolution': self.checks.check_dns_resolution(),
            'response_headers': self.checks.check_response_headers(),
            'error_pages': self.checks.check_error_pages()
        }
        
        # Calculate overall health score
        health_results['overall_health'] = self._calculate_health_score(health_results)
        
        return health_results
    
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