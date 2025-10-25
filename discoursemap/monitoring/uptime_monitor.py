#!/usr/bin/env python3
"""
Uptime Monitor Module

Monitors Discourse instance uptime and availability over time.
"""

import requests
import time
import json
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin
from datetime import datetime, timedelta


class UptimeMonitor:
    """Monitors uptime and availability"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.monitoring_data = []
    
    def start_monitoring(self, duration_minutes: int = 60, check_interval: int = 30) -> Dict[str, Any]:
        """Start uptime monitoring for specified duration"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting uptime monitoring for {duration_minutes} minutes...{Style.RESET_ALL}")
        
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        self.monitoring_data = []
        
        while time.time() < end_time:
            check_result = self._perform_uptime_check()
            self.monitoring_data.append(check_result)
            
            if self.verbose:
                status = "UP" if check_result['is_up'] else "DOWN"
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Status: {status} - Response: {check_result.get('response_time', 'N/A')}s")
            
            time.sleep(check_interval)
        
        return self._analyze_uptime_data()
    
    def _perform_uptime_check(self) -> Dict[str, Any]:
        """Perform a single uptime check"""
        check_time = datetime.now()
        
        try:
            start_time = time.time()
            response = self.session.get(self.target_url, timeout=10)
            end_time = time.time()
            
            return {
                'timestamp': check_time.isoformat(),
                'is_up': response.status_code < 400,
                'status_code': response.status_code,
                'response_time': end_time - start_time,
                'error': None
            }
            
        except Exception as e:
            return {
                'timestamp': check_time.isoformat(),
                'is_up': False,
                'status_code': None,
                'response_time': None,
                'error': str(e)
            }
    
    def _analyze_uptime_data(self) -> Dict[str, Any]:
        """Analyze collected uptime data"""
        if not self.monitoring_data:
            return {'error': 'No monitoring data available'}
        
        total_checks = len(self.monitoring_data)
        up_checks = sum(1 for check in self.monitoring_data if check['is_up'])
        down_checks = total_checks - up_checks
        
        uptime_percentage = (up_checks / total_checks) * 100 if total_checks > 0 else 0
        
        # Calculate response time statistics
        response_times = [check['response_time'] for check in self.monitoring_data if check['response_time'] is not None]
        
        response_stats = {}
        if response_times:
            response_stats = {
                'avg_response_time': sum(response_times) / len(response_times),
                'min_response_time': min(response_times),
                'max_response_time': max(response_times),
                'total_response_samples': len(response_times)
            }
        
        # Identify downtime periods
        downtime_periods = self._identify_downtime_periods()
        
        return {
            'monitoring_summary': {
                'total_checks': total_checks,
                'up_checks': up_checks,
                'down_checks': down_checks,
                'uptime_percentage': uptime_percentage,
                'monitoring_duration': self._calculate_monitoring_duration()
            },
            'response_time_stats': response_stats,
            'downtime_periods': downtime_periods,
            'raw_data': self.monitoring_data
        }    

    def _identify_downtime_periods(self) -> List[Dict[str, Any]]:
        """Identify periods of downtime"""
        downtime_periods = []
        current_downtime = None
        
        for check in self.monitoring_data:
            if not check['is_up']:
                if current_downtime is None:
                    current_downtime = {
                        'start_time': check['timestamp'],
                        'end_time': check['timestamp'],
                        'duration_seconds': 0,
                        'error_types': [check.get('error', 'Unknown')]
                    }
                else:
                    current_downtime['end_time'] = check['timestamp']
                    if check.get('error') and check['error'] not in current_downtime['error_types']:
                        current_downtime['error_types'].append(check['error'])
            else:
                if current_downtime is not None:
                    # Calculate duration
                    start_dt = datetime.fromisoformat(current_downtime['start_time'])
                    end_dt = datetime.fromisoformat(current_downtime['end_time'])
                    current_downtime['duration_seconds'] = (end_dt - start_dt).total_seconds()
                    
                    downtime_periods.append(current_downtime)
                    current_downtime = None
        
        # Handle case where monitoring ended during downtime
        if current_downtime is not None:
            start_dt = datetime.fromisoformat(current_downtime['start_time'])
            end_dt = datetime.fromisoformat(current_downtime['end_time'])
            current_downtime['duration_seconds'] = (end_dt - start_dt).total_seconds()
            downtime_periods.append(current_downtime)
        
        return downtime_periods
    
    def _calculate_monitoring_duration(self) -> Dict[str, Any]:
        """Calculate total monitoring duration"""
        if len(self.monitoring_data) < 2:
            return {'duration_seconds': 0}
        
        start_time = datetime.fromisoformat(self.monitoring_data[0]['timestamp'])
        end_time = datetime.fromisoformat(self.monitoring_data[-1]['timestamp'])
        
        duration = end_time - start_time
        
        return {
            'duration_seconds': duration.total_seconds(),
            'duration_minutes': duration.total_seconds() / 60,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat()
        }
    
    def quick_availability_check(self) -> Dict[str, Any]:
        """Perform a quick availability check"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Performing quick availability check...{Style.RESET_ALL}")
        
        endpoints_to_check = [
            '/',
            '/categories.json',
            '/latest.json'
        ]
        
        results = {}
        
        for endpoint in endpoints_to_check:
            url = urljoin(self.target_url, endpoint)
            
            try:
                start_time = time.time()
                response = self.session.get(url, timeout=10)
                end_time = time.time()
                
                results[endpoint] = {
                    'available': response.status_code < 400,
                    'status_code': response.status_code,
                    'response_time': end_time - start_time
                }
                
            except Exception as e:
                results[endpoint] = {
                    'available': False,
                    'error': str(e)
                }
        
        available_endpoints = sum(1 for r in results.values() if r.get('available', False))
        total_endpoints = len(results)
        
        return {
            'overall_availability': (available_endpoints / total_endpoints) * 100 if total_endpoints > 0 else 0,
            'available_endpoints': available_endpoints,
            'total_endpoints': total_endpoints,
            'endpoint_results': results,
            'timestamp': datetime.now().isoformat()
        }