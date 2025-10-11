#!/usr/bin/env python3
"""Endpoint Scanner - Core scanning logic"""

from urllib.parse import urljoin
import requests


class EndpointScanner:
    """Scan and discover Discourse endpoints"""
    
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
    
    def scan_endpoint(self, endpoint):
        """Scan a single endpoint"""
        try:
            url = urljoin(self.target_url, endpoint)
            response = requests.get(url, timeout=self.timeout)
            
            return {
                'endpoint': endpoint,
                'url': url,
                'status_code': response.status_code,
                'accessible': response.status_code == 200,
                'size': len(response.content),
                'response_time': response.elapsed.total_seconds()
            }
        except Exception as e:
            return {
                'endpoint': endpoint,
                'accessible': False,
                'error': str(e)
            }
    
    def scan_multiple(self, endpoints):
        """Scan multiple endpoints"""
        results = []
        for endpoint in endpoints:
            result = self.scan_endpoint(endpoint)
            results.append(result)
        return results
