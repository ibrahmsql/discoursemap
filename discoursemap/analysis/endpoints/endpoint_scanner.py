#!/usr/bin/env python3
"""Endpoint Scanner - Core scanning logic"""

from urllib.parse import urljoin
import requests


class EndpointScanner:
    """Scan and discover Discourse endpoints"""
    
    def __init__(self, target_url, timeout=10):
        """
        Create an EndpointScanner configured with the base URL to scan and a request timeout.
        
        Parameters:
        	target_url (str): Base URL against which endpoints will be resolved.
        	timeout (int | float): HTTP request timeout in seconds (default 10).
        """
        self.target_url = target_url
        self.timeout = timeout
    
    def scan_endpoint(self, endpoint):
        """
        Scan a single endpoint on the configured target URL.
        
        Builds the full request URL by joining the scanner's base URL with `endpoint` and issues an HTTP GET, returning a summary of the request result.
        
        Parameters:
            endpoint (str): Endpoint path or URL to scan. May be a relative path (joined with the scanner's `target_url`) or an absolute URL.
        
        Returns:
            dict: A dictionary summarizing the scan. On success the dictionary contains:
                - 'endpoint' (str): The original `endpoint` argument.
                - 'url' (str): The full URL requested.
                - 'status_code' (int): HTTP response status code.
                - 'accessible' (bool): `true` if `status_code` is 200, `false` otherwise.
                - 'size' (int): Length of the response content in bytes.
                - 'response_time' (float): Request elapsed time in seconds.
            On failure the dictionary contains:
                - 'endpoint' (str): The original `endpoint` argument.
                - 'accessible' (bool): `false`.
                - 'error' (str): String representation of the encountered exception.
        """
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
        """
        Scan a sequence of endpoint paths and return their individual scan results.
        
        Parameters:
            endpoints (iterable[str]): Iterable of endpoint paths (relative or absolute) to scan. The order of results matches the input order.
        
        Returns:
            list[dict]: A list of result dictionaries for each endpoint. Each dictionary contains information about the scanned endpoint such as 'endpoint', 'url' (when available), 'status_code' (when available), 'accessible' (boolean), 'size' (when available), 'response_time' (when available), and 'error' (when an exception occurred).
        """
        results = []
        for endpoint in endpoints:
            result = self.scan_endpoint(endpoint)
            results.append(result)
        return results