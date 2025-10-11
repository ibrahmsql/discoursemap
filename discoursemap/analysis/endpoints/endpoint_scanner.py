#!/usr/bin/env python3
"""Endpoint Scanner - Core scanning logic"""

from urllib.parse import urljoin
import requests


class EndpointScanner:
    """Scan and discover Discourse endpoints"""
    
    def __init__(self, target_url, timeout=10):
        """
        Initialize the EndpointScanner with a target base URL and request timeout.
        
        Parameters:
            target_url (str): Base URL to scan (e.g., "https://example.com"); used with endpoint paths to form full request URLs.
            timeout (int | float, optional): Request timeout in seconds. Defaults to 10.
        """
        self.target_url = target_url
        self.timeout = timeout
    
    def scan_endpoint(self, endpoint):
        """
        Scan a single endpoint path under the scanner's target URL.
        
        Parameters:
            endpoint (str): Endpoint path or relative URL to append to the scanner's target URL.
        
        Returns:
            dict: Result information with keys:
                - 'endpoint' (str): The provided endpoint path.
                - 'url' (str): Full URL requested (target URL joined with endpoint).
                - 'status_code' (int): HTTP response status code (present on success).
                - 'accessible' (bool): `true` if status code is 200, `false` otherwise.
                - 'size' (int): Length in bytes of the response content (present on success).
                - 'response_time' (float): Request elapsed time in seconds (present on success).
                - 'error' (str): Error message if the request failed (present when 'accessible' is `false` due to an exception).
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
            endpoints (Iterable[str]): An iterable of endpoint path strings to scan under the scanner's target URL.
        
        Returns:
            list[dict]: A list of result dictionaries, one per endpoint. Successful scan dictionaries contain:
                - 'endpoint' (str): the scanned endpoint path
                - 'url' (str): the full URL requested
                - 'status_code' (int): HTTP response status code
                - 'accessible' (bool): `True` if status_code == 200, `False` otherwise
                - 'size' (int): length of the response content in bytes
                - 'response_time' (float): elapsed time of the request in seconds
            Error result dictionaries contain:
                - 'endpoint' (str): the scanned endpoint path
                - 'accessible' (bool): `False`
                - 'error' (str): string representation of the encountered exception
        """
        results = []
        for endpoint in endpoints:
            result = self.scan_endpoint(endpoint)
            results.append(result)
        return results