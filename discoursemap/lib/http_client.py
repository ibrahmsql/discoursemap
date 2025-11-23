#!/usr/bin/env python3
"""
HTTP Client

Wrapper around requests for consistent HTTP operations.
"""

import requests
from typing import Optional, Dict, Any

class HTTPClient:
    """HTTP Client wrapper"""
    
    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()
        
    def get(self, url: str, **kwargs) -> requests.Response:
        """Perform GET request"""
        return self.session.get(url, **kwargs)
        
    def post(self, url: str, **kwargs) -> requests.Response:
        """Perform POST request"""
        return self.session.post(url, **kwargs)
        
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Perform generic request"""
        return self.session.request(method, url, **kwargs)
