#!/usr/bin/env python3
"""
HTTP Utilities for Discourse-Specific Modules

Centralized HTTP request handling with:
- Timeout management
- Error handling
- Consistent headers
- Rate limiting awareness
"""

import requests
from typing import Optional, Dict, Any


def make_request(
    url: str,
    method: str = 'GET',
    timeout: int = 10,
    headers: Optional[Dict[str, str]] = None,
    json_data: Optional[Dict[str, Any]] = None,
    **kwargs
) -> Optional[requests.Response]:
    """
    Centralized HTTP request handler
    
    Args:
        url: Target URL
        method: HTTP method (GET, POST, PUT, DELETE)
        timeout: Request timeout in seconds
        headers: Optional custom headers
        json_data: Optional JSON payload
        **kwargs: Additional requests arguments
    
    Returns:
        Response object or None on failure
    """
    default_headers = {
        'User-Agent': 'DiscourseMap/2.0 Security Scanner',
        'Accept': 'application/json'
    }
    
    if headers:
        default_headers.update(headers)
    
    try:
        if method.upper() == 'GET':
            response = requests.get(url, headers=default_headers, timeout=timeout, **kwargs)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=default_headers, json=json_data, timeout=timeout, **kwargs)
        elif method.upper() == 'PUT':
            response = requests.put(url, headers=default_headers, json=json_data, timeout=timeout, **kwargs)
        elif method.upper() == 'DELETE':
            response = requests.delete(url, headers=default_headers, timeout=timeout, **kwargs)
        else:
            return None
        
        return response
    except requests.exceptions.RequestException:
        return None


def get_json(url: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """
    GET request and return JSON data
    
    Args:
        url: Target URL
        timeout: Request timeout
    
    Returns:
        JSON dict or None
    """
    response = make_request(url, timeout=timeout)
    if response and response.status_code == 200:
        try:
            return response.json()
        except:
            return None
    return None
