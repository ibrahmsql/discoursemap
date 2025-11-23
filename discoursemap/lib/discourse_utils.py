#!/usr/bin/env python3
"""
Discourse Utilities

Common utility functions for Discourse scanning.
"""

import re
import random
from urllib.parse import urlparse, urlunparse

# Common user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
]

def clean_url(url: str) -> str:
    """
    Clean and normalize URL.
    
    Args:
        url: Input URL
        
    Returns:
        Cleaned URL
    """
    if not url:
        return ""
        
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    parsed = urlparse(url)
    
    # Remove trailing slash from path
    path = parsed.path.rstrip('/')
    
    # Reconstruct URL
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

def validate_url(url: str) -> bool:
    """
    Validate URL format.
    
    Args:
        url: Input URL
        
    Returns:
        True if valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except ValueError:
        return False

def is_discourse_site(url: str, timeout: int = 10, verify_ssl: bool = True, **kwargs) -> bool:
    """
    Check if the target is a Discourse site.
    
    Args:
        url: Target URL
        timeout: Request timeout
        verify_ssl: Whether to verify SSL certificates (default: True)
        **kwargs: Additional arguments
        
    Returns:
        True if Discourse, False otherwise
    """
    import requests
    try:
        # Use kwargs if needed, or just ignore them
        response = requests.get(url, timeout=timeout, verify=verify_ssl, **kwargs)
        
        # Check for Discourse specific headers or content
        if 'Discourse' in response.headers.get('X-Generator', ''):
            return True
            
        if 'Discourse' in response.text or 'discourse-application' in response.text:
            return True
            
        return False
    except Exception:
        return False

def random_user_agent() -> str:
    """
    Get a random user agent.
    
    Returns:
        User agent string
    """
    return random.choice(USER_AGENTS)
