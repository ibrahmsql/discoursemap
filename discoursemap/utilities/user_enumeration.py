#!/usr/bin/env python3
"""
User Enumeration Helper Module

Handles user discovery and enumeration tasks.
"""

import re
import json
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from typing import Dict, List, Any


class UserEnumerator:
    """User enumeration functionality"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.discovered_users = []
    
    def discover_users_from_public_endpoints(self):
        """Discover users from public Discourse endpoints"""
        endpoints = [
            '/about.json',
            '/users.json',
            '/directory_items.json',
            '/u/search/users'
        ]
        
        for endpoint in endpoints:
            try:
                url = urljoin(self.scanner.target_url, endpoint)
                response = self.scanner.make_request(url, timeout=10)
                
                if response and response.status_code == 200:
                    self._extract_users_from_json(response.json(), endpoint)
            except Exception:
                continue
        
        return self.discovered_users
    
    def discover_users_from_directory(self):
        """Discover users from directory page"""
        try:
            url = urljoin(self.scanner.target_url, '/u')
            response = self.scanner.make_request(url, timeout=10)
            
            if response and response.status_code == 200:
                self._extract_users_from_html(response.text)
        except Exception:
            pass
        
        return self.discovered_users
    
    def discover_users_from_search(self, query='a'):
        """Discover users via search endpoint"""
        try:
            url = urljoin(self.scanner.target_url, '/u/search/users')
            response = self.scanner.make_request(
                url,
                params={'term': query},
                timeout=10
            )
            
            if response and response.status_code == 200:
                data = response.json()
                users = data.get('users', [])
                
                for user in users:
                    self.discovered_users.append({
                        'username': user.get('username'),
                        'name': user.get('name'),
                        'source': 'search'
                    })
        except Exception:
            pass
        
        return self.discovered_users
    
    def _extract_users_from_json(self, data, endpoint):
        """Extract users from JSON response"""
        if isinstance(data, dict):
            # Check common keys
            for key in ['users', 'directory_items', 'about', 'members']:
                if key in data:
                    items = data[key]
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict):
                                username = item.get('username') or item.get('user', {}).get('username')
                                if username:
                                    self.discovered_users.append({
                                        'username': username,
                                        'name': item.get('name', ''),
                                        'source': endpoint
                                    })
    
    def _extract_users_from_html(self, html_content):
        """Extract users from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find user links
        user_links = soup.find_all('a', href=re.compile(r'/u/[^/]+'))
        
        for link in user_links:
            href = link.get('href', '')
            match = re.search(r'/u/([^/]+)', href)
            if match:
                username = match.group(1)
                self.discovered_users.append({
                    'username': username,
                    'source': 'html_parsing'
                })
    
    def test_user_enumeration(self, usernames):
        """Test if usernames can be enumerated via login"""
        results = []
        
        login_url = urljoin(self.scanner.target_url, '/session')
        
        for username in usernames[:10]:  # Limit to 10 tests
            try:
                response = self.scanner.make_request(
                    login_url,
                    method='POST',
                    json={'login': username, 'password': 'invalid'},
                    timeout=5
                )
                
                if response:
                    # Check if response differs for valid/invalid users
                    if 'user' in response.text.lower() or 'account' in response.text.lower():
                        results.append({
                            'username': username,
                            'enumerable': True,
                            'method': 'login_response'
                        })
            except Exception:
                continue
        
        return results
    
    def test_forgot_password_enumeration(self, usernames):
        """Test password reset enumeration"""
        results = []
        
        reset_url = urljoin(self.scanner.target_url, '/session/forgot_password')
        
        for username in usernames[:5]:  # Limit tests
            try:
                response = self.scanner.make_request(
                    reset_url,
                    method='POST',
                    json={'login': username},
                    timeout=5
                )
                
                if response:
                    results.append({
                        'username': username,
                        'status_code': response.status_code,
                        'enumerable': response.status_code != 429
                    })
            except Exception:
                continue
        
        return results
