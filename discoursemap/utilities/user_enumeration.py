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
        """
        Initialize the UserEnumerator with a scanner and prepare storage for discovered users.
        
        Parameters:
            scanner: An object used to perform requests and provide the target URL (expected to expose attributes/methods like `target_url` and `make_request`).
        
        Detailed behavior:
            Creates an empty list `discovered_users` to accumulate found user records.
        """
        self.scanner = scanner
        self.discovered_users = []
    
    def discover_users_from_public_endpoints(self):
        """
        Probe common public Discourse JSON endpoints and aggregate discovered users.
        
        Queries a set of public endpoints (e.g., /about.json, /users.json, /directory_items.json, /u/search/users) on the target and extracts usernames found in returned JSON payloads, appending them to the enumerator's internal `discovered_users` list.
        
        Returns:
            list: A list of user records (dicts) added to `self.discovered_users`. Each record typically contains keys such as `username`, optional `name`, and `source` indicating where the user was found.
        """
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
        """
        Extract user profiles from the target site's directory page (/u) and add them to the enumerator's discovered users.
        
        Returns:
        	list[dict]: The list of discovered user records (each typically contains keys like 'username', optional 'name', and 'source').
        """
        try:
            url = urljoin(self.scanner.target_url, '/u')
            response = self.scanner.make_request(url, timeout=10)
            
            if response and response.status_code == 200:
                self._extract_users_from_html(response.text)
        except Exception:
            pass
        
        return self.discovered_users
    
    def discover_users_from_search(self, query='a'):
        """
        Discover users by querying the site's search endpoint.
        
        Queries the /u/search/users endpoint with the provided search term and appends any returned users to the enumerator's internal `discovered_users` list. Each appended entry is a dict containing `username`, `name`, and `source` set to `'search'`.
        
        Parameters:
        	query (str): Search term to use when querying the users endpoint. Defaults to `'a'`.
        
        Returns:
        	list: The enumerator's `discovered_users` list, containing dicts with keys `username`, `name`, and `source`.
        """
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
        """
        Extract usernames from a JSON-like payload and append them to self.discovered_users.
        
        Scans the provided dict for common keys that contain user lists (such as 'users',
        'directory_items', 'about', and 'members'). For each user object found, appends a
        dictionary with keys 'username', 'name', and 'source' (set to the provided endpoint)
        to self.discovered_users.
        
        Parameters:
            data (dict): Parsed JSON payload to search for user entries.
            endpoint (str): Identifier of the source endpoint to record in the 'source' field.
        """
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
        """
        Parse HTML and add discovered usernames found in user profile links to self.discovered_users.
        
        Parameters:
            html_content (str): HTML document text to search for user profile links.
        
        Notes:
            For each discovered username, a dict is appended to self.discovered_users with keys:
            'username' (str) and 'source' set to 'html_parsing'.
        """
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
        """
        Check which provided usernames appear enumerable by probing the application's login endpoint.
        
        Parameters:
            usernames (iterable): Sequence of username strings to test; only the first 10 entries are attempted.
        
        Returns:
            list: A list of dictionaries for usernames that produced an indicative login response. Each dictionary contains:
                - 'username' (str): The tested username.
                - 'enumerable' (bool): `True` if the login response suggests the account exists, `False` otherwise.
                - 'method' (str): The enumeration method used (set to 'login_response').
        """
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
        """
        Detect whether the forgot-password endpoint reveals the existence of specific usernames.
        
        Parameters:
            usernames (Iterable[str]): Candidate usernames to test. Only the first 5 entries will be sent to the endpoint.
        
        Returns:
            list[dict]: A list of results, one per tested username. Each dict contains:
                - 'username' (str): The tested username.
                - 'status_code' (int): HTTP status code returned by the forgot-password endpoint.
                - 'enumerable' (bool): `true` if the response status code is not 429, `false` otherwise.
        """
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