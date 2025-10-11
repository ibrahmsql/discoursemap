#!/usr/bin/env python3
"""CSRF Vulnerability Scanner"""

from urllib.parse import urljoin
from bs4 import BeautifulSoup


class CSRFScanner:
    """Cross-Site Request Forgery scanner"""
    
    def __init__(self, scanner):
        """
        Initialize the CSRFScanner with the given scanner instance.
        
        Parameters:
            scanner: An object that provides HTTP request functionality and target information — expected to expose a `make_request(url, timeout)` method (or equivalent) and a `target_url` attribute used by scan_csrf.
        """
        self.scanner = scanner
    
    def scan_csrf(self):
        """
        Scan the target page for HTML forms that appear to lack CSRF protection.
        
        Parses the response for the scanner's target URL and inspects each form; reports forms that use the POST method but have no input whose name contains "csrf" or "token".
        
        Returns:
            results (list): A list of vulnerability dictionaries. Each dictionary contains the keys:
                - 'type': human-readable issue type (e.g., "Missing CSRF Protection")
                - 'severity': severity level (e.g., "high")
                - 'form_action': the form's action attribute
                - 'description': a short description of the finding
        
        Notes:
            If the HTTP request or parsing fails, the method may return an empty or partial results list.
        """
        results = []
        
        try:
            # Check if CSRF tokens are used
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if not response:
                return results
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check forms
            forms = soup.find_all('form')
            
            for form in forms:
                # Check if form has CSRF token
                csrf_found = False
                
                inputs = form.find_all('input')
                for input_tag in inputs:
                    input_type = input_tag.get('type', '').lower()
                    input_name = input_tag.get('name', '').lower()
                    
                    if 'csrf' in input_name or 'token' in input_name:
                        csrf_found = True
                        break
                
                if not csrf_found:
                    # Check if it's a state-changing form
                    method = form.get('method', 'GET').upper()
                    action = form.get('action', '')
                    
                    if method == 'POST':
                        results.append({
                            'type': 'Missing CSRF Protection',
                            'severity': 'high',
                            'form_action': action,
                            'description': f'Form without CSRF token: {action}'
                        })
        
        except Exception:
            pass
        
        return results