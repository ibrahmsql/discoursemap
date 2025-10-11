#!/usr/bin/env python3
"""CSRF Vulnerability Scanner"""

from urllib.parse import urljoin
from bs4 import BeautifulSoup


class CSRFScanner:
    """Cross-Site Request Forgery scanner"""
    
    def __init__(self, scanner):
        self.scanner = scanner
    
    def scan_csrf(self):
        """Scan for CSRF vulnerabilities"""
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
