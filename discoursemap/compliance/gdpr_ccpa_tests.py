#!/usr/bin/env python3
"""
GDPR & CCPA Compliance Tests

Privacy regulation compliance testing.
"""

import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup


class PrivacyComplianceTests:
    """GDPR and CCPA compliance testing"""
    
    def __init__(self, scanner):
        """
        Initialize the PrivacyComplianceTests instance and prepare results storage.
        
        Initializes the instance with a scanner used to perform HTTP requests and creates a results dictionary containing two keys, 'gdpr' and 'ccpa', each initialized to an empty list for accumulating findings.
        
        Parameters:
            scanner: An object providing a make_request(target_url, timeout=...) method used by the compliance checks to fetch page content.
        """
        self.scanner = scanner
        self.results = {
            'gdpr': [],
            'ccpa': []
        }
    
    def test_gdpr_compliance(self):
        """
        Run GDPR-related checks (cookie consent, data subject rights, DPO contact, privacy policy) and record findings.
        
        @returns
        A list of GDPR result entries (dicts) describing detected issues or informational findings and their severities.
        """
        self._check_cookie_consent()
        self._check_data_subject_rights()
        self._check_dpo_contact()
        self._check_privacy_policy()
        
        return self.results['gdpr']
    
    def test_ccpa_compliance(self):
        """
        Scan the target site's content for common CCPA indicators and append a result entry to the GDPR/CCPA results.
        
        Searches the fetched page content for phrases such as "do not sell", "ccpa", "california privacy", and "opt-out". If any indicators are found, an info-level entry including the matched indicators is appended to self.results['ccpa']; otherwise a medium-severity entry indicating no indicators found is appended.
        
        Returns:
            list: The list of CCPA result entries stored in self.results['ccpa'].
        """
        try:
            # Check for "Do Not Sell My Personal Information" link
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if response:
                content = response.text.lower()
                
                ccpa_indicators = [
                    'do not sell',
                    'ccpa',
                    'california privacy',
                    'opt-out'
                ]
                
                found_indicators = [ind for ind in ccpa_indicators if ind in content]
                
                if found_indicators:
                    self.results['ccpa'].append({
                        'type': 'CCPA Compliance',
                        'severity': 'info',
                        'indicators': found_indicators,
                        'description': 'CCPA compliance indicators found'
                    })
                else:
                    self.results['ccpa'].append({
                        'type': 'CCPA Compliance',
                        'severity': 'medium',
                        'description': 'No CCPA compliance indicators found'
                    })
        except Exception:
            pass
        
        return self.results['ccpa']
    
    def _check_cookie_consent(self):
        """
        Detect whether the target site exposes a cookie consent mechanism and record the finding.
        
        Appends a result entry to self.results['gdpr']: an info entry with type "Cookie Consent" when a consent mechanism is detected, or a high-severity entry with type "Missing Cookie Consent" when none is found. Any exceptions raised while fetching or inspecting the page are suppressed.
        """
        try:
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if response:
                content = response.text.lower()
                
                consent_keywords = [
                    'cookie consent', 'accept cookies', 'cookie policy',
                    'cookie banner', 'gdpr', 'cookies usage'
                ]
                
                found_consent = any(keyword in content for keyword in consent_keywords)
                
                if found_consent:
                    self.results['gdpr'].append({
                        'type': 'Cookie Consent',
                        'severity': 'info',
                        'description': 'Cookie consent mechanism detected'
                    })
                else:
                    self.results['gdpr'].append({
                        'type': 'Missing Cookie Consent',
                        'severity': 'high',
                        'description': 'No cookie consent mechanism found - GDPR violation'
                    })
        except Exception:
            pass
    
    def _check_data_subject_rights(self):
        """
        Detects documented data subject rights on the target site and records the finding.
        
        If any rights phrases (e.g., "right to access", "right to erasure", "data portability", "right to rectification", "data subject rights") are present in the fetched page content, appends an info entry to self.results['gdpr'] listing the found rights; otherwise appends a medium-severity entry indicating data subject rights are not clearly documented.
        """
        try:
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if response:
                content = response.text.lower()
                
                rights_keywords = [
                    'right to access', 'right to erasure', 'data portability',
                    'right to rectification', 'data subject rights'
                ]
                
                found_rights = [kw for kw in rights_keywords if kw in content]
                
                if found_rights:
                    self.results['gdpr'].append({
                        'type': 'Data Subject Rights',
                        'severity': 'info',
                        'rights_found': found_rights,
                        'description': 'Data subject rights information found'
                    })
                else:
                    self.results['gdpr'].append({
                        'type': 'Missing Data Rights Info',
                        'severity': 'medium',
                        'description': 'Data subject rights not clearly documented'
                    })
        except Exception:
            pass
    
    def _check_dpo_contact(self):
        """
        Check for Data Protection Officer (DPO) or privacy contact information and record a GDPR result.
        
        Fetches the scanner's target URL, searches the page content for DPO-related keywords, and appends an entry to self.results['gdpr']: an `info` entry when contact information is found, or a `medium`-severity entry when none is found. Exceptions raised while fetching or processing the page are suppressed.
        """
        try:
            response = self.scanner.make_request(self.scanner.target_url, timeout=10)
            if response:
                content = response.text.lower()
                
                dpo_keywords = [
                    'data protection officer', 'dpo', 'privacy officer',
                    'data controller'
                ]
                
                found_dpo = any(keyword in content for keyword in dpo_keywords)
                
                if found_dpo:
                    self.results['gdpr'].append({
                        'type': 'DPO Contact',
                        'severity': 'info',
                        'description': 'DPO contact information found'
                    })
                else:
                    self.results['gdpr'].append({
                        'type': 'Missing DPO Info',
                        'severity': 'medium',
                        'description': 'No DPO contact information found'
                    })
        except Exception:
            pass
    
    def _check_privacy_policy(self):
        """
        Check common privacy policy endpoints and record a GDPR result entry.
        
        Attempts the common privacy policy paths for the current target and stops at the first endpoint that returns an HTTP 200. If a policy is found, appends an info result to self.results['gdpr'] containing 'type' = 'Privacy Policy', 'severity' = 'info', 'endpoint' = the matched path, and a brief 'description'. If none of the endpoints respond with 200, appends a high-severity result with 'type' = 'Missing Privacy Policy', 'severity' = 'high', and 'description' = 'No privacy policy found'.
        """
        privacy_endpoints = ['/privacy', '/privacy-policy', '/legal/privacy']
        
        for endpoint in privacy_endpoints:
            try:
                url = urljoin(self.scanner.target_url, endpoint)
                response = self.scanner.make_request(url, timeout=10)
                
                if response and response.status_code == 200:
                    self.results['gdpr'].append({
                        'type': 'Privacy Policy',
                        'severity': 'info',
                        'endpoint': endpoint,
                        'description': f'Privacy policy found at {endpoint}'
                    })
                    return
            except Exception:
                continue
        
        self.results['gdpr'].append({
            'type': 'Missing Privacy Policy',
            'severity': 'high',
            'description': 'No privacy policy found'
        })