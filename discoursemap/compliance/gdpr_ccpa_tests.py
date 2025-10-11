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
        Initialize the PrivacyComplianceTests instance with a scanner and empty results storage.
        
        Parameters:
            scanner: An object responsible for performing HTTP requests against target URLs (used to fetch pages for compliance checks).
        
        Detailed behavior:
            Creates `self.results` with two keys, `'gdpr'` and `'ccpa'`, each initialized to an empty list for accumulating check results.
        """
        self.scanner = scanner
        self.results = {
            'gdpr': [],
            'ccpa': []
        }
    
    def test_gdpr_compliance(self):
        """
        Run GDPR-related checks and collect findings.
        
        Performs cookie consent, data subject rights, DPO contact, and privacy policy checks and appends their findings to the internal GDPR results list.
        
        Returns:
            gdpr_results (list): List of result entries describing detected issues or informational findings related to GDPR compliance.
        """
        self._check_cookie_consent()
        self._check_data_subject_rights()
        self._check_dpo_contact()
        self._check_privacy_policy()
        
        return self.results['gdpr']
    
    def test_ccpa_compliance(self):
        """
        Scan the target site for common CCPA indicators and record any findings in the instance results.
        
        If the site response contains CCPA-related phrases (for example "do not sell", "ccpa", "california privacy", "opt-out"), an info entry listing the found indicators is appended to self.results['ccpa']; if none are found, a medium-severity entry indicating no indicators is appended. Network or parsing exceptions during scanning are suppressed and do not raise.
        
        Returns:
            list: The list stored in self.results['ccpa'] containing the appended CCPA result entries.
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
        
        Scans the target page content for cookie-consent-related keywords and appends a GDPR result to self.results['gdpr']: an `info` entry when a consent mechanism is detected, or a `high`-severity entry indicating missing cookie consent when none is found.
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
        Detect and record whether data subject rights information is present on the target site.
        
        Scans the target content for common data subject rights phrases and appends a GDPR result to self.results['gdpr']: an info entry including the list of rights found if any phrases are present, or a medium-severity entry indicating rights information is not clearly documented.
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
        Detects Data Protection Officer (DPO) contact information on the target page.
        
        If DPO-related keywords are found in the page content, appends an info entry to self.results['gdpr'] describing the detected DPO contact; otherwise appends a medium-severity entry indicating missing DPO information. Network or parsing errors are suppressed and will result in no change to results.
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
        Record whether the target site exposes a privacy policy and append a corresponding GDPR result.
        
        Searches common privacy policy endpoints and, if a policy is found, appends an info entry to self.results['gdpr'] noting the endpoint; if none are found, appends a high-severity 'Missing Privacy Policy' entry.
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