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
        self.scanner = scanner
        self.results = {
            'gdpr': [],
            'ccpa': []
        }
    
    def test_gdpr_compliance(self):
        """Test GDPR compliance requirements"""
        self._check_cookie_consent()
        self._check_data_subject_rights()
        self._check_dpo_contact()
        self._check_privacy_policy()
        
        return self.results['gdpr']
    
    def test_ccpa_compliance(self):
        """Test CCPA compliance requirements"""
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
        """Check for cookie consent mechanism"""
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
        """Check for data subject rights information"""
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
        """Check for Data Protection Officer contact"""
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
        """Check for privacy policy"""
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
