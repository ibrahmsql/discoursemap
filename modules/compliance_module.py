#!/usr/bin/env python3
"""
Discourse Compliance and Regulatory Testing Module

This module tests compliance with various security standards and regulations
such as GDPR, CCPA, HIPAA, SOX, PCI-DSS, and other security frameworks.

Author: ibrahimsql
Version: 2.0
"""

import requests
import json
import time
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from datetime import datetime, timedelta

class ComplianceModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.target_url = scanner.target_url
        self.session = scanner.session
        self.results = {
            'module_name': 'Compliance and Regulatory Testing',
            'target': self.target_url,
            'gdpr_compliance': [],
            'ccpa_compliance': [],
            'hipaa_compliance': [],
            'pci_dss_compliance': [],
            'sox_compliance': [],
            'iso27001_compliance': [],
            'nist_compliance': [],
            'owasp_compliance': [],
            'privacy_policies': [],
            'data_protection': [],
            'audit_logs': [],
            'security_headers': [],
            'encryption_compliance': [],
            'access_controls': [],
            'data_retention': [],
            'breach_notification': []
        }
        
        # GDPR requirements
        self.gdpr_requirements = {
            'privacy_policy': 'Privacy policy must be present and accessible',
            'cookie_consent': 'Cookie consent mechanism required',
            'data_portability': 'Data export functionality required',
            'right_to_erasure': 'Data deletion functionality required',
            'consent_withdrawal': 'Ability to withdraw consent required',
            'data_processing_basis': 'Legal basis for data processing must be stated',
            'dpo_contact': 'Data Protection Officer contact information',
            'breach_notification': 'Data breach notification procedures',
            'privacy_by_design': 'Privacy by design implementation',
            'data_minimization': 'Data minimization principles'
        }
        
        # CCPA requirements
        self.ccpa_requirements = {
            'privacy_notice': 'Privacy notice at collection required',
            'do_not_sell': 'Do Not Sell My Personal Information link required',
            'data_categories': 'Categories of personal information disclosed',
            'third_party_sharing': 'Third party data sharing disclosure',
            'consumer_rights': 'Consumer rights information',
            'opt_out_mechanism': 'Opt-out mechanism for data sales',
            'verification_process': 'Identity verification for requests',
            'non_discrimination': 'Non-discrimination policy'
        }
        
        # Security headers for compliance
        self.security_headers = {
            'strict-transport-security': 'HSTS header for secure connections',
            'content-security-policy': 'CSP header for XSS protection',
            'x-frame-options': 'Clickjacking protection',
            'x-content-type-options': 'MIME type sniffing protection',
            'referrer-policy': 'Referrer information control',
            'permissions-policy': 'Feature policy for browser APIs',
            'x-xss-protection': 'XSS filter activation',
            'expect-ct': 'Certificate transparency enforcement'
        }
        
        # PCI-DSS requirements
        self.pci_requirements = {
            'secure_transmission': 'Secure transmission of cardholder data',
            'encryption_at_rest': 'Encryption of stored cardholder data',
            'access_controls': 'Restrict access to cardholder data',
            'network_security': 'Secure network architecture',
            'vulnerability_management': 'Regular security testing',
            'monitoring': 'Monitor and test networks regularly',
            'information_security': 'Maintain information security policy'
        }
        
        # OWASP Top 10 compliance
        self.owasp_top10 = {
            'injection': 'SQL, NoSQL, OS, and LDAP injection',
            'broken_authentication': 'Broken authentication and session management',
            'sensitive_data_exposure': 'Sensitive data exposure',
            'xxe': 'XML External Entities (XXE)',
            'broken_access_control': 'Broken access control',
            'security_misconfiguration': 'Security misconfiguration',
            'xss': 'Cross-Site Scripting (XSS)',
            'insecure_deserialization': 'Insecure deserialization',
            'vulnerable_components': 'Using components with known vulnerabilities',
            'insufficient_logging': 'Insufficient logging and monitoring'
        }
        
    def run_scan(self):
        """Run comprehensive compliance testing"""
        print(f"[*] Starting compliance testing for {self.target_url}")
        
        try:
            # GDPR Compliance Testing
            self._test_gdpr_compliance()
            
            # CCPA Compliance Testing
            self._test_ccpa_compliance()
            
            # HIPAA Compliance Testing
            self._test_hipaa_compliance()
            
            # PCI-DSS Compliance Testing
            self._test_pci_compliance()
            
            # SOX Compliance Testing
            self._test_sox_compliance()
            
            # ISO 27001 Compliance Testing
            self._test_iso27001_compliance()
            
            # NIST Framework Testing
            self._test_nist_compliance()
            
            # OWASP Compliance Testing
            self._test_owasp_compliance()
            
            # Security Headers Testing
            self._test_security_headers()
            
            # Privacy Policy Analysis
            self._analyze_privacy_policies()
            
            # Data Protection Testing
            self._test_data_protection()
            
            # Audit Logging Testing
            self._test_audit_logging()
            
            # Encryption Compliance
            self._test_encryption_compliance()
            
            # Access Control Testing
            self._test_access_controls()
            
            # Data Retention Testing
            self._test_data_retention()
            
            # Breach Notification Testing
            self._test_breach_notification()
            
            print(f"[+] Compliance testing completed")
            
        except Exception as e:
            print(f"[!] Error during compliance testing: {str(e)}")
            self.results['gdpr_compliance'].append({
                'type': 'Compliance Testing Error',
                'severity': 'info',
                'description': f'Error during compliance testing: {str(e)}'
            })
        
        return self.results
    
    def _test_gdpr_compliance(self):
        """Test GDPR compliance requirements"""
        print("[*] Testing GDPR compliance...")
        
        # Check for privacy policy
        privacy_endpoints = ['/privacy', '/privacy-policy', '/gdpr', '/data-protection']
        privacy_found = False
        
        for endpoint in privacy_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    privacy_found = True
                    content = response.text.lower()
                    
                    # Check for GDPR-specific terms
                    gdpr_terms = [
                        'gdpr', 'general data protection regulation',
                        'data subject rights', 'right to erasure',
                        'data portability', 'consent withdrawal',
                        'data protection officer', 'lawful basis'
                    ]
                    
                    found_terms = [term for term in gdpr_terms if term in content]
                    
                    self.results['gdpr_compliance'].append({
                        'type': 'Privacy Policy Analysis',
                        'severity': 'info' if found_terms else 'medium',
                        'endpoint': endpoint,
                        'gdpr_terms_found': found_terms,
                        'gdpr_terms_count': len(found_terms),
                        'description': f'Privacy policy found at {endpoint} with {len(found_terms)} GDPR-related terms'
                    })
                    break
            
            except Exception as e:
                print(f"[!] Error checking privacy policy at {endpoint}: {str(e)}")
        
        if not privacy_found:
            self.results['gdpr_compliance'].append({
                'type': 'Missing Privacy Policy',
                'severity': 'high',
                'description': 'No privacy policy found - GDPR compliance violation'
            })
        
        # Check for cookie consent
        self._check_cookie_consent()
        
        # Check for data subject rights
        self._check_data_subject_rights()
        
        # Check for DPO contact information
        self._check_dpo_contact()
    
    def _check_cookie_consent(self):
        """Check for cookie consent mechanism"""
        try:
            response = self.session.get(self.target_url)
            content = response.text.lower()
            
            cookie_indicators = [
                'cookie consent', 'accept cookies', 'cookie policy',
                'cookie banner', 'cookie notice', 'manage cookies'
            ]
            
            consent_found = any(indicator in content for indicator in cookie_indicators)
            
            if consent_found:
                self.results['gdpr_compliance'].append({
                    'type': 'Cookie Consent Mechanism',
                    'severity': 'info',
                    'description': 'Cookie consent mechanism detected'
                })
            else:
                self.results['gdpr_compliance'].append({
                    'type': 'Missing Cookie Consent',
                    'severity': 'medium',
                    'description': 'No cookie consent mechanism found - potential GDPR violation'
                })
        
        except Exception as e:
            print(f"[!] Error checking cookie consent: {str(e)}")
    
    def _check_data_subject_rights(self):
        """Check for data subject rights implementation"""
        data_rights_endpoints = [
            '/data-export', '/download-data', '/export',
            '/delete-account', '/data-deletion', '/erasure',
            '/account-settings', '/privacy-settings'
        ]
        
        rights_found = []
        
        for endpoint in data_rights_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    rights_found.append(endpoint)
            
            except Exception as e:
                print(f"[!] Error checking data rights endpoint {endpoint}: {str(e)}")
        
        if rights_found:
            self.results['gdpr_compliance'].append({
                'type': 'Data Subject Rights Implementation',
                'severity': 'info',
                'endpoints_found': rights_found,
                'description': f'Data subject rights endpoints found: {rights_found}'
            })
        else:
            self.results['gdpr_compliance'].append({
                'type': 'Missing Data Subject Rights',
                'severity': 'high',
                'description': 'No data subject rights implementation found - GDPR compliance violation'
            })
    
    def _check_dpo_contact(self):
        """Check for Data Protection Officer contact information"""
        try:
            contact_endpoints = ['/contact', '/about', '/privacy', '/legal']
            dpo_found = False
            
            for endpoint in contact_endpoints:
                try:
                    url = urljoin(self.target_url, endpoint)
                    response = self.session.get(url)
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        dpo_indicators = [
                            'data protection officer', 'dpo', 'privacy officer',
                            'data controller', 'privacy contact'
                        ]
                        
                        if any(indicator in content for indicator in dpo_indicators):
                            dpo_found = True
                            self.results['gdpr_compliance'].append({
                                'type': 'DPO Contact Information',
                                'severity': 'info',
                                'endpoint': endpoint,
                                'description': f'DPO contact information found at {endpoint}'
                            })
                            break
                
                except Exception as e:
                    print(f"[!] Error checking DPO contact at {endpoint}: {str(e)}")
            
            if not dpo_found:
                self.results['gdpr_compliance'].append({
                    'type': 'Missing DPO Contact',
                    'severity': 'medium',
                    'description': 'No DPO contact information found - may be required for GDPR compliance'
                })
        
        except Exception as e:
            print(f"[!] Error checking DPO contact: {str(e)}")
    
    def _test_ccpa_compliance(self):
        """Test CCPA compliance requirements"""
        print("[*] Testing CCPA compliance...")
        
        try:
            response = self.session.get(self.target_url)
            content = response.text.lower()
            
            # Check for "Do Not Sell" link
            do_not_sell_indicators = [
                'do not sell', 'do not sell my personal information',
                'opt out of sale', 'ccpa opt out'
            ]
            
            do_not_sell_found = any(indicator in content for indicator in do_not_sell_indicators)
            
            if do_not_sell_found:
                self.results['ccpa_compliance'].append({
                    'type': 'Do Not Sell Link',
                    'severity': 'info',
                    'description': 'Do Not Sell My Personal Information link found'
                })
            else:
                self.results['ccpa_compliance'].append({
                    'type': 'Missing Do Not Sell Link',
                    'severity': 'medium',
                    'description': 'No "Do Not Sell" link found - potential CCPA violation'
                })
            
            # Check for CCPA-specific terms
            ccpa_terms = [
                'ccpa', 'california consumer privacy act',
                'consumer rights', 'personal information categories',
                'third party disclosure', 'opt out'
            ]
            
            found_ccpa_terms = [term for term in ccpa_terms if term in content]
            
            if found_ccpa_terms:
                self.results['ccpa_compliance'].append({
                    'type': 'CCPA Terms Analysis',
                    'severity': 'info',
                    'ccpa_terms_found': found_ccpa_terms,
                    'description': f'CCPA-related terms found: {found_ccpa_terms}'
                })
        
        except Exception as e:
            print(f"[!] Error testing CCPA compliance: {str(e)}")
    
    def _test_hipaa_compliance(self):
        """Test HIPAA compliance requirements"""
        print("[*] Testing HIPAA compliance...")
        
        # HIPAA is primarily for healthcare, but check for health-related indicators
        try:
            response = self.session.get(self.target_url)
            content = response.text.lower()
            
            health_indicators = [
                'health', 'medical', 'patient', 'healthcare',
                'hipaa', 'phi', 'protected health information'
            ]
            
            health_related = any(indicator in content for indicator in health_indicators)
            
            if health_related:
                # Check for HIPAA-specific requirements
                hipaa_requirements = [
                    'hipaa compliance', 'business associate agreement',
                    'minimum necessary', 'administrative safeguards',
                    'physical safeguards', 'technical safeguards'
                ]
                
                found_requirements = [req for req in hipaa_requirements if req in content]
                
                self.results['hipaa_compliance'].append({
                    'type': 'HIPAA Compliance Analysis',
                    'severity': 'medium' if not found_requirements else 'info',
                    'health_related': True,
                    'hipaa_requirements_found': found_requirements,
                    'description': f'Health-related content detected. HIPAA requirements found: {found_requirements}'
                })
            else:
                self.results['hipaa_compliance'].append({
                    'type': 'HIPAA Compliance Check',
                    'severity': 'info',
                    'health_related': False,
                    'description': 'No health-related content detected - HIPAA may not apply'
                })
        
        except Exception as e:
            print(f"[!] Error testing HIPAA compliance: {str(e)}")
    
    def _test_pci_compliance(self):
        """Test PCI-DSS compliance requirements"""
        print("[*] Testing PCI-DSS compliance...")
        
        # Check for payment processing indicators
        try:
            response = self.session.get(self.target_url)
            content = response.text.lower()
            
            payment_indicators = [
                'payment', 'credit card', 'debit card', 'paypal',
                'stripe', 'checkout', 'billing', 'subscription'
            ]
            
            payment_related = any(indicator in content for indicator in payment_indicators)
            
            if payment_related:
                # Check SSL/TLS implementation
                parsed_url = urlparse(self.target_url)
                if parsed_url.scheme == 'https':
                    self.results['pci_dss_compliance'].append({
                        'type': 'Secure Transmission',
                        'severity': 'info',
                        'description': 'HTTPS enabled for secure transmission'
                    })
                else:
                    self.results['pci_dss_compliance'].append({
                        'type': 'Insecure Transmission',
                        'severity': 'critical',
                        'description': 'HTTP used for payment processing - PCI-DSS violation'
                    })
                
                # Check for PCI compliance statements
                pci_indicators = [
                    'pci compliant', 'pci dss', 'payment card industry',
                    'secure payment', 'encrypted payment'
                ]
                
                found_pci = [indicator for indicator in pci_indicators if indicator in content]
                
                if found_pci:
                    self.results['pci_dss_compliance'].append({
                        'type': 'PCI Compliance Statement',
                        'severity': 'info',
                        'pci_indicators': found_pci,
                        'description': f'PCI compliance indicators found: {found_pci}'
                    })
            else:
                self.results['pci_dss_compliance'].append({
                    'type': 'PCI-DSS Compliance Check',
                    'severity': 'info',
                    'payment_related': False,
                    'description': 'No payment processing detected - PCI-DSS may not apply'
                })
        
        except Exception as e:
            print(f"[!] Error testing PCI compliance: {str(e)}")
    
    def _test_sox_compliance(self):
        """Test SOX compliance requirements"""
        print("[*] Testing SOX compliance...")
        
        # SOX applies to public companies - check for financial indicators
        try:
            response = self.session.get(self.target_url)
            content = response.text.lower()
            
            financial_indicators = [
                'financial', 'investor', 'sec filing', 'annual report',
                'quarterly report', '10-k', '10-q', 'sox compliance',
                'sarbanes oxley', 'internal controls', 'audit'
            ]
            
            financial_related = any(indicator in content for indicator in financial_indicators)
            
            if financial_related:
                sox_requirements = [
                    'internal controls', 'financial reporting',
                    'audit trail', 'sox compliance', 'sarbanes oxley'
                ]
                
                found_sox = [req for req in sox_requirements if req in content]
                
                self.results['sox_compliance'].append({
                    'type': 'SOX Compliance Analysis',
                    'severity': 'medium' if not found_sox else 'info',
                    'financial_related': True,
                    'sox_requirements_found': found_sox,
                    'description': f'Financial content detected. SOX requirements found: {found_sox}'
                })
            else:
                self.results['sox_compliance'].append({
                    'type': 'SOX Compliance Check',
                    'severity': 'info',
                    'financial_related': False,
                    'description': 'No financial content detected - SOX may not apply'
                })
        
        except Exception as e:
            print(f"[!] Error testing SOX compliance: {str(e)}")
    
    def _test_iso27001_compliance(self):
        """Test ISO 27001 compliance requirements"""
        print("[*] Testing ISO 27001 compliance...")
        
        try:
            # Check for security policy and procedures
            security_endpoints = ['/security', '/security-policy', '/iso27001', '/isms']
            
            for endpoint in security_endpoints:
                try:
                    url = urljoin(self.target_url, endpoint)
                    response = self.session.get(url)
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        iso_indicators = [
                            'iso 27001', 'information security management',
                            'isms', 'security policy', 'risk assessment',
                            'security controls', 'continual improvement'
                        ]
                        
                        found_iso = [indicator for indicator in iso_indicators if indicator in content]
                        
                        if found_iso:
                            self.results['iso27001_compliance'].append({
                                'type': 'ISO 27001 Compliance Evidence',
                                'severity': 'info',
                                'endpoint': endpoint,
                                'iso_indicators': found_iso,
                                'description': f'ISO 27001 indicators found at {endpoint}: {found_iso}'
                            })
                
                except Exception as e:
                    print(f"[!] Error checking ISO 27001 at {endpoint}: {str(e)}")
        
        except Exception as e:
            print(f"[!] Error testing ISO 27001 compliance: {str(e)}")
    
    def _test_nist_compliance(self):
        """Test NIST Framework compliance"""
        print("[*] Testing NIST Framework compliance...")
        
        try:
            # Check for NIST framework implementation
            response = self.session.get(self.target_url)
            content = response.text.lower()
            
            nist_functions = [
                'identify', 'protect', 'detect', 'respond', 'recover'
            ]
            
            nist_indicators = [
                'nist', 'cybersecurity framework', 'risk management',
                'incident response', 'business continuity',
                'vulnerability management', 'access control'
            ]
            
            found_nist = [indicator for indicator in nist_indicators if indicator in content]
            
            if found_nist:
                self.results['nist_compliance'].append({
                    'type': 'NIST Framework Evidence',
                    'severity': 'info',
                    'nist_indicators': found_nist,
                    'description': f'NIST Framework indicators found: {found_nist}'
                })
        
        except Exception as e:
            print(f"[!] Error testing NIST compliance: {str(e)}")
    
    def _test_owasp_compliance(self):
        """Test OWASP Top 10 compliance"""
        print("[*] Testing OWASP Top 10 compliance...")
        
        # This would typically involve running security tests
        # For now, check for OWASP-related documentation
        try:
            security_endpoints = ['/security', '/owasp', '/security-policy']
            
            for endpoint in security_endpoints:
                try:
                    url = urljoin(self.target_url, endpoint)
                    response = self.session.get(url)
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        owasp_indicators = [
                            'owasp', 'top 10', 'injection', 'xss',
                            'broken authentication', 'sensitive data exposure',
                            'security misconfiguration', 'vulnerable components'
                        ]
                        
                        found_owasp = [indicator for indicator in owasp_indicators if indicator in content]
                        
                        if found_owasp:
                            self.results['owasp_compliance'].append({
                                'type': 'OWASP Compliance Evidence',
                                'severity': 'info',
                                'endpoint': endpoint,
                                'owasp_indicators': found_owasp,
                                'description': f'OWASP indicators found at {endpoint}: {found_owasp}'
                            })
                
                except Exception as e:
                    print(f"[!] Error checking OWASP at {endpoint}: {str(e)}")
        
        except Exception as e:
            print(f"[!] Error testing OWASP compliance: {str(e)}")
    
    def _test_security_headers(self):
        """Test security headers compliance"""
        print("[*] Testing security headers...")
        
        try:
            response = self.session.get(self.target_url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            for header, description in self.security_headers.items():
                if header in headers:
                    self.results['security_headers'].append({
                        'type': 'Security Header Present',
                        'severity': 'info',
                        'header': header,
                        'value': headers[header],
                        'description': f'{description} - Header present'
                    })
                else:
                    severity = 'high' if header in ['strict-transport-security', 'content-security-policy'] else 'medium'
                    self.results['security_headers'].append({
                        'type': 'Missing Security Header',
                        'severity': severity,
                        'header': header,
                        'description': f'{description} - Header missing'
                    })
        
        except Exception as e:
            print(f"[!] Error testing security headers: {str(e)}")
    
    def _analyze_privacy_policies(self):
        """Analyze privacy policies for compliance"""
        print("[*] Analyzing privacy policies...")
        
        privacy_endpoints = ['/privacy', '/privacy-policy', '/terms', '/legal']
        
        for endpoint in privacy_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    # Check for required privacy policy elements
                    required_elements = {
                        'data_collection': ['collect', 'gather', 'obtain'],
                        'data_usage': ['use', 'process', 'utilize'],
                        'data_sharing': ['share', 'disclose', 'third party'],
                        'data_retention': ['retain', 'keep', 'store'],
                        'user_rights': ['rights', 'access', 'delete', 'correct'],
                        'contact_info': ['contact', 'email', 'address'],
                        'updates': ['update', 'change', 'modify']
                    }
                    
                    found_elements = {}
                    for element, keywords in required_elements.items():
                        if any(keyword in content for keyword in keywords):
                            found_elements[element] = True
                    
                    missing_elements = [elem for elem in required_elements.keys() if elem not in found_elements]
                    
                    self.results['privacy_policies'].append({
                        'type': 'Privacy Policy Analysis',
                        'severity': 'medium' if missing_elements else 'info',
                        'endpoint': endpoint,
                        'found_elements': list(found_elements.keys()),
                        'missing_elements': missing_elements,
                        'completeness_score': len(found_elements) / len(required_elements),
                        'description': f'Privacy policy analysis for {endpoint}'
                    })
            
            except Exception as e:
                print(f"[!] Error analyzing privacy policy at {endpoint}: {str(e)}")
    
    def _test_data_protection(self):
        """Test data protection measures"""
        print("[*] Testing data protection measures...")
        
        # Check for data protection endpoints
        protection_endpoints = [
            '/data-export', '/download-data', '/delete-account',
            '/privacy-settings', '/account-settings'
        ]
        
        protection_features = []
        
        for endpoint in protection_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    protection_features.append(endpoint)
            
            except Exception as e:
                print(f"[!] Error testing data protection endpoint {endpoint}: {str(e)}")
        
        if protection_features:
            self.results['data_protection'].append({
                'type': 'Data Protection Features',
                'severity': 'info',
                'features_found': protection_features,
                'description': f'Data protection features available: {protection_features}'
            })
        else:
            self.results['data_protection'].append({
                'type': 'Missing Data Protection Features',
                'severity': 'high',
                'description': 'No data protection features found - compliance risk'
            })
    
    def _test_audit_logging(self):
        """Test audit logging capabilities"""
        print("[*] Testing audit logging...")
        
        # Check for audit-related endpoints
        audit_endpoints = ['/admin/logs', '/logs', '/audit', '/activity']
        
        for endpoint in audit_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    self.results['audit_logs'].append({
                        'type': 'Audit Logging Interface',
                        'severity': 'info',
                        'endpoint': endpoint,
                        'description': f'Audit logging interface found at {endpoint}'
                    })
                elif response.status_code == 403:
                    self.results['audit_logs'].append({
                        'type': 'Protected Audit Logs',
                        'severity': 'info',
                        'endpoint': endpoint,
                        'description': f'Protected audit logs at {endpoint} (access denied)'
                    })
            
            except Exception as e:
                print(f"[!] Error testing audit logging at {endpoint}: {str(e)}")
    
    def _test_encryption_compliance(self):
        """Test encryption compliance"""
        print("[*] Testing encryption compliance...")
        
        try:
            # Check HTTPS implementation
            parsed_url = urlparse(self.target_url)
            if parsed_url.scheme == 'https':
                self.results['encryption_compliance'].append({
                    'type': 'HTTPS Encryption',
                    'severity': 'info',
                    'description': 'HTTPS encryption enabled for data in transit'
                })
            else:
                self.results['encryption_compliance'].append({
                    'type': 'Missing HTTPS Encryption',
                    'severity': 'critical',
                    'description': 'HTTPS not enabled - data transmitted in clear text'
                })
            
            # Check for encryption-related headers
            response = self.session.get(self.target_url)
            headers = response.headers
            
            if 'Strict-Transport-Security' in headers:
                self.results['encryption_compliance'].append({
                    'type': 'HSTS Header',
                    'severity': 'info',
                    'description': 'HTTP Strict Transport Security header present'
                })
        
        except Exception as e:
            print(f"[!] Error testing encryption compliance: {str(e)}")
    
    def _test_access_controls(self):
        """Test access control compliance"""
        print("[*] Testing access controls...")
        
        # Check for authentication endpoints
        auth_endpoints = ['/login', '/signup', '/admin', '/api']
        
        for endpoint in auth_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    self.results['access_controls'].append({
                        'type': 'Authentication Endpoint',
                        'severity': 'info',
                        'endpoint': endpoint,
                        'description': f'Authentication endpoint available at {endpoint}'
                    })
                elif response.status_code == 403:
                    self.results['access_controls'].append({
                        'type': 'Protected Endpoint',
                        'severity': 'info',
                        'endpoint': endpoint,
                        'description': f'Protected endpoint at {endpoint} (access denied)'
                    })
            
            except Exception as e:
                print(f"[!] Error testing access controls at {endpoint}: {str(e)}")
    
    def _test_data_retention(self):
        """Test data retention policies"""
        print("[*] Testing data retention policies...")
        
        try:
            # Check for data retention information
            policy_endpoints = ['/privacy', '/terms', '/data-retention']
            
            for endpoint in policy_endpoints:
                try:
                    url = urljoin(self.target_url, endpoint)
                    response = self.session.get(url)
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        retention_keywords = [
                            'retention', 'keep data', 'store data',
                            'delete data', 'data lifecycle', 'retention period'
                        ]
                        
                        found_retention = [kw for kw in retention_keywords if kw in content]
                        
                        if found_retention:
                            self.results['data_retention'].append({
                                'type': 'Data Retention Policy',
                                'severity': 'info',
                                'endpoint': endpoint,
                                'retention_keywords': found_retention,
                                'description': f'Data retention policy information found at {endpoint}'
                            })
                
                except Exception as e:
                    print(f"[!] Error checking data retention at {endpoint}: {str(e)}")
        
        except Exception as e:
            print(f"[!] Error testing data retention: {str(e)}")
    
    def _test_breach_notification(self):
        """Test breach notification procedures"""
        print("[*] Testing breach notification procedures...")
        
        try:
            # Check for breach notification information
            notification_endpoints = ['/security', '/privacy', '/incident-response']
            
            for endpoint in notification_endpoints:
                try:
                    url = urljoin(self.target_url, endpoint)
                    response = self.session.get(url)
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        breach_keywords = [
                            'data breach', 'security incident', 'breach notification',
                            'incident response', 'security breach', 'data incident'
                        ]
                        
                        found_breach = [kw for kw in breach_keywords if kw in content]
                        
                        if found_breach:
                            self.results['breach_notification'].append({
                                'type': 'Breach Notification Procedures',
                                'severity': 'info',
                                'endpoint': endpoint,
                                'breach_keywords': found_breach,
                                'description': f'Breach notification procedures found at {endpoint}'
                            })
                
                except Exception as e:
                    print(f"[!] Error checking breach notification at {endpoint}: {str(e)}")
        
        except Exception as e:
            print(f"[!] Error testing breach notification: {str(e)}")

if __name__ == "__main__":
    # Test the module
    class MockScanner:
        def __init__(self):
            self.target_url = "https://discourse.example.com"
            self.session = requests.Session()
    
    scanner = MockScanner()
    compliance_module = ComplianceModule(scanner)
    results = compliance_module.run_scan()
    
    print(json.dumps(results, indent=2))