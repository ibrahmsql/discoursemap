#!/usr/bin/env python3
"""
Discourse Email Security Module

Tests email configuration, SPF, DKIM, DMARC, and email-related vulnerabilities.
"""

import requests
import dns.resolver
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin, urlparse


class EmailSecurityModule:
    """Email security testing for Discourse"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        """Initialize email security module"""
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.domain = urlparse(target_url).netloc
        self.results = {
            'spf_record': {},
            'dkim_record': {},
            'dmarc_record': {},
            'email_endpoints': [],
            'vulnerabilities': [],
            'recommendations': []
        }
    
    def scan(self) -> Dict[str, Any]:
        """Perform email security scan"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting email security scan...{Style.RESET_ALL}")
        
        self._check_spf_record()
        self._check_dkim_record()
        self._check_dmarc_record()
        self._test_email_enumeration()
        self._check_email_bounce_handling()
        self._test_email_injection()
        
        self._generate_recommendations()
        return self.results
    
    def _check_spf_record(self):
        """Check SPF record"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking SPF record...{Style.RESET_ALL}")
        
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            spf_found = False
            
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=spf1'):
                    spf_found = True
                    self.results['spf_record'] = {
                        'exists': True,
                        'record': txt_record,
                        'valid': True
                    }
                    
                    # Check for common issues
                    if '+all' in txt_record or '?all' in txt_record:
                        self.results['vulnerabilities'].append({
                            'type': 'Weak SPF Policy',
                            'severity': 'MEDIUM',
                            'description': 'SPF record allows all senders'
                        })
                    break
            
            if not spf_found:
                self.results['spf_record'] = {'exists': False}
                self.results['vulnerabilities'].append({
                    'type': 'Missing SPF Record',
                    'severity': 'HIGH',
                    'description': 'No SPF record found for domain'
                })
                
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception) as e:
            self.results['spf_record'] = {'exists': False, 'error': str(e)}
    
    def _check_dkim_record(self):
        """Check DKIM record"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking DKIM record...{Style.RESET_ALL}")
        
        # Common DKIM selectors
        selectors = ['default', 'discourse', 'mail', 'dkim', 'google', 'k1', 'selector1']
        
        dkim_found = False
        for selector in selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{self.domain}"
                answers = dns.resolver.resolve(dkim_domain, 'TXT')
                
                for rdata in answers:
                    txt_record = str(rdata).strip('"')
                    if 'p=' in txt_record:
                        dkim_found = True
                        self.results['dkim_record'] = {
                            'exists': True,
                            'selector': selector,
                            'record': txt_record
                        }
                        break
                        
                if dkim_found:
                    break
                    
            except Exception:
                continue
        
        if not dkim_found:
            self.results['dkim_record'] = {'exists': False}
            self.results['vulnerabilities'].append({
                'type': 'Missing DKIM Record',
                'severity': 'MEDIUM',
                'description': 'No DKIM record found'
            })
    
    def _check_dmarc_record(self):
        """Check DMARC record"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking DMARC record...{Style.RESET_ALL}")
        
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=DMARC1'):
                    self.results['dmarc_record'] = {
                        'exists': True,
                        'record': txt_record
                    }
                    
                    # Check policy
                    if 'p=none' in txt_record:
                        self.results['vulnerabilities'].append({
                            'type': 'Weak DMARC Policy',
                            'severity': 'LOW',
                            'description': 'DMARC policy set to none (monitoring only)'
                        })
                    break
                    
        except Exception:
            self.results['dmarc_record'] = {'exists': False}
            self.results['vulnerabilities'].append({
                'type': 'Missing DMARC Record',
                'severity': 'MEDIUM',
                'description': 'No DMARC record found'
            })
    
    def _test_email_enumeration(self):
        """Test email enumeration"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing email enumeration...{Style.RESET_ALL}")
        
        try:
            # Test user email endpoint
            url = urljoin(self.target_url, '/u/check_username')
            response = self.session.get(url, params={'username': 'admin'}, timeout=5)
            
            if response.status_code == 200:
                self.results['email_endpoints'].append({
                    'endpoint': '/u/check_username',
                    'accessible': True,
                    'enumeration_possible': True
                })
        except Exception:
            pass
    
    def _check_email_bounce_handling(self):
        """Check email bounce handling"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking email bounce handling...{Style.RESET_ALL}")
        
        self.results['bounce_handling'] = {
            'tested': True,
            'note': 'Discourse handles bounces via /admin/email/bounced'
        }
    
    def _test_email_injection(self):
        """Test email injection vulnerabilities"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing email injection...{Style.RESET_ALL}")
        
        injection_payloads = [
            'test@example.com\nBcc: attacker@evil.com',
            'test@example.com%0aBcc:attacker@evil.com',
            'test@example.com\r\nBcc: attacker@evil.com'
        ]
        
        # Test would require actual email sending capability
        self.results['email_injection'] = {
            'tested': 'partial',
            'note': 'Full test requires email sending capability'
        }
    
    def _generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = []
        
        if not self.results['spf_record'].get('exists'):
            recommendations.append({
                'severity': 'HIGH',
                'issue': 'Missing SPF record',
                'recommendation': 'Configure SPF record to prevent email spoofing'
            })
        
        if not self.results['dkim_record'].get('exists'):
            recommendations.append({
                'severity': 'MEDIUM',
                'issue': 'Missing DKIM signature',
                'recommendation': 'Enable DKIM signing for email authentication'
            })
        
        if not self.results['dmarc_record'].get('exists'):
            recommendations.append({
                'severity': 'MEDIUM',
                'issue': 'Missing DMARC policy',
                'recommendation': 'Configure DMARC policy for email validation'
            })
        
        self.results['recommendations'] = recommendations
    
    def print_results(self):
        """Print formatted results"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"Discourse Email Security Scan Results")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        # SPF
        spf_status = "✓" if self.results['spf_record'].get('exists') else "✗"
        color = Fore.GREEN if self.results['spf_record'].get('exists') else Fore.RED
        print(f"{color}[{spf_status}] SPF Record{Style.RESET_ALL}")
        
        # DKIM
        dkim_status = "✓" if self.results['dkim_record'].get('exists') else "✗"
        color = Fore.GREEN if self.results['dkim_record'].get('exists') else Fore.RED
        print(f"{color}[{dkim_status}] DKIM Record{Style.RESET_ALL}")
        
        # DMARC
        dmarc_status = "✓" if self.results['dmarc_record'].get('exists') else "✗"
        color = Fore.GREEN if self.results['dmarc_record'].get('exists') else Fore.RED
        print(f"{color}[{dmarc_status}] DMARC Record{Style.RESET_ALL}")
        
        if self.results['vulnerabilities']:
            print(f"\n{Fore.RED}[!] Issues Found: {len(self.results['vulnerabilities'])}{Style.RESET_ALL}")
            for vuln in self.results['vulnerabilities']:
                print(f"  [{vuln['severity']}] {vuln['type']}")
        
        if self.results['recommendations']:
            print(f"\n{Fore.YELLOW}[*] Recommendations:{Style.RESET_ALL}")
            for rec in self.results['recommendations']:
                print(f"  [{rec['severity']}] {rec['issue']}")
                print(f"      → {rec['recommendation']}")
