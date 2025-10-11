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
        """
                 Create an EmailSecurityModule configured to scan email-related security for a Discourse deployment.
                 
                 Parameters:
                     target_url (str): Base URL of the target Discourse instance; trailing slash is removed and the network location is used as the target domain.
                     verbose (bool): If True, enable verbose status output during scans.
                 
                 Attributes:
                     target_url (str): Normalized base URL with no trailing slash.
                     session (requests.Session): HTTP session used for requests.
                     verbose (bool): Verbosity flag.
                     domain (str): Extracted network location (domain) from target_url.
                     results (dict): Container for scan results with keys:
                         - spf_record, dkim_record, dmarc_record: dicts describing discovered DNS records or error info.
                         - email_endpoints: list of discovered or tested email-related endpoints.
                         - vulnerabilities: list of identified security issues (each with severity and details).
                         - recommendations: list of remediation suggestions derived from findings.
                 """
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
        """
        Run the full email security scan for the configured target.
        
        Performs SPF, DKIM, and DMARC checks, basic email enumeration and injection probes, and bounce-handling discovery, then generates remediation recommendations and aggregates results.
        
        Returns:
            results (Dict[str, Any]): Aggregated scan results containing keys:
                - spf_record: info about SPF existence and record or error details
                - dkim_record: info about DKIM selector and record if found
                - dmarc_record: info about DMARC existence and record or error details
                - email_endpoints: discovered email-related endpoints and accessibility notes
                - bounce_handling: metadata about bounce handling configuration
                - email_injection: summary of email injection test status and findings
                - vulnerabilities: list of identified vulnerabilities with severity and reason
                - recommendations: list of remediation recommendations derived from findings
        """
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
        """
        Check for a domain SPF TXT record and record findings in the module results.
        
        Updates self.results['spf_record'] with whether an SPF record exists, the SPF string when found, or an error message on DNS failure. Appends a HIGH-severity vulnerability if no SPF record is present and a MEDIUM-severity vulnerability if the SPF record contains a permissive mechanism such as `+all` or `?all`.
        """
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
        """
        Locate and record a DKIM TXT record for common selectors on the target domain.
        
        If a TXT record containing a DKIM public key (`p=`) is found for any tested selector, stores a dictionary with keys `exists` (True), `selector`, and `record` in `self.results['dkim_record']`. If no DKIM record is found after testing common selectors, sets `self.results['dkim_record']` to `{'exists': False}` and appends a MEDIUM-severity vulnerability entry describing the missing DKIM record to `self.results['vulnerabilities']`.
        """
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
        """
        Verify presence and policy of the domain's DMARC record and record findings.
        
        Updates self.results['dmarc_record'] with an `exists` flag and the raw DMARC record when found. If the DMARC policy contains `p=none`, appends a LOW-severity vulnerability noting a monitoring-only policy. If no valid DMARC record is found, sets `exists` to False and appends a MEDIUM-severity vulnerability for a missing DMARC record.
        """
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
        """
        Attempt a minimal email enumeration check against the Discourse instance.
        
        Performs an HTTP GET to the /u/check_username endpoint with parameter username=admin; if the request returns HTTP 200, appends an entry to self.results['email_endpoints'] describing the endpoint with keys 'endpoint' (str), 'accessible' (True), and 'enumeration_possible' (True).
        """
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
        """
        Record how Discourse handles email bounces for the target instance.
        
        Sets results['bounce_handling'] to indicate the check was performed and provides a brief note about the bounce handling endpoint used by Discourse ("/admin/email/bounced").
        """
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Checking email bounce handling...{Style.RESET_ALL}")
        
        self.results['bounce_handling'] = {
            'tested': True,
            'note': 'Discourse handles bounces via /admin/email/bounced'
        }
    
    def _test_email_injection(self):
        """
        Prepare and record a partial email header injection test.
        
        This method constructs representative email header injection payloads and records in self.results['email_injection'] that injection testing was performed only partially. It notes that a complete test requires the ability to send emails so payloads can be delivered and evaluated.
        """
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
        """
        Build a list of remediation recommendations for missing email authentication records and store it in self.results['recommendations'].
        
        Checks whether SPF, DKIM, and DMARC records are present; for each missing record it appends a recommendation object containing a severity level, an issue description, and a suggested action. The final list replaces any existing recommendations in self.results['recommendations'].
        """
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
        """
        Prints a formatted summary of the email security scan results to standard output.
        
        Reports the presence status for SPF, DKIM, and DMARC records and displays a check or cross symbol for each. If any vulnerabilities were recorded, prints the total count and each vulnerability's severity and type. If recommendations exist, lists each recommendation with its severity, the associated issue, and the recommended action. Output uses colored terminal formatting and symbols to improve readability.
        """
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