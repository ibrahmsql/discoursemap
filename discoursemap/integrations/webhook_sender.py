#!/usr/bin/env python3
"""
Webhook Integration Module

Sends scan results to external systems via webhooks.
"""

import requests
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import hashlib
import hmac


class WebhookSender:
    """Sends scan results via webhooks"""
    
    def __init__(self, webhook_url: str, secret_key: Optional[str] = None,
                 verbose: bool = False):
        self.webhook_url = webhook_url
        self.secret_key = secret_key
        self.verbose = verbose
    
    def send_results(self, scan_results: Dict[str, Any], 
                    target_url: str) -> Dict[str, Any]:
        """Send scan results to webhook"""
        
        payload = self._prepare_payload(scan_results, target_url)
        
        try:
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'DiscourseMap-Webhook/1.0'
            }
            
            # Add signature if secret key is provided
            if self.secret_key:
                signature = self._generate_signature(payload)
                headers['X-DiscourseMap-Signature'] = signature
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers=headers,
                timeout=30
            )
            
            return {
                'success': response.status_code < 400,
                'status_code': response.status_code,
                'response': response.text[:500],  # Limit response text
                'sent_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'sent_at': datetime.now().isoformat()
            }
    
    def _prepare_payload(self, scan_results: Dict[str, Any], 
                        target_url: str) -> Dict[str, Any]:
        """Prepare webhook payload"""
        
        # Count vulnerabilities by severity
        vulnerability_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        total_vulnerabilities = 0
        
        for module_data in scan_results.values():
            if isinstance(module_data, dict) and 'vulnerabilities' in module_data:
                vulns = module_data['vulnerabilities']
                if isinstance(vulns, list):
                    total_vulnerabilities += len(vulns)
                    
                    for vuln in vulns:
                        severity = vuln.get('severity', 'LOW').upper()
                        if severity in vulnerability_counts:
                            vulnerability_counts[severity] += 1
        
        # Determine overall risk level
        if vulnerability_counts['CRITICAL'] > 0:
            risk_level = 'CRITICAL'
        elif vulnerability_counts['HIGH'] > 0:
            risk_level = 'HIGH'
        elif vulnerability_counts['MEDIUM'] > 0:
            risk_level = 'MEDIUM'
        elif vulnerability_counts['LOW'] > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'event_type': 'scan_completed',
            'timestamp': datetime.now().isoformat(),
            'target_url': target_url,
            'summary': {
                'total_vulnerabilities': total_vulnerabilities,
                'risk_level': risk_level,
                'vulnerability_breakdown': vulnerability_counts,
                'modules_scanned': len(scan_results)
            },
            'detailed_results': scan_results
        }
    
    def _generate_signature(self, payload: Dict[str, Any]) -> str:
        """Generate HMAC signature for payload"""
        
        payload_str = json.dumps(payload, sort_keys=True)
        signature = hmac.new(
            self.secret_key.encode(),
            payload_str.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f'sha256={signature}'
    
    def send_alert(self, alert_type: str, message: str, 
                   severity: str = 'INFO') -> Dict[str, Any]:
        """Send alert message"""
        
        payload = {
            'event_type': 'alert',
            'timestamp': datetime.now().isoformat(),
            'alert_type': alert_type,
            'severity': severity,
            'message': message
        }
        
        try:
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'DiscourseMap-Webhook/1.0'
            }
            
            if self.secret_key:
                signature = self._generate_signature(payload)
                headers['X-DiscourseMap-Signature'] = signature
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers=headers,
                timeout=30
            )
            
            return {
                'success': response.status_code < 400,
                'status_code': response.status_code,
                'sent_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'sent_at': datetime.now().isoformat()
            }