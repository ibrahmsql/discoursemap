#!/usr/bin/env python3
"""
Slack Integration Module

Sends notifications to Slack channels.
"""

import requests
import json
from typing import Dict, List, Optional, Any
from datetime import datetime


class SlackNotifier:
    """Sends notifications to Slack"""
    
    def __init__(self, webhook_url: str, channel: Optional[str] = None,
                 username: str = 'DiscourseMap', verbose: bool = False):
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username
        self.verbose = verbose
    
    def send_scan_summary(self, scan_results: Dict[str, Any], 
                         target_url: str) -> Dict[str, Any]:
        """Send scan summary to Slack"""
        
        summary = self._generate_summary(scan_results)
        
        # Choose color based on risk level
        color_map = {
            'CRITICAL': '#FF0000',  # Red
            'HIGH': '#FF8C00',      # Orange
            'MEDIUM': '#FFD700',    # Gold
            'LOW': '#32CD32',       # Green
            'MINIMAL': '#808080'    # Gray
        }
        
        color = color_map.get(summary['risk_level'], '#808080')
        
        # Create Slack message
        message = {
            'username': self.username,
            'icon_emoji': ':shield:',
            'attachments': [
                {
                    'color': color,
                    'title': f'DiscourseMap Scan Results - {target_url}',
                    'fields': [
                        {
                            'title': 'Risk Level',
                            'value': summary['risk_level'],
                            'short': True
                        },
                        {
                            'title': 'Total Vulnerabilities',
                            'value': str(summary['total_vulnerabilities']),
                            'short': True
                        },
                        {
                            'title': 'Critical',
                            'value': str(summary['vulnerability_breakdown']['CRITICAL']),
                            'short': True
                        },
                        {
                            'title': 'High',
                            'value': str(summary['vulnerability_breakdown']['HIGH']),
                            'short': True
                        },
                        {
                            'title': 'Medium',
                            'value': str(summary['vulnerability_breakdown']['MEDIUM']),
                            'short': True
                        },
                        {
                            'title': 'Low',
                            'value': str(summary['vulnerability_breakdown']['LOW']),
                            'short': True
                        }
                    ],
                    'footer': 'DiscourseMap Security Scanner',
                    'ts': int(datetime.now().timestamp())
                }
            ]
        }
        
        if self.channel:
            message['channel'] = self.channel
        
        return self._send_message(message)
    
    def send_alert(self, title: str, message: str, 
                   severity: str = 'INFO') -> Dict[str, Any]:
        """Send alert to Slack"""
        
        # Choose emoji and color based on severity
        emoji_map = {
            'CRITICAL': ':rotating_light:',
            'HIGH': ':warning:',
            'MEDIUM': ':exclamation:',
            'LOW': ':information_source:',
            'INFO': ':information_source:'
        }
        
        color_map = {
            'CRITICAL': '#FF0000',
            'HIGH': '#FF8C00',
            'MEDIUM': '#FFD700',
            'LOW': '#32CD32',
            'INFO': '#0080FF'
        }
        
        emoji = emoji_map.get(severity, ':information_source:')
        color = color_map.get(severity, '#0080FF')
        
        slack_message = {
            'username': self.username,
            'icon_emoji': emoji,
            'attachments': [
                {
                    'color': color,
                    'title': title,
                    'text': message,
                    'footer': 'DiscourseMap Security Scanner',
                    'ts': int(datetime.now().timestamp())
                }
            ]
        }
        
        if self.channel:
            slack_message['channel'] = self.channel
        
        return self._send_message(slack_message)
    
    def send_vulnerability_details(self, vulnerabilities: List[Dict[str, Any]], 
                                  target_url: str) -> Dict[str, Any]:
        """Send detailed vulnerability information"""
        
        if not vulnerabilities:
            return self.send_alert(
                'No Vulnerabilities Found',
                f'Scan of {target_url} completed with no vulnerabilities detected.',
                'INFO'
            )
        
        # Group vulnerabilities by severity
        by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)
        
        # Create detailed message
        fields = []
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in by_severity:
                vuln_list = by_severity[severity]
                vuln_text = '\n'.join([
                    f"• {vuln.get('type', 'Unknown')} - {vuln.get('endpoint', 'N/A')}"
                    for vuln in vuln_list[:5]  # Limit to 5 per severity
                ])
                
                if len(vuln_list) > 5:
                    vuln_text += f"\n... and {len(vuln_list) - 5} more"
                
                fields.append({
                    'title': f'{severity} ({len(vuln_list)})',
                    'value': vuln_text,
                    'short': False
                })
        
        message = {
            'username': self.username,
            'icon_emoji': ':shield:',
            'attachments': [
                {
                    'color': '#FF8C00',
                    'title': f'Vulnerability Details - {target_url}',
                    'fields': fields,
                    'footer': 'DiscourseMap Security Scanner',
                    'ts': int(datetime.now().timestamp())
                }
            ]
        }
        
        if self.channel:
            message['channel'] = self.channel
        
        return self._send_message(message)
    
    def _generate_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary from scan results"""
        
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
        
        # Determine risk level
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
            'total_vulnerabilities': total_vulnerabilities,
            'risk_level': risk_level,
            'vulnerability_breakdown': vulnerability_counts
        }
    
    def _send_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Send message to Slack"""
        
        try:
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=30
            )
            
            return {
                'success': response.status_code == 200,
                'status_code': response.status_code,
                'response': response.text,
                'sent_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'sent_at': datetime.now().isoformat()
            }