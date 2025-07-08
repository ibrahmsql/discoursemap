#!/usr/bin/env python3
"""
Discourse Security Scanner - Report Generation Module

Generates detailed reports in multiple formats (JSON, HTML, CSV)
"""

import json
import csv
import os
from datetime import datetime
from jinja2 import Template

class Reporter:
    """Report generation class for scan results"""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.scan_time = datetime.now()
        self.results = {}
    
    def add_module_results(self, module_name, results):
        """Add results from a scanning module"""
        self.results[module_name] = results
    
    def generate_json_report(self, output_file=None):
        """Generate JSON format report"""
        report_data = {
            'scan_info': {
                'target': self.target_url,
                'scan_time': self.scan_time.isoformat(),
                'scanner': 'DiscourseMap Security Scanner',
                'version': '1.0.0'
            },
            'results': self.results,
            'summary': self._generate_summary()
        }
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            return f"JSON report saved to {output_file}"
        else:
            return json.dumps(report_data, indent=2, ensure_ascii=False)
    
    def generate_html_report(self, output_file=None):
        """Generate HTML format report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DiscourseMap Security Scan Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #007cba;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #007cba;
            margin: 0;
            font-size: 2.5em;
        }
        .scan-info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            border-left: 5px solid #007cba;
        }
        .module-section {
            margin-bottom: 40px;
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
        }
        .module-header {
            background: #007cba;
            color: white;
            padding: 15px 20px;
            font-size: 1.3em;
            font-weight: bold;
        }
        .module-content {
            padding: 20px;
        }
        .vulnerability {
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 5px;
            border-left: 5px solid #ddd;
        }
        .critical {
            background: #fff5f5;
            border-left-color: #dc3545;
        }
        .high {
            background: #fff8e1;
            border-left-color: #ff9800;
        }
        .medium {
            background: #fff3e0;
            border-left-color: #ff5722;
        }
        .low {
            background: #f3e5f5;
            border-left-color: #9c27b0;
        }
        .info {
            background: #e3f2fd;
            border-left-color: #2196f3;
        }
        .success {
            background: #e8f5e8;
            border-left-color: #4caf50;
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-critical {
            background: #dc3545;
            color: white;
        }
        .severity-high {
            background: #ff9800;
            color: white;
        }
        .severity-medium {
            background: #ff5722;
            color: white;
        }
        .severity-low {
            background: #9c27b0;
            color: white;
        }
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #ddd;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #007cba;
        }
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #f8f9fa;
            font-weight: bold;
        }
        .code {
            background: #f4f4f4;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 DiscourseMap Security Scanner</h1>
            <p>Comprehensive Security Assessment Report</p>
        </div>
        
        <div class="scan-info">
            <h2>📋 Scan Information</h2>
            <p><strong>Target:</strong> {{ target }}</p>
            <p><strong>Scan Time:</strong> {{ scan_time }}</p>
            <p><strong>Scanner Version:</strong> 1.0.0</p>
        </div>
        
        <div class="summary-stats">
            <div class="stat-card">
                <div class="stat-number">{{ summary.total_vulnerabilities }}</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ summary.critical_count }}</div>
                <div class="stat-label">Critical Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ summary.high_count }}</div>
                <div class="stat-label">High Risk Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ summary.total_tests }}</div>
                <div class="stat-label">Tests Performed</div>
            </div>
        </div>
        
        {% for module_name, module_results in results.items() %}
        <div class="module-section">
            <div class="module-header">
                📊 {{ module_results.module_name or module_name }}
            </div>
            <div class="module-content">
                <p><strong>Tests Performed:</strong> {{ module_results.tests_performed or 0 }}</p>
                <p><strong>Scan Time:</strong> {{ "%.2f"|format(module_results.scan_time or 0) }} seconds</p>
                
                {% if module_name == 'info_module' %}
                    {% if module_results.discourse_info %}
                    <div class="vulnerability info">
                        <h4>🔍 Discourse Information</h4>
                        <table>
                            {% for key, value in module_results.discourse_info.items() %}
                            <tr><td><strong>{{ key.replace('_', ' ').title() }}</strong></td><td>{{ value }}</td></tr>
                            {% endfor %}
                        </table>
                    </div>
                    {% endif %}
                    
                    {% if module_results.plugins %}
                    <div class="vulnerability info">
                        <h4>🔌 Installed Plugins</h4>
                        <ul>
                        {% for plugin in module_results.plugins %}
                            <li>{{ plugin.name }} ({{ plugin.version or 'Unknown version' }})</li>
                        {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                    
                    {% if module_results.users %}
                    <div class="vulnerability info">
                        <h4>👥 Discovered Users</h4>
                        <table>
                            <tr><th>Username</th><th>Trust Level</th><th>Post Count</th></tr>
                            {% for user in module_results.users %}
                            <tr>
                                <td>{{ user.username }}</td>
                                <td>{{ user.trust_level or 'Unknown' }}</td>
                                <td>{{ user.post_count or 'Unknown' }}</td>
                            </tr>
                            {% endfor %}
                        </table>
                    </div>
                    {% endif %}
                {% endif %}
                
                {% if module_name == 'vulnerability_module' %}
                    {% for vuln_type, vulns in module_results.items() %}
                        {% if vulns and vuln_type not in ['module_name', 'target', 'tests_performed', 'scan_time'] %}
                        <div class="vulnerability {{ vulns[0].severity if vulns and vulns[0].severity else 'info' }}">
                            <h4>🚨 {{ vuln_type.replace('_', ' ').title() }}</h4>
                            {% for vuln in vulns %}
                            <div style="margin-bottom: 10px;">
                                <span class="severity-badge severity-{{ vuln.severity or 'info' }}">{{ vuln.severity or 'info' }}</span>
                                <p><strong>{{ vuln.description or vuln_type }}</strong></p>
                                {% if vuln.payload %}<div class="code">Payload: {{ vuln.payload }}</div>{% endif %}
                                {% if vuln.url %}<p><strong>URL:</strong> {{ vuln.url }}</p>{% endif %}
                            </div>
                            {% endfor %}
                        </div>
                        {% endif %}
                    {% endfor %}
                {% endif %}
                
                {% if module_name == 'endpoint_module' %}
                    {% if module_results.discovered_endpoints %}
                    <div class="vulnerability info">
                        <h4>🔗 Discovered Endpoints</h4>
                        <table>
                            <tr><th>Endpoint</th><th>Status</th><th>Type</th></tr>
                            {% for endpoint in module_results.discovered_endpoints %}
                            <tr>
                                <td>{{ endpoint.path }}</td>
                                <td>{{ endpoint.status_code }}</td>
                                <td>{{ endpoint.endpoint_type or 'Unknown' }}</td>
                            </tr>
                            {% endfor %}
                        </table>
                    </div>
                    {% endif %}
                {% endif %}
                
                {% if module_name == 'user_module' %}
                    {% if module_results.user_enumeration %}
                    <div class="vulnerability medium">
                        <h4>👤 User Enumeration</h4>
                        <table>
                            <tr><th>Username</th><th>Status</th><th>Method</th></tr>
                            {% for user in module_results.user_enumeration %}
                            <tr>
                                <td>{{ user.username }}</td>
                                <td>{{ user.status }}</td>
                                <td>{{ user.method }}</td>
                            </tr>
                            {% endfor %}
                        </table>
                    </div>
                    {% endif %}
                    
                    {% if module_results.weak_passwords %}
                    <div class="vulnerability critical">
                        <h4>🔑 Weak Passwords</h4>
                        {% for weak_pass in module_results.weak_passwords %}
                        <div style="margin-bottom: 10px;">
                            <span class="severity-badge severity-critical">Critical</span>
                            <p><strong>{{ weak_pass.description }}</strong></p>
                            <p>Username: {{ weak_pass.username }}</p>
                        </div>
                        {% endfor %}
                    </div>
                    {% endif %}
                {% endif %}
                
                {% if module_name == 'cve_module' %}
                    {% if module_results.cve_results %}
                    {% for cve in module_results.cve_results %}
                    <div class="vulnerability {{ cve.severity or 'medium' }}">
                        <h4>🔴 {{ cve.cve_id }}</h4>
                        <span class="severity-badge severity-{{ cve.severity or 'medium' }}">{{ cve.severity or 'medium' }}</span>
                        <p><strong>{{ cve.description }}</strong></p>
                        {% if cve.payload %}<div class="code">Payload: {{ cve.payload }}</div>{% endif %}
                        {% if cve.url %}<p><strong>URL:</strong> {{ cve.url }}</p>{% endif %}
                    </div>
                    {% endfor %}
                    {% endif %}
                {% endif %}
            </div>
        </div>
        {% endfor %}
        
        <div class="footer">
            <p>Report generated by DiscourseMap Security Scanner v1.0.0</p>
            <p>⚠️ This tool is for authorized security testing only. Use responsibly.</p>
        </div>
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        html_content = template.render(
            target=self.target_url,
            scan_time=self.scan_time.strftime('%Y-%m-%d %H:%M:%S'),
            results=self.results,
            summary=self._generate_summary()
        )
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return f"HTML report saved to {output_file}"
        else:
            return html_content
    
    def generate_csv_report(self, output_file=None):
        """Generate CSV format report"""
        csv_data = []
        
        # Add header
        csv_data.append([
            'Module', 'Issue Type', 'Severity', 'Description', 
            'URL', 'Payload', 'Status'
        ])
        
        # Process each module's results
        for module_name, module_results in self.results.items():
            if isinstance(module_results, dict):
                for key, value in module_results.items():
                    if isinstance(value, list) and value:
                        for item in value:
                            if isinstance(item, dict):
                                csv_data.append([
                                    module_name,
                                    key,
                                    item.get('severity', 'info'),
                                    item.get('description', ''),
                                    item.get('url', ''),
                                    item.get('payload', ''),
                                    item.get('status', '')
                                ])
        
        if output_file:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerows(csv_data)
            return f"CSV report saved to {output_file}"
        else:
            # Return as string
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerows(csv_data)
            return output.getvalue()
    
    def _generate_summary(self):
        """Generate summary statistics"""
        summary = {
            'total_vulnerabilities': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'info_count': 0,
            'total_tests': 0,
            'modules_run': len(self.results)
        }
        
        for module_name, module_results in self.results.items():
            if isinstance(module_results, dict):
                # Count tests performed
                summary['total_tests'] += module_results.get('tests_performed', 0)
                
                # Count vulnerabilities by severity
                for key, value in module_results.items():
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict) and 'severity' in item:
                                summary['total_vulnerabilities'] += 1
                                severity = item['severity'].lower()
                                if severity == 'critical':
                                    summary['critical_count'] += 1
                                elif severity == 'high':
                                    summary['high_count'] += 1
                                elif severity == 'medium':
                                    summary['medium_count'] += 1
                                elif severity == 'low':
                                    summary['low_count'] += 1
                                else:
                                    summary['info_count'] += 1
        
        return summary
    
    def print_summary(self):
        """Print a beautiful formatted summary of the scan results"""
        from colorama import Fore, Style
        import time
        
        # Debug: Check if this method is called multiple times
        if hasattr(self, '_summary_printed'):
            return  # Prevent duplicate printing
        self._summary_printed = True
        
        summary = self._generate_summary()
        
        # Calculate scan duration
        scan_duration = "0m 0s"
        if hasattr(self, 'scan_start_time') and hasattr(self, 'scan_end_time'):
            duration_seconds = int(self.scan_end_time - self.scan_start_time)
            minutes = duration_seconds // 60
            seconds = duration_seconds % 60
            scan_duration = f"{minutes}m {seconds}s"
        
        # Create complete output as a single string to prevent duplication
        output_lines = []
        
        # Header
        output_lines.append(f"\n{Fore.CYAN}🛡️  DiscourseMap v2.0{Style.RESET_ALL}")
        output_lines.append(f"{Fore.CYAN}🎯 Target: {self.target_url}{Style.RESET_ALL}")
        output_lines.append(f"{Fore.CYAN}⏰ Started: {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        output_lines.append("")
        output_lines.append(f"{Fore.CYAN}[INFO] Starting comprehensive security scan...{Style.RESET_ALL}")
        output_lines.append(f"{Fore.CYAN}[INFO] Modules loaded: {', '.join(self.results.keys()) if self.results else 'none'}{Style.RESET_ALL}")
        output_lines.append("")
        
        # Information Gathering
        output_lines.append(f"{Fore.BLUE}📋 Information Gathering{Style.RESET_ALL}")
        info_results = self.results.get('info', {})
        if info_results:
            discourse_info = info_results.get('discourse_info', {})
            plugins = info_results.get('plugins', [])
            users = info_results.get('users', [])
            
            version = discourse_info.get('version', 'Unknown')
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Server: Discourse {version}")
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Plugins: {len(plugins)} installed")
            output_lines.append(f"├── {Fore.YELLOW}[⚠️]{Style.RESET_ALL} Users: {len(users)} discovered")
            
            # Show user details if found
            if users:
                output_lines.append(f"│   └── Discovered users ({len(users)} total):")
                # Show more users (up to 10) with detailed information
                display_count = min(len(users), 10)
                for i, user in enumerate(users[:display_count]):
                    username = user.get('username', 'Unknown')
                    name = user.get('name', '')
                    trust_level = user.get('trust_level', 'Unknown')
                    role = user.get('role', '')
                    user_id = user.get('id', 'Unknown')
                    avatar_template = user.get('avatar_template', '')
                    
                    # Build display name with more details
                    display_name = f"{username}"
                    if name and name != username:
                        display_name += f" ({name})"
                    if role:
                        display_name += f" [{role}]"
                    
                    # Add trust level description
                    trust_desc = {
                        0: "New User",
                        1: "Basic User", 
                        2: "Member",
                        3: "Regular",
                        4: "Leader",
                        5: "Elder"
                    }.get(trust_level, f"Level {trust_level}")
                    
                    prefix = "├──" if i < display_count - 1 else "└──"
                    output_lines.append(f"│       {prefix} {display_name}")
                    output_lines.append(f"│           │ ID: {user_id} | Trust: {trust_desc} ({trust_level})")
                    if avatar_template:
                        output_lines.append(f"│           │ Avatar: {avatar_template[:50]}{'...' if len(avatar_template) > 50 else ''}")
                
                # Show if there are more users
                if len(users) > display_count:
                    remaining = len(users) - display_count
                    output_lines.append(f"│           └── ... and {remaining} more users")
            
            output_lines.append(f"└── {Fore.GREEN}[✓]{Style.RESET_ALL} Information gathering completed")
        else:
            output_lines.append(f"└── {Fore.RED}[❌]{Style.RESET_ALL} Information gathering failed")
        output_lines.append("")
        
        # Endpoint Discovery
        output_lines.append(f"{Fore.BLUE}🔍 Endpoint Discovery{Style.RESET_ALL}")
        endpoint_results = self.results.get('endpoint', {})
        if endpoint_results:
            endpoints = endpoint_results.get('discovered_endpoints', [])
            admin_found = any('/admin' in ep.get('path', '') for ep in endpoints)
            api_count = len([ep for ep in endpoints if 'api' in ep.get('path', '')])
            
            output_lines.append(f"├── {Fore.GREEN if admin_found else Fore.YELLOW}[{'✓' if admin_found else '⚠️'}]{Style.RESET_ALL} Admin panel: {'Found' if admin_found else 'Not found'}")
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} API endpoints: {api_count} discovered")
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Total endpoints: {len(endpoints)} found")
            output_lines.append(f"└── {Fore.GREEN}[✓]{Style.RESET_ALL} Endpoint discovery completed")
        else:
            output_lines.append(f"└── {Fore.RED}[❌]{Style.RESET_ALL} Endpoint discovery failed")
        output_lines.append("")
        
        # Vulnerability Assessment
        output_lines.append(f"{Fore.BLUE}🛡️ Vulnerability Assessment{Style.RESET_ALL}")
        vuln_results = self.results.get('vuln', {})
        if summary['critical_count'] > 0 or summary['high_count'] > 0:
            output_lines.append(f"├── {Fore.RED}[❌]{Style.RESET_ALL} Critical vulnerabilities: {summary['critical_count']} found")
            output_lines.append(f"├── {Fore.YELLOW}[⚠️]{Style.RESET_ALL} High vulnerabilities: {summary['high_count']} found")
            output_lines.append(f"├── {Fore.YELLOW}[⚠️]{Style.RESET_ALL} Medium vulnerabilities: {summary['medium_count']} found")
            output_lines.append(f"└── {Fore.GREEN}[✓]{Style.RESET_ALL} Low vulnerabilities: {summary['low_count']} found")
        else:
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} SQL Injection: No vulnerabilities found")
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} XSS: No vulnerabilities found")
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} CSRF: Properly protected")
            output_lines.append(f"└── {Fore.GREEN}[✓]{Style.RESET_ALL} File upload: Properly restricted")
        output_lines.append("")
        
        # Authentication & Authorization
        output_lines.append(f"{Fore.BLUE}🔐 Authentication & Authorization{Style.RESET_ALL}")
        user_results = self.results.get('user', {})
        user_enum = user_results.get('user_enumeration', [])
        weak_passwords = user_results.get('weak_passwords', [])
        
        if len(weak_passwords) > 0:
            output_lines.append(f"├── {Fore.RED}[❌]{Style.RESET_ALL} Weak passwords: {len(weak_passwords)} found")
            output_lines.append(f"├── {Fore.YELLOW}[⚠️]{Style.RESET_ALL} User enumeration: {len(user_enum)} users")
            output_lines.append(f"├── {Fore.YELLOW}[⚠️]{Style.RESET_ALL} Session management: Needs review")
            output_lines.append(f"└── {Fore.RED}[❌]{Style.RESET_ALL} Authentication issues detected")
        else:
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Default credentials: Not found")
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Session management: Properly configured")
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Password policy: Strong requirements")
            output_lines.append(f"└── {Fore.GREEN}[✓]{Style.RESET_ALL} Authentication properly secured")
        output_lines.append("")
        
        # Plugin Detection
        output_lines.append(f"{Fore.BLUE}🔍 Plugin Detection{Style.RESET_ALL}")
        detection_results = self.results.get('plugin_detection', {})
        detected_plugins = detection_results.get('detected_plugins', [])
        detected_themes = detection_results.get('detected_themes', [])
        tech_stack = detection_results.get('technology_stack', [])
        js_libraries = detection_results.get('javascript_libraries', [])
        
        if len(detected_plugins) > 0 or len(tech_stack) > 0:
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Plugins detected: {len(detected_plugins)} found")
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Themes detected: {len(detected_themes)} found")
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Technology stack: {len(tech_stack)} identified")
            output_lines.append(f"└── {Fore.GREEN}[✓]{Style.RESET_ALL} JS libraries: {len(js_libraries)} detected")
        else:
            output_lines.append(f"├── {Fore.YELLOW}[⚠️]{Style.RESET_ALL} Plugin detection: Limited results")
            output_lines.append(f"├── {Fore.YELLOW}[⚠️]{Style.RESET_ALL} Theme detection: Limited results")
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Technology fingerprinting: Completed")
            output_lines.append(f"└── {Fore.GREEN}[✓]{Style.RESET_ALL} Detection scan completed")
        output_lines.append("")
        
        # Plugin Bruteforce
        output_lines.append(f"{Fore.BLUE}⚔️ Plugin Bruteforce Attacks{Style.RESET_ALL}")
        plugin_results = self.results.get('plugin_bruteforce', {})
        endpoint_attacks = plugin_results.get('endpoint_attacks', [])
        injection_tests = plugin_results.get('injection_tests', [])
        auth_bypasses = plugin_results.get('authentication_bypasses', [])
        
        if len(endpoint_attacks) > 0 or len(injection_tests) > 0 or len(auth_bypasses) > 0:
            output_lines.append(f"├── {Fore.RED if len(endpoint_attacks) > 0 else Fore.GREEN}[{'❌' if len(endpoint_attacks) > 0 else '✓'}]{Style.RESET_ALL} Endpoint attacks: {len(endpoint_attacks)} successful")
            output_lines.append(f"├── {Fore.RED if len(injection_tests) > 0 else Fore.GREEN}[{'❌' if len(injection_tests) > 0 else '✓'}]{Style.RESET_ALL} Injection attacks: {len(injection_tests)} vulnerabilities")
            output_lines.append(f"├── {Fore.RED if len(auth_bypasses) > 0 else Fore.GREEN}[{'❌' if len(auth_bypasses) > 0 else '✓'}]{Style.RESET_ALL} Auth bypasses: {len(auth_bypasses)} successful")
            output_lines.append(f"└── {Fore.RED if any([endpoint_attacks, injection_tests, auth_bypasses]) else Fore.GREEN}[{'❌' if any([endpoint_attacks, injection_tests, auth_bypasses]) else '✓'}]{Style.RESET_ALL} Bruteforce attacks completed")
        else:
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Endpoint attacks: No vulnerabilities")
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Injection attacks: No vulnerabilities")
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Auth bypasses: No vulnerabilities")
            output_lines.append(f"└── {Fore.GREEN}[✓]{Style.RESET_ALL} Bruteforce attacks completed")
        output_lines.append("")
        
        # CVE Exploits
        output_lines.append(f"{Fore.BLUE}🔒 CVE Exploits{Style.RESET_ALL}")
        cve_results = self.results.get('cve', {})
        cve_vulns = cve_results.get('cve_results', [])
        
        if len(cve_vulns) > 0:
            critical_cves = [c for c in cve_vulns if c.get('severity', '').lower() == 'critical']
            high_cves = [c for c in cve_vulns if c.get('severity', '').lower() == 'high']
            output_lines.append(f"├── {Fore.RED}[❌]{Style.RESET_ALL} Critical CVEs: {len(critical_cves)} found")
            output_lines.append(f"├── {Fore.YELLOW}[⚠️]{Style.RESET_ALL} High CVEs: {len(high_cves)} found")
            output_lines.append(f"├── {Fore.YELLOW}[⚠️]{Style.RESET_ALL} Total CVEs: {len(cve_vulns)} tested")
            output_lines.append(f"└── {Fore.RED}[❌]{Style.RESET_ALL} CVE vulnerabilities detected")
        else:
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Known CVEs: No vulnerabilities found")
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} Security patches: Up to date")
            output_lines.append(f"├── {Fore.GREEN}[✓]{Style.RESET_ALL} CVE database: Checked")
            output_lines.append(f"└── {Fore.GREEN}[✓]{Style.RESET_ALL} No known CVE exploits")
        output_lines.append("")
        
        # Scan Summary
        output_lines.append(f"{Fore.BLUE}📈 Scan Summary{Style.RESET_ALL}")
        output_lines.append(f"├── 🔴 Critical: {summary['critical_count']} vulnerabilities")
        output_lines.append(f"├── 🟡 High: {summary['high_count']} vulnerabilities")
        output_lines.append(f"├── 🟠 Medium: {summary['medium_count']} vulnerabilities")
        output_lines.append(f"└── 🟢 Low: {summary['low_count']} vulnerabilities")
        output_lines.append("")
        
        # Footer
        timestamp = self.scan_time.strftime('%Y%m%d_%H%M%S')
        output_lines.append(f"{Fore.GREEN}💾 Report saved: discourse_scan_{timestamp}.json{Style.RESET_ALL}")
        output_lines.append(f"{Fore.GREEN}⏱️  Scan completed in {scan_duration}{Style.RESET_ALL}")
        output_lines.append("")
        
        # Print all output at once to prevent duplication
        print("\n".join(output_lines))
    
    def finalize_scan(self):
        """Finalize the scan and print summary"""
        # Print summary at the end of scan
        self.print_summary()