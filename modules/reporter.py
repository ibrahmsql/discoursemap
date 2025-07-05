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
        """Print a summary of the scan results"""
        summary = self._generate_summary()
        
        print("\n" + "="*60)
        print("📊 SCAN SUMMARY")
        print("="*60)
        print(f"Target: {self.target_url}")
        print(f"Scan Time: {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Modules Run: {summary['modules_run']}")
        print(f"Total Tests: {summary['total_tests']}")
        print("\n🚨 VULNERABILITIES FOUND:")
        print(f"  Critical: {summary['critical_count']}")
        print(f"  High:     {summary['high_count']}")
        print(f"  Medium:   {summary['medium_count']}")
        print(f"  Low:      {summary['low_count']}")
        print(f"  Info:     {summary['info_count']}")
        print(f"  Total:    {summary['total_vulnerabilities']}")
        print("="*60)
        
        # Risk assessment
        if summary['critical_count'] > 0:
            print("🔴 CRITICAL RISK: Immediate action required!")
        elif summary['high_count'] > 0:
            print("🟠 HIGH RISK: Address these issues soon.")
        elif summary['medium_count'] > 0:
            print("🟡 MEDIUM RISK: Consider addressing these issues.")
        elif summary['low_count'] > 0:
            print("🟢 LOW RISK: Minor issues found.")
        else:
            print("✅ NO MAJOR ISSUES: Target appears secure.")
        
        print("\n⚠️  Remember: This tool is for authorized testing only!")
        print("="*60)
    
    def finalize_scan(self):
        """Finalize the scan - placeholder for any cleanup operations"""
        # This method can be used for any final operations after scan completion
        # Currently just a placeholder
        pass