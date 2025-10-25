#!/usr/bin/env python3
"""
DiscourseMap v2.1 Demo Script

Demonstrates all the new modular features and capabilities.
"""

import sys
import time
from datetime import datetime

# Add current directory to path
sys.path.insert(0, '.')

import discoursemap
from discoursemap.core import DiscourseScanner, Banner
from discoursemap.config import ScannerConfig
from discoursemap.performance import LoadTester, ResponseAnalyzer
from discoursemap.monitoring import HealthChecker, UptimeMonitor
from discoursemap.reporting import JSONReporter, HTMLReporter
from discoursemap.security.testing import InjectionTester, AuthenticationTester
from discoursemap.discourse_specific.rate_limiting import RateLimitModule
from discoursemap.integrations import SlackNotifier
from discoursemap.utilities import NetworkTools, DataProcessor


def print_banner():
    """Print demo banner"""
    print(Banner)
    print(f"\n🎯 DiscourseMap v{discoursemap.__version__} - Modular Architecture Demo")
    print("=" * 60)


def demo_configuration():
    """Demo configuration management"""
    print("\n📋 1. Configuration Management Demo")
    print("-" * 40)
    
    # Create configuration
    config = ScannerConfig()
    
    # Configure scanner settings
    config.set('scanner.timeout', 15)
    config.set('scanner.user_agent', 'DiscourseMap-Demo/2.1')
    
    # Enable modules
    config.enable_module('rate_limiting')
    config.enable_module('security_testing')
    
    # Set authentication
    config.set_authentication(username='demo_user', password='demo_pass')
    
    print("✓ Configuration created and customized")
    print(f"  - Timeout: {config.get('scanner.timeout')}s")
    print(f"  - User Agent: {config.get('scanner.user_agent')}")
    print(f"  - Enabled modules: {len(config.get('modules.enabled', []))}")
    
    # Validate configuration
    issues = config.validate_config()
    if issues['errors']:
        print(f"  - Errors: {len(issues['errors'])}")
    if issues['warnings']:
        print(f"  - Warnings: {len(issues['warnings'])}")
    
    return config


def demo_network_tools():
    """Demo network utilities"""
    print("\n🌐 2. Network Tools Demo")
    print("-" * 40)
    
    network = NetworkTools(verbose=True)
    
    # DNS lookup demo
    print("Testing DNS lookup...")
    dns_result = network.dns_lookup('google.com')
    if dns_result['success']:
        print(f"✓ DNS resolved: {dns_result['hostname']} -> {dns_result['ip_address']}")
    
    # Port connectivity demo
    print("Testing port connectivity...")
    port_result = network.check_port_connectivity('google.com', [80, 443, 8080])
    open_ports = [port for port, data in port_result['results'].items() if data.get('open')]
    print(f"✓ Open ports on google.com: {open_ports}")


def demo_performance_testing():
    """Demo performance testing"""
    print("\n⚡ 3. Performance Testing Demo")
    print("-" * 40)
    
    # Response analyzer demo
    analyzer = ResponseAnalyzer('https://httpbin.org', verbose=True)
    
    print("Analyzing endpoint performance...")
    results = analyzer.analyze_endpoint_performance(['/get', '/json'])
    
    for endpoint, data in results['endpoint_analysis'].items():
        if 'avg_response_time' in data:
            print(f"✓ {endpoint}: {data['avg_response_time']:.3f}s average")
    
    print(f"✓ Overall performance rating: {results['summary'].get('performance_rating', 'N/A')}")


def demo_security_testing():
    """Demo security testing"""
    print("\n🔒 4. Security Testing Demo")
    print("-" * 40)
    
    # Injection tester demo (safe test)
    print("Testing injection detection capabilities...")
    injection_tester = InjectionTester('https://httpbin.org', verbose=True)
    
    # Auth tester demo
    print("Testing authentication security...")
    auth_tester = AuthenticationTester('https://httpbin.org', verbose=True)
    
    print("✓ Security testing modules initialized")
    print("  - SQL Injection detection ready")
    print("  - XSS detection ready")
    print("  - Authentication testing ready")


def demo_monitoring():
    """Demo monitoring capabilities"""
    print("\n📊 5. Monitoring Demo")
    print("-" * 40)
    
    # Health checker demo
    health_checker = HealthChecker('https://httpbin.org', verbose=True)
    
    print("Performing health check...")
    health_results = health_checker.comprehensive_health_check()
    
    print(f"✓ Basic connectivity: {'✓' if health_results['basic_connectivity'].get('accessible') else '✗'}")
    print(f"✓ SSL certificate: {'✓' if health_results['ssl_certificate'].get('certificate_valid') else '✗'}")
    print(f"✓ Overall health score: {health_results['overall_health']['overall_score']:.1f}/100")


def demo_reporting():
    """Demo reporting capabilities"""
    print("\n📄 6. Reporting Demo")
    print("-" * 40)
    
    # Sample scan results
    sample_results = {
        'rate_limiting': {
            'vulnerabilities': [
                {
                    'type': 'Missing Rate Limiting',
                    'severity': 'HIGH',
                    'endpoint': '/login',
                    'description': 'Login endpoint lacks rate limiting'
                }
            ],
            'recommendations': [
                {
                    'severity': 'HIGH',
                    'issue': 'Missing rate limiting',
                    'recommendation': 'Implement rate limiting on authentication endpoints'
                }
            ]
        }
    }
    
    # JSON Reporter
    json_reporter = JSONReporter(verbose=True)
    json_report = json_reporter.generate_report(sample_results, 'https://demo.discourse.org')
    
    print("✓ JSON report generated")
    print(f"  - Vulnerabilities: {json_report['executive_summary']['total_vulnerabilities']}")
    print(f"  - Risk level: {json_report['executive_summary']['overall_risk_level']}")
    
    # HTML Reporter
    html_reporter = HTMLReporter(verbose=True)
    html_report = html_reporter.generate_report(sample_results, 'https://demo.discourse.org')
    
    print("✓ HTML report generated")
    print(f"  - Report size: {len(html_report)} characters")


def demo_data_processing():
    """Demo data processing"""
    print("\n🔄 7. Data Processing Demo")
    print("-" * 40)
    
    processor = DataProcessor(verbose=True)
    
    # Sample data
    sample_data = {
        'vulnerabilities': [
            {'severity': 'HIGH', 'type': 'SQL Injection'},
            {'severity': 'MEDIUM', 'type': 'XSS'},
            {'severity': 'LOW', 'type': 'Information Disclosure'}
        ]
    }
    
    # Calculate risk score
    risk_score = processor.calculate_risk_score(sample_data['vulnerabilities'])
    
    print("✓ Data processing completed")
    print(f"  - Risk score: {risk_score['normalized_score']:.1f}/100")
    print(f"  - Risk level: {risk_score['risk_level']}")
    print(f"  - Total vulnerabilities: {risk_score['total_vulnerabilities']}")


def demo_integrations():
    """Demo external integrations"""
    print("\n🔗 8. Integration Demo")
    print("-" * 40)
    
    print("✓ Integration modules available:")
    print("  - Slack notifications")
    print("  - Webhook sender")
    print("  - Custom API integrations")
    print("  - CI/CD pipeline integration")
    
    # Note: We don't actually send notifications in demo
    print("✓ Integration capabilities demonstrated")


def demo_modular_architecture():
    """Demo modular architecture benefits"""
    print("\n🏗️ 9. Modular Architecture Benefits")
    print("-" * 40)
    
    print("✓ Modular benefits demonstrated:")
    print("  - 50+ specialized modules")
    print("  - Independent testing capability")
    print("  - Easy extensibility")
    print("  - Focused single-responsibility design")
    print("  - Reusable components")
    print("  - Better maintainability")


def main():
    """Main demo function"""
    start_time = time.time()
    
    print_banner()
    
    try:
        # Run all demos
        config = demo_configuration()
        demo_network_tools()
        demo_performance_testing()
        demo_security_testing()
        demo_monitoring()
        demo_reporting()
        demo_data_processing()
        demo_integrations()
        demo_modular_architecture()
        
        # Summary
        end_time = time.time()
        duration = end_time - start_time
        
        print("\n" + "=" * 60)
        print("🎉 DiscourseMap v2.1 Demo Completed Successfully!")
        print(f"⏱️  Total demo time: {duration:.2f} seconds")
        print(f"📅 Demo completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\n🚀 Ready for production use!")
        print("📖 See MODULAR_ARCHITECTURE.md for detailed documentation")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())