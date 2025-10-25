#!/usr/bin/env python3
"""
Unit Tests for DiscourseMap Modular Architecture

Tests all major components and modules.
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import discoursemap
from discoursemap.config import ScannerConfig
from discoursemap.utilities import NetworkTools, DataProcessor
from discoursemap.performance import ResponseAnalyzer
from discoursemap.monitoring import HealthChecker
from discoursemap.reporting import JSONReporter, HTMLReporter
from discoursemap.security.testing import InjectionTester
from discoursemap.discourse_specific.rate_limiting import LoginRateTester


class TestModularArchitecture(unittest.TestCase):
    """Test modular architecture components"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_url = 'https://httpbin.org'
    
    def test_import_all_modules(self):
        """Test that all modules can be imported"""
        # Core modules
        from discoursemap.core import DiscourseScanner, Reporter, Banner
        
        # Performance modules
        from discoursemap.performance import LoadTester, ResponseAnalyzer
        
        # Monitoring modules
        from discoursemap.monitoring import HealthChecker, UptimeMonitor
        
        # Reporting modules
        from discoursemap.reporting import JSONReporter, HTMLReporter
        
        # Security testing modules
        from discoursemap.security.testing import InjectionTester, FileUploadTester, AuthenticationTester
        
        # Rate limiting modules
        from discoursemap.discourse_specific.rate_limiting import RateLimitModule, LoginRateTester
        
        # Integration modules
        from discoursemap.integrations import WebhookSender, SlackNotifier
        
        # Configuration module
        from discoursemap.config import ScannerConfig
        
        self.assertTrue(True, "All modules imported successfully")
    
    def test_scanner_config(self):
        """Test scanner configuration"""
        config = ScannerConfig()
        
        # Test default values
        self.assertEqual(config.get('scanner.timeout'), 10)
        
        # Test setting values
        config.set('scanner.timeout', 15)
        self.assertEqual(config.get('scanner.timeout'), 15)
        
        # Test module management
        config.enable_module('test_module')
        self.assertTrue(config.is_module_enabled('test_module'))
        
        config.disable_module('test_module')
        self.assertFalse(config.is_module_enabled('test_module'))
    
    def test_network_tools(self):
        """Test network utilities"""
        network = NetworkTools()
        
        # Test DNS lookup
        result = network.dns_lookup('google.com')
        self.assertTrue(result['success'])
        self.assertIn('ip_address', result)
    
    def test_data_processor(self):
        """Test data processing utilities"""
        processor = DataProcessor()
        
        # Test risk score calculation
        vulnerabilities = [
            {'severity': 'HIGH', 'type': 'Test Vuln 1'},
            {'severity': 'MEDIUM', 'type': 'Test Vuln 2'}
        ]
        
        risk_score = processor.calculate_risk_score(vulnerabilities)
        
        self.assertIn('normalized_score', risk_score)
        self.assertIn('risk_level', risk_score)
        self.assertEqual(risk_score['total_vulnerabilities'], 2)
    
    def test_json_reporter(self):
        """Test JSON reporter"""
        reporter = JSONReporter()
        
        sample_results = {
            'test_module': {
                'vulnerabilities': [
                    {'type': 'Test', 'severity': 'HIGH'}
                ]
            }
        }
        
        report = reporter.generate_report(sample_results, self.test_url)
        
        self.assertIn('report_metadata', report)
        self.assertIn('executive_summary', report)
        self.assertEqual(report['executive_summary']['total_vulnerabilities'], 1)
    
    def test_html_reporter(self):
        """Test HTML reporter"""
        reporter = HTMLReporter()
        
        sample_results = {
            'test_module': {
                'vulnerabilities': [
                    {'type': 'Test', 'severity': 'MEDIUM'}
                ]
            }
        }
        
        html_report = reporter.generate_report(sample_results, self.test_url)
        
        self.assertIsInstance(html_report, str)
        self.assertIn('<!DOCTYPE html>', html_report)
        self.assertIn('DiscourseMap Security Report', html_report)
    
    def test_health_checker_initialization(self):
        """Test health checker initialization"""
        health_checker = HealthChecker(self.test_url)
        
        self.assertEqual(health_checker.target_url, self.test_url)
        self.assertFalse(health_checker.verbose)
    
    def test_injection_tester_initialization(self):
        """Test injection tester initialization"""
        injection_tester = InjectionTester(self.test_url)
        
        self.assertEqual(injection_tester.target_url, self.test_url)
        self.assertIsInstance(injection_tester.sql_payloads, list)
        self.assertIsInstance(injection_tester.xss_payloads, list)
    
    def test_rate_limit_tester_initialization(self):
        """Test rate limit tester initialization"""
        rate_tester = LoginRateTester(self.test_url)
        
        self.assertEqual(rate_tester.target_url, self.test_url)
    
    def test_version_info(self):
        """Test version and metadata"""
        self.assertEqual(discoursemap.__version__, "2.1.0")
        self.assertEqual(discoursemap.__author__, "ibrahimsql")
        self.assertIn("Discourse forum security scanner", discoursemap.__description__)


class TestConfigurationValidation(unittest.TestCase):
    """Test configuration validation"""
    
    def test_valid_configuration(self):
        """Test valid configuration"""
        config = ScannerConfig()
        config.set('scanner.timeout', 10)
        config.enable_module('test_module')
        
        issues = config.validate_config()
        
        self.assertEqual(len(issues['errors']), 0)
    
    def test_invalid_timeout(self):
        """Test invalid timeout configuration"""
        config = ScannerConfig()
        config.set('scanner.timeout', -1)
        
        issues = config.validate_config()
        
        self.assertGreater(len(issues['errors']), 0)
        self.assertTrue(any('timeout' in error.lower() for error in issues['errors']))


class TestDataProcessing(unittest.TestCase):
    """Test data processing functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.processor = DataProcessor()
    
    def test_normalize_scan_results(self):
        """Test scan results normalization"""
        raw_results = {
            'module1': {
                'vulnerabilities': [
                    {'type': 'Test', 'severity': 'HIGH'}
                ],
                'recommendations': [
                    {'issue': 'Test issue', 'severity': 'HIGH'}
                ]
            }
        }
        
        normalized = self.processor.normalize_scan_results(raw_results)
        
        self.assertIn('metadata', normalized)
        self.assertIn('summary', normalized)
        self.assertIn('vulnerabilities', normalized)
        self.assertEqual(len(normalized['vulnerabilities']), 1)
    
    def test_filter_by_severity(self):
        """Test filtering by severity"""
        data = {
            'vulnerabilities': [
                {'severity': 'HIGH', 'type': 'Test1'},
                {'severity': 'MEDIUM', 'type': 'Test2'},
                {'severity': 'LOW', 'type': 'Test3'}
            ]
        }
        
        filtered = self.processor.filter_by_severity(data, ['HIGH', 'MEDIUM'])
        
        self.assertEqual(len(filtered['vulnerabilities']), 2)
        severities = [v['severity'] for v in filtered['vulnerabilities']]
        self.assertIn('HIGH', severities)
        self.assertIn('MEDIUM', severities)
        self.assertNotIn('LOW', severities)


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestModularArchitecture))
    test_suite.addTest(unittest.makeSuite(TestConfigurationValidation))
    test_suite.addTest(unittest.makeSuite(TestDataProcessing))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)