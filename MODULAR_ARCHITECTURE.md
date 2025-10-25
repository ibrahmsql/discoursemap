# DiscourseMap v2.1 - Modular Architecture

## Overview
DiscourseMap has been completely restructured into a highly modular architecture with 50+ specialized modules organized by functionality. This new structure provides better maintainability, scalability, and extensibility.

## Module Categories

### 1. Core Modules (`discoursemap/core/`)
- **scanner/**: Base scanner functionality
  - `base_scanner.py` - Core scanning engine
  - `module_manager.py` - Module management system
  - `async_scanner.py` - Asynchronous scanning capabilities
- `reporter.py` - Report generation
- `banner.py` - CLI banner and branding

### 2. Discourse-Specific Modules (`discoursemap/discourse_specific/`)

#### Categories (`categories/`)
- `category_discovery.py` - Category enumeration
- `permission_tester.py` - Permission testing
- `advanced_tests.py` - Advanced category security tests
- `category_module.py` - Main category module

#### Badges (`badges/`)
- `badge_discovery.py` - Badge enumeration
- `badge_security_tests.py` - Badge security testing
- `badge_module.py` - Main badge module

#### Trust Levels (`trust_levels/`)
- `trust_level_discovery.py` - Trust level enumeration
- `trust_level_tests.py` - Trust level security tests
- `trust_level_analysis.py` - Trust level analysis
- `trust_level_module.py` - Main trust level module

#### Session Management (`session/`)
- `cookie_security.py` - Cookie security testing
- `csrf_tests.py` - CSRF protection testing
- `session_module.py` - Complete session security module

#### Rate Limiting (`rate_limiting/`)
- `login_rate_tester.py` - Login rate limit testing
- `api_rate_tester.py` - API rate limit testing
- `bypass_tester.py` - Rate limit bypass techniques
- `header_analyzer.py` - Rate limit header analysis

### 3. Security Testing (`discoursemap/security/testing/`)
- `injection_tester.py` - SQL, XSS, Command injection testing
- `file_upload_tester.py` - File upload security testing
- `authentication_tester.py` - Authentication security testing

### 4. Analysis Modules (`discoursemap/analysis/`)

#### Plugins (`plugins/`)
- `plugin_discovery.py` - Plugin enumeration
- `plugin_security_tests.py` - Plugin security testing
- `plugin_module.py` - Main plugin analysis module

### 5. Performance Testing (`discoursemap/performance/`)
- `load_tester.py` - Load testing and stress testing
- `response_analyzer.py` - Response time and performance analysis

### 6. Monitoring (`discoursemap/monitoring/`)
- `health_checker.py` - Comprehensive health checking
- `uptime_monitor.py` - Uptime monitoring and availability tracking

### 7. Reporting (`discoursemap/reporting/`)
- `json_reporter.py` - JSON format reports
- `html_reporter.py` - HTML format reports with styling

### 8. Utilities (`discoursemap/utilities/`)
- `user_agents/` - User agent management
  - `browser_agents.py` - Browser user agents
  - `mobile_agents.py` - Mobile user agents
- `network_tools.py` - Network connectivity utilities
- `data_processor.py` - Data processing and transformation

### 9. Configuration (`discoursemap/config/`)
- `scanner_config.py` - Advanced configuration management

### 10. Integrations (`discoursemap/integrations/`)
- `webhook_sender.py` - Webhook integration
- `slack_notifier.py` - Slack notifications

### 11. CLI (`discoursemap/cli/`)
- `argument_parser.py` - Command line argument parsing
- `config_loader.py` - Configuration loading
- `updater.py` - Auto-update functionality
- `utils.py` - CLI utilities

### 12. Library (`discoursemap/lib/`)
- `discourse_utils.py` - Discourse-specific utilities
- `config_manager.py` - Configuration management
- `http_client.py` - HTTP client wrapper

## Key Features

### Modular Design Benefits
- **Single Responsibility**: Each module has a focused purpose
- **Easy Testing**: Individual modules can be tested independently
- **Extensibility**: New modules can be added without affecting existing code
- **Maintainability**: Code is organized logically and easy to navigate
- **Reusability**: Modules can be reused across different scan types

### Advanced Testing Capabilities
- **Rate Limit Testing**: Comprehensive rate limiting analysis with bypass techniques
- **Security Testing**: Injection attacks, file upload vulnerabilities, authentication flaws
- **Performance Testing**: Load testing, stress testing, response time analysis
- **Health Monitoring**: System health checks and uptime monitoring

### Multiple Output Formats
- **JSON**: Machine-readable structured data
- **HTML**: Professional reports with styling and charts
- **CSV**: Spreadsheet-compatible vulnerability data
- **XML**: Structured markup format

### External Integrations
- **Slack**: Real-time notifications to Slack channels
- **Webhooks**: Custom webhook integrations for CI/CD pipelines
- **APIs**: RESTful API endpoints for integration

### Configuration Management
- **YAML/JSON**: Flexible configuration file formats
- **Environment Variables**: Support for environment-based configuration
- **CLI Overrides**: Command-line parameter overrides
- **Validation**: Configuration validation and error reporting

## Usage Examples

### Basic Scan
```python
from discoursemap import DiscourseScanner

scanner = DiscourseScanner('https://forum.example.com')
results = scanner.scan()
```

### Advanced Configuration
```python
from discoursemap.config import ScannerConfig
from discoursemap.core.scanner import BaseScanner

config = ScannerConfig('config.yaml')
config.enable_module('rate_limiting')
config.set_authentication('username', 'password')

scanner = BaseScanner(config)
results = scanner.comprehensive_scan()
```

### Custom Reporting
```python
from discoursemap.reporting import HTMLReporter, JSONReporter

html_reporter = HTMLReporter()
json_reporter = JSONReporter()

html_report = html_reporter.generate_report(results, target_url)
json_report = json_reporter.generate_report(results, target_url)

html_reporter.save_report(html_report, 'report.html')
json_reporter.save_report(json_report, 'report.json')
```

### Slack Integration
```python
from discoursemap.integrations import SlackNotifier

slack = SlackNotifier(webhook_url, channel='#security')
slack.send_scan_summary(results, target_url)
```

## Module Development Guidelines

### Creating New Modules
1. Follow the single responsibility principle
2. Implement proper error handling
3. Add comprehensive docstrings
4. Include type hints
5. Write unit tests
6. Update the appropriate `__init__.py` file

### Module Structure Template
```python
#!/usr/bin/env python3
"""
Module Description

Brief description of what this module does.
"""

from typing import Dict, List, Optional, Any
from colorama import Fore, Style


class ModuleName:
    """Module description"""
    
    def __init__(self, target_url: str, verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
    
    def scan(self) -> Dict[str, Any]:
        """Main scanning method"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting module scan...{Style.RESET_ALL}")
        
        results = {}
        # Implementation here
        
        return results
```

## Migration from v2.0

The modular architecture is backward compatible with v2.0 APIs. Existing scripts should continue to work without modification. However, to take advantage of new features, consider:

1. Updating import statements to use specific modules
2. Migrating to the new configuration system
3. Adopting the new reporting formats
4. Implementing external integrations

## Performance Considerations

- **Lazy Loading**: Modules are loaded only when needed
- **Async Support**: Asynchronous scanning for better performance
- **Caching**: Intelligent caching of HTTP responses
- **Rate Limiting**: Built-in rate limiting to avoid overwhelming targets
- **Resource Management**: Proper cleanup of resources and connections

## Security Considerations

- **Input Validation**: All inputs are validated and sanitized
- **Safe Defaults**: Secure default configurations
- **Credential Handling**: Secure storage and transmission of credentials
- **Audit Logging**: Comprehensive logging for security audits
- **Error Handling**: Secure error handling that doesn't leak information

This modular architecture provides a solid foundation for future development and ensures DiscourseMap remains maintainable and extensible as it grows.