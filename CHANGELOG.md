# Changelog

All notable changes to DiscourseMap will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2025-10-25

### 🚀 Major Release - Complete Modular Architecture

#### Added
- **Complete Modular Architecture** - 50+ specialized modules
- **Rate Limiting Module** - Comprehensive rate limiting analysis
  - `LoginRateTester` - Login endpoint rate limiting
  - `APIRateTester` - API endpoint rate limiting  
  - `BypassTester` - Rate limit bypass techniques
  - `HeaderAnalyzer` - Rate limiting header analysis
- **Security Testing Modules**
  - `InjectionTester` - SQL, XSS, Command injection testing
  - `FileUploadTester` - File upload security testing
  - `AuthenticationTester` - Authentication security analysis
- **Performance Testing**
  - `LoadTester` - Load testing and stress testing
  - `ResponseAnalyzer` - Response time and performance analysis
- **Monitoring Modules**
  - `HealthChecker` - Comprehensive health checking
  - `UptimeMonitor` - Uptime monitoring and availability tracking
- **Advanced Reporting**
  - `JSONReporter` - JSON format reports
  - `HTMLReporter` - Professional HTML reports with styling
  - CSV and XML export capabilities
- **External Integrations**
  - `SlackNotifier` - Slack notifications
  - `WebhookSender` - Webhook integrations
- **Configuration Management**
  - `ScannerConfig` - Advanced YAML/JSON configuration
  - Environment variable support
  - Configuration validation
- **Utility Modules**
  - `NetworkTools` - Network connectivity utilities
  - `DataProcessor` - Data processing and transformation
  - Enhanced user agent management
- **Docker Support**
  - Complete Docker containerization
  - Docker Compose with Redis and PostgreSQL
  - Multi-architecture builds (AMD64, ARM64)
- **CI/CD Pipeline**
  - GitHub Actions workflow
  - Automated testing across Python versions
  - Security scanning with Bandit
  - Docker image publishing
- **Development Tools**
  - Comprehensive Makefile
  - Unit test framework
  - Code formatting with Black
  - Linting with Flake8

#### Enhanced
- **Discourse-Specific Modules** - Completely rewritten and modularized
  - Categories security testing
  - Badge system analysis
  - Trust level security
  - Session management testing
- **Core Scanner** - Redesigned with modular architecture
  - `BaseScanner` - Core scanning functionality
  - `ModuleManager` - Dynamic module loading
  - `AsyncScanner` - Asynchronous scanning capabilities
- **CLI Interface** - Modular command-line interface
  - `ArgumentParser` - Advanced argument parsing
  - `ConfigLoader` - Configuration loading
  - `Updater` - Auto-update functionality

#### Changed
- **Breaking Change**: Complete API restructure for modular design
- **File Organization**: Reorganized into logical module categories
- **Import Structure**: New import paths for better organization
- **Configuration**: New YAML-based configuration system

#### Improved
- **Performance**: Significant performance improvements with async support
- **Maintainability**: Modular design for easier maintenance
- **Extensibility**: Easy to add new modules and features
- **Testing**: Comprehensive unit test coverage
- **Documentation**: Complete architecture documentation

#### Security
- **Enhanced Security Testing**: More comprehensive vulnerability detection
- **Safe Defaults**: Secure default configurations
- **Rate Limiting**: Built-in rate limiting to avoid overwhelming targets
- **Input Validation**: Comprehensive input validation and sanitization

## [2.0.5] - Previous Version

### Added
- Basic modular structure
- Core Discourse-specific modules
- Initial security testing capabilities

### Fixed
- Various bug fixes and improvements
- Stability enhancements

## [1.x.x] - Legacy Versions

### Features
- Basic Discourse forum scanning
- Simple vulnerability detection
- Basic reporting capabilities

---

## Migration Guide

### From v2.0.x to v2.1.0

The v2.1.0 release includes breaking changes due to the complete modular restructure:

#### Import Changes
```python
# Old (v2.0.x)
from discoursemap import DiscourseScanner

# New (v2.1.0)
from discoursemap.core import DiscourseScanner
```

#### Configuration Changes
```python
# Old (v2.0.x)
scanner = DiscourseScanner(url, options)

# New (v2.1.0)
from discoursemap.config import ScannerConfig
config = ScannerConfig()
config.set('scanner.timeout', 30)
scanner = DiscourseScanner(config)
```

#### Module Usage
```python
# New modular approach
from discoursemap.discourse_specific.rate_limiting import RateLimitModule
from discoursemap.security.testing import InjectionTester
from discoursemap.performance import LoadTester

rate_tester = RateLimitModule(target_url)
injection_tester = InjectionTester(target_url)
load_tester = LoadTester(target_url)
```

### Compatibility
- Python 3.8+ required
- All major features from v2.0.x are available in modular form
- Legacy scripts may need updates for new import structure

---

For detailed information about the modular architecture, see [MODULAR_ARCHITECTURE.md](MODULAR_ARCHITECTURE.md).