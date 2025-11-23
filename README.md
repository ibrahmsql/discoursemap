# DiscourseMap

![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-yellow.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue.svg)

> **Advanced Modular Security Scanner for Discourse Forums**
>
> A comprehensive, modular security assessment tool specifically designed for Discourse forum platforms. Built by security professionals, for security professionals.

---

## 🚀 What's New in v2.1

- **50+ Specialized Modules** - Complete modular architecture re-engineered for scalability.
- **Advanced Rate Limiting Tests** - Sophisticated analysis including bypass techniques and header inspection.
- **Comprehensive Security Testing** - Enhanced injection (SQL, XSS), file upload, and authentication testing.
- **Performance Monitoring** - Integrated load testing and detailed response analysis.
- **Health & Uptime** - Real-time system health checks and availability monitoring.
- **Multiple Report Formats** - JSON, HTML, CSV, and XML export capabilities.
- **External Integrations** - Native support for Slack notifications, Webhooks, and CI/CD pipelines.
- **Advanced Configuration** - Flexible YAML/JSON configuration with environment variable support.

## 📋 Features

### 🔍 **Discourse-Specific Modules**
- **Rate Limiting Analysis**: Deep dive into login and API rate limits, including potential bypass vectors.
- **Session Security**: Comprehensive testing of cookie security attributes and CSRF protection mechanisms.
- **Category Security**: Enumeration of categories and rigorous permission/access control testing.
- **Badge System Analysis**: Enumeration and security assessment of the badge awarding system.
- **Trust Levels**: Analysis of user trust levels and potential privilege escalation paths.
- **Admin Panel**: Targeted security testing of administrative interfaces.

### 🛡️ **Security Testing**
- **Injection Testing**: Automated detection of SQL Injection, XSS, and Command Injection vulnerabilities.
- **File Upload Security**: Testing for bypass techniques in file upload restrictions.
- **Authentication Testing**: detection of weak credentials and brute-force protection mechanisms.
- **Session Management**: Checks for session fixation and concurrent session handling issues.

### 📊 **Performance & Monitoring**
- **Load Testing**: Configurable stress testing to evaluate system resilience.
- **Response Analysis**: Detailed metrics on response times and potential bottlenecks.
- **Health Checking**: Automated system health verification.
- **Uptime Monitoring**: Tracking availability over time.

### 📄 **Advanced Reporting**
- **JSON Reports**: Machine-readable data for integration with other tools.
- **HTML Reports**: Professional, styled reports with charts for stakeholders.
- **CSV Export**: Easy-to-analyze data for spreadsheet software.
- **XML Format**: Standardized output for enterprise systems.

### 🔗 **Integrations**
- **Slack Notifications**: Instant alerts sent directly to your team's channel.
- **Webhook Support**: Custom hooks to trigger external actions or workflows.
- **CI/CD Pipeline**: Designed to fit into automated testing pipelines.
- **API Endpoints**: RESTful interface for programmatic control.

## 🛠️ Installation

### Quick Install
```bash
git clone https://github.com/ibrahmsql/discoursemap.git
cd discoursemap
pip install -r requirements.txt
pip install -e .
```

### Docker Installation
```bash
# Build the image
make docker-build

# Run the container
make docker-run
```

### Development Setup
```bash
make install-dev
make test
```

## 🎯 Quick Start

### Basic Usage
```python
from discoursemap.core import DiscourseScanner
from discoursemap.reporting import HTMLReporter

# Initialize scanner
scanner = DiscourseScanner('https://forum.example.com')

# Run comprehensive scan
results = scanner.scan()

# Generate and save report
reporter = HTMLReporter()
report = reporter.generate_report(results, 'https://forum.example.com')
reporter.save_report(report, 'security_report.html')
```

### Advanced Configuration
```python
from discoursemap.config import ScannerConfig
from discoursemap.core.scanner import BaseScanner

# Load configuration
config = ScannerConfig('config.yaml')
config.enable_module('rate_limiting')
config.set_authentication('username', 'password')

# Run configured scan
scanner = BaseScanner(config)
results = scanner.comprehensive_scan()
```

### Rate Limiting Analysis
```python
from discoursemap.discourse_specific.rate_limiting import RateLimitModule

# Test specific module
rate_tester = RateLimitModule('https://forum.example.com', verbose=True)
results = rate_tester.scan()

print(f"Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
```

## 📊 Demo

Run the interactive demo to explore features:

```bash
make demo
```

## 🏗️ Modular Architecture

DiscourseMap v2.1 features a completely modular architecture designed for extensibility:

```
discoursemap/
├── core/                    # Core scanning engine
├── discourse_specific/      # Discourse-specific modules
│   ├── rate_limiting/      # Rate limiting tests
│   ├── session/            # Session security
│   ├── categories/         # Category security
│   ├── badges/             # Badge system tests
│   └── trust_levels/       # Trust level analysis
├── security/               # General security testing
│   └── testing/           # Injection, auth, file upload
├── performance/            # Performance testing
├── monitoring/             # Health and uptime monitoring
├── reporting/              # Report generation
├── integrations/           # External integrations
├── utilities/              # Utility functions
└── config/                 # Configuration management
```

See [MODULAR_ARCHITECTURE.md](MODULAR_ARCHITECTURE.md) for detailed documentation.

## 🧪 Testing

Run the test suite to ensure reliability:

```bash
# Unit tests
python -m pytest tests/ -v

# Full test suite
make test
```

## 📖 Documentation

- **[Modular Architecture Guide](MODULAR_ARCHITECTURE.md)** - Detailed architecture documentation.
- **[API Reference](docs/api.md)** - Complete API documentation.
- **[Configuration Guide](docs/configuration.md)** - Configuration options.
- **[Integration Guide](docs/integrations.md)** - External integrations.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md).

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/new-feature`).
3. Commit your changes (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature/new-feature`).
5. Open a Pull Request.

## ⚠️ Ethical Usage

**IMPORTANT**: This tool is designed for authorized security testing only. Always ensure you have proper authorization before testing any Discourse forum. Respect rate limits, terms of service, and applicable laws.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Discourse Team** - For creating an amazing forum platform.
- **Security Community** - For continuous feedback and contributions.

---

**Made with ❤️ by [ibrahimsql](https://github.com/ibrahmsql)**

*Securing Discourse forums, one scan at a time.*
