# DiscourseMap v2.1 🛡️

**Advanced Modular Security Scanner for Discourse Forums**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.1.0-orange.svg)](https://github.com/ibrahmsql/discoursemap)

> A comprehensive, modular security assessment tool specifically designed for Discourse forum platforms. Built by security professionals, for security professionals.

## 🚀 What's New in v2.1

- **50+ Specialized Modules** - Complete modular architecture
- **Advanced Rate Limiting Tests** - Including bypass techniques
- **Comprehensive Security Testing** - Injection, file upload, authentication
- **Performance Monitoring** - Load testing and response analysis
- **Health Checking** - System health and uptime monitoring
- **Multiple Report Formats** - JSON, HTML, CSV, XML
- **External Integrations** - Slack, Webhooks, CI/CD
- **Advanced Configuration** - YAML/JSON configuration management

## 📋 Features

### 🔍 **Discourse-Specific Modules**
- **Rate Limiting Analysis** - Login, API, bypass techniques
- **Session Security** - Cookie security, CSRF protection
- **Category Security** - Permission testing, access controls
- **Badge System** - Badge enumeration and security
- **Trust Levels** - Trust level analysis and exploitation
- **Admin Panel** - Admin interface security testing

### 🛡️ **Security Testing**
- **Injection Testing** - SQL, XSS, Command injection
- **File Upload Security** - Upload bypass techniques
- **Authentication Testing** - Weak credentials, brute force protection
- **Session Management** - Session fixation, concurrent sessions

### 📊 **Performance & Monitoring**
- **Load Testing** - Stress testing with configurable parameters
- **Response Analysis** - Performance metrics and optimization
- **Health Checking** - Comprehensive system health assessment
- **Uptime Monitoring** - Availability tracking over time

### 📄 **Advanced Reporting**
- **JSON Reports** - Machine-readable structured data
- **HTML Reports** - Professional styled reports with charts
- **CSV Export** - Spreadsheet-compatible vulnerability data
- **XML Format** - Structured markup for integrations

### 🔗 **Integrations**
- **Slack Notifications** - Real-time alerts to Slack channels
- **Webhook Support** - Custom webhook integrations
- **CI/CD Pipeline** - Automated security testing
- **API Endpoints** - RESTful API for external tools

## 🛠️ Installation

### Quick Install
```bash
git clone https://github.com/ibrahmsql/discoursemap.git
cd discoursemap
pip install -r requirements.txt
```

### Docker Installation
```bash
docker build -t discoursemap:2.1.0 .
docker run --rm -it discoursemap:2.1.0
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

# Initialize scanner
scanner = DiscourseScanner('https://forum.example.com')

# Run comprehensive scan
results = scanner.scan()

# Generate reports
from discoursemap.reporting import HTMLReporter
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

# Test rate limiting
rate_tester = RateLimitModule('https://forum.example.com', verbose=True)
results = rate_tester.scan()

print(f"Rate limiting vulnerabilities: {len(results['vulnerabilities'])}")
```

### Performance Testing
```python
from discoursemap.performance import LoadTester, ResponseAnalyzer

# Performance analysis
analyzer = ResponseAnalyzer('https://forum.example.com')
perf_results = analyzer.analyze_endpoint_performance()

# Load testing (be careful with real sites)
load_tester = LoadTester('https://forum.example.com')
load_results = load_tester.run_load_test(concurrent_users=5, duration=30)
```

### Security Testing
```python
from discoursemap.security.testing import InjectionTester, AuthenticationTester

# Injection testing
injection_tester = InjectionTester('https://forum.example.com')
injection_results = injection_tester.test_all_injections()

# Authentication testing
auth_tester = AuthenticationTester('https://forum.example.com')
auth_results = auth_tester.test_all_auth_vulnerabilities()
```

## 📊 Demo

Run the interactive demo to see all features:

```bash
python demo.py
```

Test against a real Discourse site (ethically):

```bash
python real_test.py
```

## 🏗️ Modular Architecture

DiscourseMap v2.1 features a completely modular architecture:

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

Run the test suite:

```bash
# Unit tests
python -m pytest tests/ -v

# Import test
python -c "import discoursemap; print('✓ Import successful')"

# Full test suite
make test
```

## 🐳 Docker Support

### Build and Run
```bash
# Build image
make docker-build

# Run container
make docker-run

# Docker Compose (with Redis and PostgreSQL)
docker-compose up -d
```

### Docker Hub
```bash
docker pull ibrahimsql/discoursemap:latest
docker run --rm -it ibrahimsql/discoursemap:latest
```

## 📖 Documentation

- **[Modular Architecture Guide](MODULAR_ARCHITECTURE.md)** - Detailed architecture documentation
- **[API Reference](docs/api.md)** - Complete API documentation
- **[Configuration Guide](docs/configuration.md)** - Configuration options
- **[Integration Guide](docs/integrations.md)** - External integrations

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md).

### Development Setup
```bash
git clone https://github.com/ibrahmsql/discoursemap.git
cd discoursemap
make dev-setup
```

### Code Quality
```bash
make lint          # Run linting
make format        # Format code
make security-check # Security checks
make check-all     # All checks
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Ethical Usage

**IMPORTANT**: This tool is designed for authorized security testing only. Always ensure you have proper authorization before testing any Discourse forum. Respect rate limits, terms of service, and applicable laws.

### Responsible Disclosure
If you discover vulnerabilities using DiscourseMap, please follow responsible disclosure practices and report them to the appropriate parties.

## 🙏 Acknowledgments

- **Discourse Team** - For creating an amazing forum platform
- **Security Community** - For continuous feedback and contributions
- **Open Source Contributors** - For making this project better

## 📞 Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/ibrahmsql/discoursemap/issues)
- **Discussions**: [Community discussions](https://github.com/ibrahmsql/discoursemap/discussions)
- **Email**: ibrahimsql@proton.me

## 🌟 Star History

If you find DiscourseMap useful, please consider giving it a star! ⭐

---

**Made with ❤️ by [ibrahimsql](https://github.com/ibrahmsql)**

*Securing Discourse forums, one scan at a time.*