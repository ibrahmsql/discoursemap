# 🛡️ DiscourseMap

<div align="center">

![DiscourseMap](https://img.shields.io/badge/DiscourseMap-Security%20Scanner-red?style=for-the-badge&logo=discourse)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![Ruby](https://img.shields.io/badge/Ruby-2.7+-red?style=for-the-badge&logo=ruby)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=for-the-badge)

**Comprehensive security testing framework for Discourse forums**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Modules](#-modules) • [Contributing](#-contributing)

</div>

## 📋 Overview

DiscourseMap is a comprehensive, modular security testing framework specifically designed for Discourse forum platforms. It combines Python-based scanning modules with Ruby exploit integration to provide thorough security assessments covering everything from basic information gathering to advanced vulnerability exploitation.

### 🎯 Key Highlights

- **25+ Security Modules** covering all aspects of Discourse security
- **Ruby Exploit Integration** with 25+ CVE-specific exploits
- **Modular Architecture** for easy extension and customization
- **Comprehensive Coverage** from reconnaissance to exploitation
- **Professional Reporting** with detailed findings and recommendations
- **Active Development** with regular updates and new features

## 🚀 Features

### 🔍 Core Security Testing

| Category | Description | Modules |
|----------|-------------|----------|
| **Information Gathering** | Reconnaissance and fingerprinting | Info, Endpoint, User |
| **Vulnerability Assessment** | Core security testing | Vulnerability, CVE Exploits |
| **Authentication & Authorization** | Access control testing | Auth, Session Management |
| **Configuration Security** | Misconfigurations and hardening | Config, Network |
| **Cryptographic Analysis** | Crypto implementation testing | Crypto, SSL/TLS |
| **Plugin & Theme Security** | Extension security testing | Plugin, Theme Analysis |

### 🛠️ Advanced Capabilities

- **Multi-Vector Testing**: Combines automated scanning with manual exploit techniques
- **CVE Database**: Integrated database of Discourse-specific vulnerabilities
- **Custom Payloads**: Sophisticated payload generation and testing
- **Evasion Techniques**: Advanced methods to bypass security controls
- **Real-time Analysis**: Live vulnerability detection and exploitation
- **Detailed Reporting**: Comprehensive reports with remediation guidance

## 📦 Installation

### 🚀 Quick Install (Recommended)
```bash
# Install from PyPI - Simple and fast!
pip install discoursemap

# Verify installation
discoursemap --help

# Start scanning immediately
discoursemap -u https://forum.example.com
```

### 📦 Alternative Installation Methods
```bash
# Install with pipx for isolated environment
pipx install discoursemap

# Install specific version
pip install discoursemap==1.1.0

# Upgrade to latest version
pip install --upgrade discoursemap
```

### Prerequisites

```bash
# System Requirements
- Python 3.8 or higher
- Ruby 2.7 or higher
- Git
- Internet connection for dependency installation
```

### 🔧 Manual Installation

```bash
# Clone the repository
git clone https://github.com/ibrahmsql/discoursemap.git
cd discoursemap

# Install Python dependencies
pip3 install -r requirements.txt

# Install Ruby dependencies
bundle install

# Make scripts executable
chmod +x discoursemap/scanner.py
chmod +x ruby_exploit_runner.rb

# Verify installation
python3 discoursemap/scanner.py --help
```

### Docker Installation

```bash
# Build Docker image
docker build -t discoursemap .

# Run scanner with Docker
docker run --rm -v $(pwd)/reports:/app/reports discoursemap \
  python3 main.py -u https://target-forum.com --modules info

# Using Docker Compose
docker-compose build
docker-compose run --rm discoursemap \
  python3 main.py -u https://target-forum.com --modules info,vuln

# Interactive mode
docker run -it --rm discoursemap bash
```

### Development Setup

```bash
# Install development dependencies
pip3 install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run tests
python3 -m pytest tests/
```

## 🎯 Usage

### Basic Scanning

```bash
# Basic security scan
python3 discoursemap/scanner.py -u https://discourse.example.com

# Scan with specific modules
python3 discoursemap/scanner.py -u https://discourse.example.com -m info,vulnerability,auth

# Aggressive scan with all modules
python3 discoursemap/scanner.py -u https://discourse.example.com --aggressive

# Scan with custom output
python3 discoursemap/scanner.py -u https://discourse.example.com -o results.json
```

### Advanced Options

```bash
# Scan with authentication
python3 discoursemap/scanner.py -u https://discourse.example.com \
  --username admin --password secretpass

# Scan with proxy
python3 discoursemap/scanner.py -u https://discourse.example.com \
  --proxy http://127.0.0.1:8080

# Scan with custom headers
python3 discoursemap/scanner.py -u https://discourse.example.com \
  --headers "X-Forwarded-For: 127.0.0.1" "User-Agent: CustomBot/1.0"

# Stealth mode with delays
python3 discoursemap/scanner.py -u https://discourse.example.com \
  --delay 2 --random-delay
```

### Ruby Exploit Integration

```bash
# Run specific CVE exploits
python3 discoursemap/modules/cve_exploit_module.py \
  --target https://discourse.example.com \
  --cve CVE-2021-41163

# Run all Ruby exploits
ruby ruby_exploit_runner.rb https://discourse.example.com

# Run exploits with custom parameters
ruby ruby_exploit_runner.rb https://discourse.example.com \
  --timeout 30 --threads 5
```

## 🧩 Modules

### 🔍 Information Gathering

#### Info Module (`info_module.py`)
- **Server Information**: Version detection, technology stack
- **Configuration Discovery**: Settings, features, plugins
- **User Enumeration**: Active users, administrators, moderators
- **Content Analysis**: Categories, topics, sensitive information

#### Endpoint Module (`endpoint_module.py`)
- **Directory Discovery**: Hidden paths, admin panels, API endpoints
- **File Discovery**: Backup files, configuration files, logs
- **API Enumeration**: REST endpoints, GraphQL schemas
- **Subdomain Discovery**: Related domains and services

### 🛡️ Security Testing

#### Vulnerability Module (`vulnerability_module.py`)
- **Injection Attacks**: SQL, NoSQL, LDAP, Command injection
- **Cross-Site Scripting**: Reflected, Stored, DOM-based XSS
- **Cross-Site Request Forgery**: CSRF token analysis
- **Server-Side Request Forgery**: SSRF testing
- **XML External Entity**: XXE vulnerability testing
- **Insecure Deserialization**: Object injection attacks

#### Auth Module (`auth_module.py`)
- **Authentication Bypass**: Login bypass techniques
- **Privilege Escalation**: Horizontal and vertical escalation
- **Session Management**: Session fixation, hijacking
- **Password Policy**: Weak password detection
- **Account Lockout**: Brute force protection testing
- **OAuth/SSO Security**: Third-party authentication flaws

### 🔐 Cryptographic Security

#### Crypto Module (`crypto_module.py`)
- **Weak Hashing**: MD5, SHA1 detection
- **Weak Encryption**: DES, RC4, ECB mode detection
- **JWT Vulnerabilities**: Algorithm confusion, weak secrets
- **Session Security**: Cookie analysis, CSRF tokens
- **Key Exposure**: Private key leakage
- **Timing Attacks**: Cryptographic timing vulnerabilities

### 🌐 Network & Infrastructure

#### Network Module (`network_module.py`)
- **Port Scanning**: Service discovery
- **SSL/TLS Analysis**: Certificate validation, cipher analysis
- **DNS Analysis**: Zone transfers, subdomain enumeration
- **CDN Detection**: Content delivery network analysis
- **Firewall Detection**: Security control identification
- **Load Balancer Analysis**: Infrastructure mapping

#### Config Module (`config_module.py`)
- **Configuration Files**: Exposed settings, backups
- **Debug Information**: Error messages, stack traces
- **Security Headers**: HSTS, CSP, X-Frame-Options
- **CORS Misconfiguration**: Cross-origin policy flaws
- **Default Credentials**: Common username/password combinations
- **Environment Variables**: Sensitive data exposure

### 🔌 Plugin & Theme Security

#### Plugin Module (`plugin_module.py`)
- **Plugin Discovery**: Installed plugins and themes
- **Vulnerability Testing**: Plugin-specific security flaws
- **Outdated Components**: Version analysis
- **Dangerous Permissions**: Excessive privileges
- **File Access**: Unauthorized file operations
- **Theme Injection**: Template injection vulnerabilities

### 🎯 User & Content Security

#### User Module (`user_module.py`)
- **User Enumeration**: Username discovery techniques
- **Profile Analysis**: Sensitive information exposure
- **Permission Testing**: Access control verification
- **Social Engineering**: Information gathering
- **Account Takeover**: Session and credential attacks

## 🔥 Ruby Exploit Collection

### Critical CVEs (CVSS 9.0+)

| CVE | Description | CVSS | Module |
|-----|-------------|------|--------|
| **CVE-2019-11479** | SQL Injection in search | 9.8 | `CVE-2019-11479.rb` |
| **CVE-2021-41163** | RCE via theme import | 9.8 | `CVE-2021-41163.rb` |
| **CVE-2023-49103** | Admin panel auth bypass | 9.1 | `CVE-2023-49103.rb` |
| **CVE-2024-28084** | File upload RCE | 9.8 | `CVE-2024-28084.rb` |
| **CVE-2024-42364** | SQL injection via search | 9.3 | `CVE-2024-42364.rb` |

### High Severity (CVSS 7.0-8.9)

| CVE | Description | CVSS | Module |
|-----|-------------|------|--------|
| **CVE-2022-31053** | SSRF via onebox preview | 8.6 | `CVE-2022-31053.rb` |
| **CVE-2024-35198** | Server-side template injection | 8.8 | `CVE-2024-35198.rb` |
| **CVE-2023-37467** | CSP nonce reuse XSS | 7.5 | `discourse_cve_exploits.rb` |

### General Vulnerability Categories

- **XSS Exploits** (`discourse_xss.rb`) - Multiple XSS vectors
- **SSRF Exploits** (`discourse_ssrf.rb`) - Server-side request forgery
- **RCE Exploits** (`discourse_rce.rb`) - Remote code execution
- **SQL Injection** (`discourse_sqli.rb`) - Database injection attacks
- **Auth Bypass** (`discourse_auth_bypass.rb`) - Authentication bypass
- **File Upload** (`discourse_file_upload.rb`) - File upload vulnerabilities
- **Info Disclosure** (`discourse_info_disclosure.rb`) - Information leakage
- **CSRF Attacks** (`discourse_csrf.rb`) - Cross-site request forgery
- **XXE Attacks** (`discourse_xxe.rb`) - XML external entity
- **Plugin Exploits** (`discourse_plugin_exploits.rb`) - Plugin vulnerabilities

## 📊 Sample Output

```
🛡️  DiscourseMap v2.0
🎯 Target: https://discourse.example.com
⏰ Started: 2024-12-20 10:30:15

[INFO] Starting comprehensive security scan...
[INFO] Modules loaded: info, endpoint, vulnerability, auth, crypto

📋 Information Gathering
├── [✓] Server: Discourse 3.1.2 (Ruby 3.0.4)
├── [✓] Plugins: 12 installed (3 outdated)
├── [⚠️] Admin users: 2 discovered
└── [✓] Categories: 15 public, 3 restricted

🔍 Endpoint Discovery
├── [✓] Admin panel: /admin (protected)
├── [⚠️] Debug endpoint: /debug (exposed)
├── [✓] API endpoints: 45 discovered
└── [❌] Backup files: config.bak found

🛡️ Vulnerability Assessment
├── [❌] SQL Injection: 2 vulnerabilities found
├── [⚠️] XSS: 1 stored XSS in user profiles
├── [❌] CSRF: Missing tokens on 3 endpoints
└── [✓] File upload: Properly restricted

🔐 Authentication & Authorization
├── [❌] Default credentials: admin/admin works
├── [⚠️] Session management: No timeout configured
├── [✓] Password policy: Strong requirements
└── [❌] Privilege escalation: Role manipulation possible

🔒 Cryptographic Security
├── [⚠️] Weak hashing: MD5 found in password reset
├── [✓] SSL/TLS: Properly configured
├── [❌] JWT: Algorithm confusion vulnerability
└── [⚠️] Session cookies: Missing secure flag

📈 Scan Summary
├── 🔴 Critical: 3 vulnerabilities
├── 🟡 High: 5 vulnerabilities  
├── 🟠 Medium: 8 vulnerabilities
└── 🟢 Low: 12 vulnerabilities

💾 Report saved: discourse_scan_20241220_103015.json
⏱️  Scan completed in 4m 32s
```

## 📋 Configuration

### Configuration File (`config.yaml`)

```yaml
# DiscourseMap Configuration

# Target Configuration
target:
  url: "https://discourse.example.com"
  timeout: 30
  retries: 3
  verify_ssl: true

# Authentication
auth:
  username: ""
  password: ""
  api_key: ""
  session_cookie: ""

# Scanning Options
scan:
  modules:
    - info
    - endpoint
    - vulnerability
    - auth
    - crypto
    - network
    - config
    - plugin
    - user
  
  aggressive: false
  delay: 1
  random_delay: true
  threads: 5

# Proxy Configuration
proxy:
  http: ""
  https: ""
  socks: ""

# Output Configuration
output:
  format: "json"  # json, xml, html, pdf
  file: "scan_results.json"
  verbose: true
  colors: true

# Ruby Exploit Configuration
ruby_exploits:
  enabled: true
  timeout: 60
  max_threads: 3
  cve_filter: []  # Empty = all CVEs

# Reporting
reporting:
  include_screenshots: false
  include_payloads: true
  risk_scoring: true
  compliance_mapping: true
```

### Environment Variables

```bash
# Set environment variables for sensitive data
export DISCOURSE_USERNAME="admin"
export DISCOURSE_PASSWORD="secretpass"
export DISCOURSE_API_KEY="your-api-key"
export PROXY_URL="http://127.0.0.1:8080"
```

## 🔧 Development

### Project Structure

```
discoursemap/
├── discoursemap/
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── info_module.py
│   │   ├── endpoint_module.py
│   │   ├── vulnerability_module.py
│   │   ├── auth_module.py
│   │   ├── crypto_module.py
│   │   ├── network_module.py
│   │   ├── config_module.py
│   │   ├── plugin_module.py
│   │   ├── user_module.py
│   │   ├── cve_exploit_module.py
│   │   └── utils.py
│   └── scanner.py
├── ruby_exploits/
│   ├── CVE-2019-11479.rb
│   ├── CVE-2021-41163.rb
│   ├── CVE-2022-31053.rb
│   ├── CVE-2023-49103.rb
│   ├── CVE-2024-28084.rb
│   ├── CVE-2024-35198.rb
│   ├── CVE-2024-42364.rb
│   ├── discourse_xss.rb
│   ├── discourse_ssrf.rb
│   ├── discourse_rce.rb
│   ├── discourse_sqli.rb
│   ├── discourse_auth_bypass.rb
│   ├── discourse_file_upload.rb
│   ├── discourse_info_disclosure.rb
│   ├── discourse_csrf.rb
│   ├── discourse_xxe.rb
│   ├── discourse_plugin_exploits.rb
│   ├── discourse_cve_exploits.rb
│   ├── discourse_file_upload_exploits.rb
│   ├── discourse_api_exploits.rb
│   └── discourse_privilege_escalation.rb
├── tests/
│   ├── test_modules.py
│   ├── test_exploits.py
│   └── test_integration.py
├── docs/
│   ├── API.md
│   ├── MODULES.md
│   └── EXPLOITS.md
├── requirements.txt
├── requirements-dev.txt
├── Gemfile
├── Dockerfile
├── config.yaml.example
├── TODO.md
└── README.md
```

### Adding New Modules

```python
# Example: Creating a new module
class CustomModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Custom Security Testing',
            'target': scanner.target_url,
            'vulnerabilities': []
        }
    
    def run_scan(self):
        """Main scanning logic"""
        print(f"[*] Running custom security tests...")
        
        # Your testing logic here
        self._test_custom_vulnerability()
        
        return self.results
    
    def _test_custom_vulnerability(self):
        """Test for custom vulnerability"""
        # Implementation here
        pass
```

### Adding Ruby Exploits

```ruby
# Example: Creating a new Ruby exploit
class CustomExploit
  def initialize(target_url)
    @target_url = target_url
    @results = []
  end
  
  def run_exploit
    puts "[*] Testing custom vulnerability..."
    
    # Your exploit logic here
    test_custom_vulnerability
    
    @results
  end
  
  private
  
  def test_custom_vulnerability
    # Implementation here
  end
end
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run specific test categories
python3 -m pytest tests/test_modules.py -v
python3 -m pytest tests/test_exploits.py -v

# Run with coverage
python3 -m pytest tests/ --cov=discoursemap --cov-report=html

# Run integration tests
python3 -m pytest tests/test_integration.py -v --slow
```

### Test Environment Setup

```bash
# Set up test Discourse instance
docker run -d --name discourse-test \
  -p 8080:80 \
  discourse/discourse:latest

# Run tests against test instance
python3 discoursemap/scanner.py -u http://localhost:8080 --test-mode
```

## 📚 Documentation

- **[API Reference](docs/API.md)** - Complete API documentation
- **[Module Guide](docs/MODULES.md)** - Detailed module documentation
- **[Exploit Guide](docs/EXPLOITS.md)** - Ruby exploit documentation
- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute
- **[Security Policy](SECURITY.md)** - Responsible disclosure
- **[Changelog](CHANGELOG.md)** - Version history

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Quick Start for Contributors

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Areas for Contribution

- 🐛 **Bug fixes** and improvements
- 🚀 **New security modules** and tests
- 💎 **Ruby exploit modules** for new CVEs
- 📚 **Documentation** improvements
- 🧪 **Test coverage** expansion
- 🎨 **UI/UX** enhancements
- 🔧 **Performance** optimizations

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**IMPORTANT**: This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The developers assume no liability for misuse of this tool.

### Responsible Use Guidelines

- ✅ **Only test systems you own or have explicit permission to test**
- ✅ **Follow responsible disclosure practices**
- ✅ **Respect rate limits and avoid DoS conditions**
- ✅ **Use in compliance with local laws and regulations**
- ❌ **Do not use for malicious purposes**
- ❌ **Do not test systems without authorization**

## 🙏 Acknowledgments

- **Discourse Team** for creating an amazing platform
- **Security Researchers** who discovered and reported vulnerabilities
- **Open Source Community** for tools and libraries used
- **Contributors** who help improve this project

## 📞 Support & Contact

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/ibrahmsql/discoursemap/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/ibrahmsql/discoursemap/discussions)
- 🔒 **Security Issues**: ibrahimsql@proton.me
- 📧 **Email**: ibrahimsql@proton.me

---

<div align="center">

**Made with ❤️ by İbrahimsql**

[![GitHub stars](https://img.shields.io/github/stars/ibrahmsql/discoursemap?style=social)](https://github.com/ibrahmsql/discoursemap/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/ibrahmsql/discoursemap?style=social)](https://github.com/ibrahmsql/discoursemap/network/members)
[![GitHub issues](https://img.shields.io/github/issues/ibrahmsql/discoursemap)](https://github.com/ibrahmsql/discoursemap/issues)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/ibrahmsql/discoursemap)](https://github.com/ibrahmsql/discoursemap/pulls)

</div>
