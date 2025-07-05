# Discourse Security Scanner

A comprehensive security scanning tool for Discourse forum platforms, designed to identify vulnerabilities and security misconfigurations.

## Features

### Core Functionality
- **Target Detection**: Automatically detects Discourse installations
- **Multi-threaded Scanning**: Configurable thread count for faster scans
- **Rate Limiting**: Built-in delays to avoid overwhelming target servers
- **Proxy Support**: HTTP/HTTPS and SOCKS proxy support
- **Session Management**: Maintains cookies and sessions throughout scans
- **SSL/TLS Analysis**: Certificate and encryption analysis

### Scanning Modules

#### Information Gathering
- Discourse version detection
- Plugin enumeration
- Server information gathering
- Configuration analysis
- User enumeration
- Admin panel detection

#### Vulnerability Scanning
- SQL Injection testing
- Cross-Site Scripting (XSS) detection
- Cross-Site Request Forgery (CSRF) testing
- File upload vulnerabilities
- Authentication bypass attempts
- Authorization flaws
- Path traversal testing
- Command injection detection

#### Endpoint Discovery
- Common endpoint enumeration
- API endpoint discovery
- Information disclosure checks
- Admin panel detection
- Backup file discovery
- Configuration file detection
- Debug information exposure
- Robots.txt and sitemap analysis

#### User Security Testing
- Weak password detection
- Brute force protection testing
- Session management analysis
- Password reset vulnerabilities
- Registration security testing
- Account lockout mechanisms

### Reporting
- **JSON Reports**: Machine-readable detailed results
- **HTML Reports**: Human-readable formatted reports
- **Console Output**: Real-time colored terminal output
- **Progress Tracking**: Visual progress bars
- **Vulnerability Scoring**: Risk assessment and prioritization

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ibrahmsql/discoursemap
cd discoursemap
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage
```bash
python main.py -u https://forum.example.com
```

### Advanced Usage
```bash
# Full scan with custom settings
python main.py -u https://forum.example.com -t 20 -d 0.5 --verbose

# Specific modules only
python main.py -u https://forum.example.com -m info,vuln

# With proxy support
python main.py -u https://forum.example.com --proxy http://127.0.0.1:8080

# Generate reports
python main.py -u https://forum.example.com --json-output report.json --html-output report.html
```

### Command Line Options

```
-u, --url           Target Discourse URL (required)
-t, --threads       Number of threads (default: 10)
-d, --delay         Delay between requests in seconds (default: 0.1)
-m, --modules       Comma-separated list of modules to run
--proxy             Proxy URL (http://host:port or socks5://host:port)
--user-agent        Custom User-Agent string
--timeout           Request timeout in seconds (default: 10)
--json-output       JSON report output file
--html-output       HTML report output file
--verbose           Enable verbose output
--quiet             Suppress non-essential output
```

### Available Modules
- `info`: Information gathering
- `vuln`: Vulnerability scanning
- `endpoint`: Endpoint discovery
- `user`: User security testing

## Output Examples

### Console Output
```
[INFO] Starting Discourse security scan...
[SUCCESS] Target verified as Discourse site
[INFO] Running info module...
[SUCCESS] Discourse version detected: 3.1.0
[WARNING] Outdated version detected - known vulnerabilities exist
[INFO] Running vulnerability module...
[CRITICAL] SQL injection vulnerability found in search endpoint
[HIGH] XSS vulnerability found in user profile
```

### JSON Report Structure
```json
{
  "scan_info": {
    "target_url": "https://forum.example.com",
    "start_time": "2024-01-15T10:30:00Z",
    "end_time": "2024-01-15T10:35:30Z",
    "duration": 330.5
  },
  "modules": {
    "info": {
      "discourse_version": "3.1.0",
      "plugins": [...],
      "server_info": {...}
    },
    "vulnerabilities": [
      {
        "title": "SQL Injection in Search",
        "severity": "critical",
        "description": "...",
        "proof_of_concept": "..."
      }
    ]
  }
}
```

## Security Considerations

### Legal Notice
**IMPORTANT**: This tool is intended for authorized security testing only. Users must:
- Obtain explicit written permission before scanning any system
- Comply with all applicable laws and regulations
- Use the tool responsibly and ethically
- Not use it for malicious purposes

### Responsible Disclosure
If you discover vulnerabilities using this tool:
1. Report them responsibly to the affected organization
2. Allow reasonable time for fixes before public disclosure
3. Follow coordinated vulnerability disclosure practices

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided "as is" without warranty of any kind. The authors are not responsible for any damage or legal issues arising from the use of this tool. Users are solely responsible for ensuring they have proper authorization before conducting any security testing.

## Contact

- Author: ibrahimsql 
- GitHub: https://github.com/ibrahmsql
- Email: ibrahimsql@proton.me

## Acknowledgments

- Inspired by tools like sqlmap, wpscan, and Metasploit
- Thanks to the security research community
- Discourse team for creating an excellent platform
