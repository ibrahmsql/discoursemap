# DiscourseMap API Documentation

Complete API reference for using DiscourseMap programmatically in Python.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Classes](#core-classes)
- [Modules](#modules)
- [Configuration](#configuration)
- [Examples](#examples)
- [Advanced Usage](#advanced-usage)

---

## Installation

```bash
pip install discoursemap
```

---

## Quick Start

### Basic Usage

```python
from discoursemap.core.discourse_scanner import DiscourseScanner

# Initialize scanner
scanner = DiscourseScanner("https://meta.discourse.org", verbose=True)

# Run scan
results = scanner.scan()

# Access results
print(f"Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
```

### Run Specific Modules

```python
from discoursemap.core.discourse_scanner import DiscourseScanner

scanner = DiscourseScanner(
    target_url="https://forum.example.com",
    modules=['info', 'cve', 'plugin'],
    verbose=True
)

results = scanner.scan()
```

---

## Core Classes

### DiscourseScanner

Main scanner class for orchestrating security assessments.

#### Constructor

```python
DiscourseScanner(
    target_url: str,
    modules: List[str] = None,
    threads: int = 5,
    timeout: int = 10,
    proxy: str = None,
    verbose: bool = False,
    config: dict = None
)
```

**Parameters:**
- `target_url` (str): Target Discourse forum URL
- `modules` (List[str], optional): List of modules to run. Default: all modules
- `threads` (int, optional): Number of concurrent threads. Default: 5
- `timeout` (int, optional): HTTP request timeout in seconds. Default: 10
- `proxy` (str, optional): Proxy server URL (e.g., "http://127.0.0.1:8080")
- `verbose` (bool, optional): Enable verbose output. Default: False
- `config` (dict, optional): Custom configuration dictionary

**Example:**
```python
scanner = DiscourseScanner(
    target_url="https://meta.discourse.org",
    modules=['info', 'plugin', 'api'],
    threads=10,
    timeout=15,
    verbose=True
)
```

#### Methods

##### `scan() -> dict`

Run the security scan.

```python
results = scanner.scan()
```

**Returns:**
- `dict`: Scan results containing findings, vulnerabilities, and module outputs

**Example:**
```python
scanner = DiscourseScanner("https://meta.discourse.org")
results = scanner.scan()

print(f"Modules run: {results['modules_run']}")
print(f"Duration: {results['scan_duration']} seconds")
```

##### `get_results() -> dict`

Get the last scan results without running a new scan.

```python
results = scanner.get_results()
```

##### `save_results(filename: str, format: str = 'json') -> bool`

Save scan results to a file.

```python
scanner.save_results('report.json', format='json')
scanner.save_results('report.html', format='html')
```

---

## Modules

### Available Modules

DiscourseMap includes 25 specialized security modules:

#### Core Analysis Modules

##### InfoModule
```python
from discoursemap.analysis.info.info_module import InfoModule

info = InfoModule("https://meta.discourse.org", verbose=True)
results = info.run()

print(f"Discourse version: {results.get('version')}")
print(f"Plugins: {results.get('plugins')}")
```

##### CVEModule
```python
from discoursemap.security.exploits.cve_exploit_module import CVEExploitModule

cve = CVEExploitModule("https://meta.discourse.org", verbose=True)
results = cve.run()

for vuln in results.get('vulnerabilities', []):
    print(f"CVE: {vuln['cve_id']} - {vuln['severity']}")
```

##### PluginModule
```python
from discoursemap.analysis.plugins.plugin_module import PluginModule

plugin = PluginModule("https://meta.discourse.org", verbose=True)
results = plugin.run()

print(f"Plugins found: {len(results.get('plugins', []))}")
```

#### Security Testing Modules

##### AuthModule
```python
from discoursemap.security.auth.auth_module import AuthModule

auth = AuthModule("https://meta.discourse.org", verbose=True)
results = auth.run()

for issue in results.get('vulnerabilities', []):
    print(f"Auth issue: {issue['type']} - {issue['severity']}")
```

##### APIModule
```python
from discoursemap.infrastructure.api.api_module import APIModule

api = APIModule("https://meta.discourse.org", verbose=True)
results = api.run()
```

#### Discourse-Specific Modules

##### BadgeSecurityModule
```python
from discoursemap.discourse_specific.badges import BadgeSecurityModule

badge = BadgeSecurityModule("https://meta.discourse.org", verbose=True)
results = badge.run()

print(f"Badges found: {len(results.get('badges_found', []))}")
```

##### CategorySecurityModule
```python
from discoursemap.discourse_specific.categories import CategorySecurityModule

category = CategorySecurityModule("https://meta.discourse.org", verbose=True)
results = category.run()

print(f"Categories: {len(results.get('categories_found', []))}")
```

##### RateLimitModule
```python
from discourseap.discourse_specific.rate_limiting import RateLimitModule

rate_limit = RateLimitModule("https://meta.discourse.org", verbose=True)
results = rate_limit.scan()
```

---

## Configuration

### Configuration File

Create a configuration file `~/.discoursemap/config.yaml`:

```yaml
# Global settings
default:
  timeout: 60
  threads: 10
  verbose: false
  skip_ssl_verify: false

# Module-specific settings
modules:
  info:
    enabled: true
  cve:
    enabled: true
    check_plugins: true
  plugin:
    enabled: true
    bruteforce: false
  
# Proxy settings
proxy:
  http: http://127.0.0.1:8080
  https: http://127.0.0.1:8080
  enabled: false

# Output settings
output:
  format: json
  save_results: true
  directory: ./reports
```

### Using Configuration in Code

```python
import yaml
from discoursemap.core.discourse_scanner import DiscourseScanner

# Load configuration
with open('config.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Initialize scanner with config
scanner = DiscourseScanner(
    target_url="https://meta.discourse.org",
    config=config
)

results = scanner.scan()
```

---

## Examples

### Example 1: Quick Vulnerability Scan

```python
from discoursemap.core.discourse_scanner import DiscourseScanner

def quick_scan(url):
    scanner = DiscourseScanner(
        target_url=url,
        modules=['info', 'cve', 'plugin'],
        verbose=True
    )
    
    results = scanner.scan()
    
    # Print summary
    print("\n=== Scan Summary ===")
    print(f"Target: {url}")
    print(f"Duration: {results['scan_duration']}s")
    print(f"Vulnerabilities: {len(results.get('vulnerabilities', []))}")
    
    return results

# Run scan
results = quick_scan("https://meta.discourse.org")
```

### Example 2: Comprehensive Security Audit

```python
from discoursemap.core.discourse_scanner import DiscourseScanner
import json

def full_audit(url, output_file='audit_report.json'):
    # All modules
    scanner = DiscourseScanner(
        target_url=url,
        threads=10,
        timeout=60,
        verbose=True
    )
    
    print(f"Starting comprehensive audit of {url}...")
    results = scanner.scan()
    
    # Save detailed report
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Print high/critical findings
    high_severity = [
        v for v in results.get('vulnerabilities', [])
        if v.get('severity') in ['high', 'critical']
    ]
    
    print(f"\n=== High/Critical Findings: {len(high_severity)} ===")
    for vuln in high_severity:
        print(f"- {vuln.get('title')} ({vuln.get('severity')})")
    
    return results

# Run audit
audit_results = full_audit("https://forum.example.com")
```

### Example 3: Batch Scanning Multiple Forums

```python
from discoursemap.core.discourse_scanner import DiscourseScanner
from concurrent.futures import ThreadPoolExecutor
import json

def scan_forum(url):
    scanner = DiscourseScanner(
        target_url=url,
        modules=['info', 'cve'],
        verbose=False
    )
    
    results = scanner.scan()
    return {
        'url': url,
        'vulnerabilities': len(results.get('vulnerabilities', [])),
        'duration': results.get('scan_duration')
    }

# List of forums
forums = [
    "https://meta.discourse.org",
    "https://forum1.example.com",
    "https://forum2.example.com"
]

# Scan in parallel
with ThreadPoolExecutor(max_workers=3) as executor:
    results = list(executor.map(scan_forum, forums))

# Print results
for result in results:
    print(f"{result['url']}: {result['vulnerabilities']} issues ({result['duration']}s)")
```

### Example 4: Custom Module Integration

```python
from discoursemap.core.scanner.base_scanner import BaseScanner

class CustomModule(BaseScanner):
    """Custom security module"""
    
    def run(self):
        results = {
            'module': 'custom',
            'findings': []
        }
        
        # Your custom scanning logic
        response = self.session.get(f"{self.target_url}/custom-endpoint")
        
        if response.status_code == 200:
            results['findings'].append({
                'type': 'custom_finding',
                'severity': 'medium'
            })
        
        return results

# Use custom module
custom = CustomModule("https://meta.discourse.org", verbose=True)
results = custom.run()
print(results)
```

### Example 5: CI/CD Integration

```python
import sys
from discoursemap.core.discourse_scanner import DiscourseScanner

def ci_scan(url, fail_on_high=True):
    """Scan for CI/CD pipeline"""
    scanner = DiscourseScanner(
        target_url=url,
        modules=['cve', 'plugin', 'auth'],
        verbose=False
    )
    
    results = scanner.scan()
    
    # Check for high/critical issues
    high_issues = [
        v for v in results.get('vulnerabilities', [])
        if v.get('severity') in ['high', 'critical']
    ]
    
    if high_issues and fail_on_high:
        print(f"FAILED: {len(high_issues)} high/critical issues found")
        for issue in high_issues:
            print(f"  - {issue.get('title')}")
        sys.exit(1)
    
    print(f"PASSED: {len(results.get('vulnerabilities', []))} total issues")
    sys.exit(0)

# Run in CI
if __name__ == "__main__":
    ci_scan("https://staging.forum.example.com")
```

---

## Advanced Usage

### Custom User Agents

```python
from discoursemap.core.discourse_scanner import DiscourseScanner

scanner = DiscourseScanner(
    target_url="https://meta.discourse.org",
    config={
        'user_agent': 'Mozilla/5.0 (Custom Scanner)'
    }
)
```

### Proxy Configuration

```python
scanner = DiscourseScanner(
    target_url="https://meta.discourse.org",
    proxy="http://127.0.0.1:8080"
)
```

### SSL Verification

```python
scanner = DiscourseScanner(
    target_url="https://meta.discourse.org",
    config={'skip_ssl_verify': True}
)
```

### Rate Limiting

```python
scanner = DiscourseScanner(
    target_url="https://meta.discourse.org",
    config={'delay': 0.5}  # 500ms delay between requests
)
```

---

## Error Handling

```python
from discoursemap.core.discourse_scanner import DiscourseScanner

try:
    scanner = DiscourseScanner("https://meta.discourse.org")
    results = scanner.scan()
except ConnectionError as e:
    print(f"Connection error: {e}")
except TimeoutError as e:
    print(f"Timeout error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

---

## Full Module List

```python
AVAILABLE_MODULES = [
    'info',                 # Information gathering
    'vuln',                 # Vulnerability scanning
    'endpoint',             # Endpoint discovery
    'user',                 # User enumeration
    'cve',                  # CVE detection
    'plugin_detection',     # Plugin detection
    'plugin_bruteforce',    # Plugin bruteforce
    'api',                  # API security
    'auth',                 # Authentication testing
    'config',               # Configuration audit
    'crypto',               # Cryptography analysis
    'network',              # Network security
    'plugin',               # Plugin security
    'waf_bypass',           # WAF bypass testing
    'compliance',           # Compliance checking
    'badge',                # Badge security
    'category',             # Category permissions
    'trust_level',          # Trust level testing
    'rate_limit',           # Rate limiting
    'session',              # Session security
    'admin',                # Admin panel testing
    'webhook',              # Webhook security
    'email',                # Email security
    'search',               # Search security
    'cache',                # Cache security
]
```

---

## Support

- **GitHub Issues**: https://github.com/ibrahmsql/discoursemap/issues
- **Documentation**: https://github.com/ibrahmsql/discoursemap
- **PyPI**: https://pypi.org/project/discoursemap/

---

## License

MIT License - see [LICENSE](../LICENSE) for details.
