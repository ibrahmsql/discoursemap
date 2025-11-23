# DiscourseMap Manual

**Version:** 2.1.0  
**Author:** ibrahimsql  
**License:** MIT

---

## NAME

**discoursemap** - Comprehensive security scanner for Discourse forums

---

## SYNOPSIS

```bash
discoursemap -u URL [OPTIONS]
discoursemap --help
discoursemap --update
```

---

## DESCRIPTION

DiscourseMap is a specialized security assessment tool designed specifically for Discourse forum platforms. It performs comprehensive security testing including vulnerability detection, misconfigurations, authentication issues, and platform-specific security checks.

**Features:**
- 50+ specialized security modules
- Advanced rate limiting and bypass testing
- Injection testing (SQL, XSS, Command Injection)
- Authentication and session security analysis
- Plugin and theme vulnerability detection
- Performance monitoring and load testing
- Multiple report formats (JSON, HTML, CSV)
- External integrations (Slack, Webhooks)

---

## OPTIONS

### Required Arguments

**-u, --url URL**  
Target Discourse forum URL (required)

**Example:**
```bash
discoursemap -u https://forum.example.com
```

---

### Performance Options

**-t, --threads THREADS**  
Number of concurrent threads (default: 5)

**--timeout TIMEOUT**  
HTTP request timeout in seconds (default: 10)

**--delay DELAY**  
Delay between requests in seconds (default: 0.05)

**--fast**  
Maximum speed preset (50 threads, 0.01s delay)

**--balanced**  
Balanced preset (20 threads, 0.05s delay) [DEFAULT]

**--safe**  
Safe preset (10 threads, 0.1s delay) [RECOMMENDED FOR PRODUCTION]

**--sync**  
Use synchronous scanning (slower but more stable)

**Examples:**
```bash
# Fast scan for development
discoursemap -u https://forum.test.local --fast

# Safe scan for production
discoursemap -u https://forum.example.com --safe

# Custom configuration
discoursemap -u https://forum.example.com -t 15 --delay 0.1
```

---

### Network Options

**-p, --proxy PROXY**  
Proxy server URL (e.g., http://127.0.0.1:8080)

**--user-agent USER_AGENT**  
Custom User-Agent string

**--skip-ssl-verify**  
Skip SSL certificate verification (not recommended)

**Examples:**
```bash
# Use Burp Suite proxy
discoursemap -u https://forum.example.com -p http://127.0.0.1:8080

# Custom User-Agent
discoursemap -u https://forum.example.com --user-agent "MyScanner/1.0"

# Skip SSL verification (testing only)
discoursemap -u https://self-signed.local --skip-ssl-verify
```

---

### Module Selection

**-m, --modules MODULE [MODULE ...]**  
Select specific modules to run (default: all)

**Available Modules:**

**Information Gathering:**
- `info` - Gather site information and version detection
- `user` - User enumeration
- `endpoint` - API endpoint discovery

**Vulnerability Detection:**
- `vuln` - General vulnerability scanning
- `cve` - CVE exploit testing
- `plugin_detection` - Plugin discovery
- `plugin_bruteforce` - Brute-force plugin discovery
- `waf_bypass` - WAF bypass techniques

**Security Testing:**
- `auth` - Authentication testing
- `session` - Session security analysis
- `rate_limit` - Rate limiting tests
- `api` - API security testing
- `crypto` - Cryptographic security
- `config` - Configuration security
- `network` - Network security

**Discourse-Specific:**
- `admin` - Admin panel security
- `badge` - Badge system analysis
- `category` - Category security
- `trust_level` - Trust level analysis
- `webhook` - Webhook security
- `email` - Email security
- `search` - Search security
- `cache` - Cache security

**Compliance:**
- `compliance` - Compliance checks

**Examples:**
```bash
# Quick info scan
discoursemap -u https://forum.example.com -m info

# Multiple specific modules
discoursemap -u https://forum.example.com -m info vuln auth

# All vulnerability modules
discoursemap -u https://forum.example.com -m vuln cve plugin_detection

# Comprehensive Discourse-specific scan
discoursemap -u https://forum.example.com -m admin badge category trust_level
```

---

### Quick Scan Mode

**-q, --quick**  
Run quick scan with essential modules (info, auth, api, vuln, waf_bypass)

**Example:**
```bash
discoursemap -u https://forum.example.com --quick
```

---

### Output Options

**-o, --output {json,html,csv}**  
Report format

**-f, --output-file OUTPUT_FILE**  
Custom output filename

**Examples:**
```bash
# JSON report
discoursemap -u https://forum.example.com -o json

# Custom filename
discoursemap -u https://forum.example.com -o html -f security_audit_2025.html

# CSV for spreadsheet analysis
discoursemap -u https://forum.example.com -o csv -f vulnerabilities.csv
```

---

### Advanced Options

**--verbose, -v**  
Enable detailed output and debugging information

**--quiet**  
Minimal output (results only)

**-c, --config CONFIG**  
Load configuration from YAML file

**--resume RESUME**  
Resume scan from partial results file

**--update**  
Update DiscourseMap to latest version

**Examples:**
```bash
# Verbose mode for debugging
discoursemap -u https://forum.example.com --verbose

# Quiet mode for automation
discoursemap -u https://forum.example.com --quiet -o json

# Use config file
discoursemap -c config.yaml

# Resume interrupted scan
discoursemap --resume partial_scan_1234567890.json
```

---

## USAGE EXAMPLES

### Basic Security Scan
```bash
discoursemap -u https://forum.example.com
```

### Quick Vulnerability Assessment
```bash
discoursemap -u https://forum.example.com --quick --fast
```

### Comprehensive Security Audit
```bash
discoursemap -u https://forum.example.com \
  --safe \
  -o html \
  -f audit_report.html \
  --verbose
```

### Authenticated Scan with Proxy
```bash
discoursemap -u https://forum.example.com \
  -p http://127.0.0.1:8080 \
  --user-agent "SecurityAudit/2.0" \
  -m auth session admin
```

### Plugin Vulnerability Scan
```bash
discoursemap -u https://forum.example.com \
  -m plugin_detection plugin_bruteforce cve \
  -o json \
  -f plugin_vulnerabilities.json
```

### Production-Safe Scan
```bash
discoursemap -u https://production-forum.com \
  --safe \
  --delay 0.5 \
  -t 5 \
  -m info auth config \
  -o html
```

### Continuous Integration
```bash
discoursemap -u https://staging.forum.com \
  --quick \
  --quiet \
  -o json \
  -f ci_scan_results.json
```

---

## CONFIGURATION FILE

Create a `config.yaml` file for persistent settings:

```yaml
# Target configuration
target:
  url: https://forum.example.com
  timeout: 10
  verify_ssl: true

# Performance settings
performance:
  threads: 20
  delay: 0.05
  
# Module selection
modules:
  enabled:
    - info
    - vuln
    - auth
    - session
    - admin
  
# Output settings
output:
  format: html
  file: scan_report.html
  
# Network settings
network:
  proxy: http://127.0.0.1:8080
  user_agent: "DiscourseMap/2.1.0"
```

**Usage:**
```bash
discoursemap -c config.yaml
```

---

## REPORT FORMATS

### JSON Report
Machine-readable format for integration with other tools
```bash
discoursemap -u URL -o json -f report.json
```

### HTML Report
Professional styled report with charts and visualizations
```bash
discoursemap -u URL -o html -f report.html
```

### CSV Report
Spreadsheet-compatible format for data analysis
```bash
discoursemap -u URL -o csv -f report.csv
```

---

## EXIT STATUS

**0** - Scan completed successfully  
**1** - Error occurred during scanning  
**2** - Invalid arguments or configuration

---

## SECURITY CONSIDERATIONS

⚠️ **IMPORTANT:** This tool should only be used on authorized systems.

### Best Practices

1. **Always obtain written authorization** before scanning
2. **Respect rate limits** - use `--safe` mode for production
3. **Avoid peak hours** when scanning production systems
4. **Review reports** before sharing with stakeholders
5. **Store results securely** - reports may contain sensitive information

### Rate Limiting Recommendations

| Environment | Preset | Threads | Delay | Use Case |
|------------|--------|---------|-------|----------|
| Development | `--fast` | 50 | 0.01s | Local testing |
| Staging | `--balanced` | 20 | 0.05s | Pre-production |
| Production | `--safe` | 5-10 | 0.1-0.5s | Live systems |

---

## INTEGRATIONS

### Burp Suite Integration
```bash
discoursemap -u https://target.com -p http://127.0.0.1:8080
```

### CI/CD Pipeline
```bash
#!/bin/bash
discoursemap -u $TARGET_URL --quick --quiet -o json -f results.json
if [ $? -eq 0 ]; then
  echo "Security scan passed"
else
  echo "Security issues detected"
  exit 1
fi
```

### Slack Notifications
Configure webhook in `config.yaml`:
```yaml
integrations:
  slack:
    webhook_url: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
    enabled: true
```

---

## TROUBLESHOOTING

### Common Issues

**"Target is not a Discourse forum"**
- Verify the URL is correct
- Check if the site is actually using Discourse
- Try with `--skip-ssl-verify` if SSL issues

**"Connection timeout"**
- Increase timeout: `--timeout 30`
- Check network connectivity
- Verify proxy settings

**"Rate limited"**
- Increase delay: `--delay 1`
- Use `--safe` preset
- Reduce threads: `-t 5`

**"ModuleNotFoundError"**
- Reinstall: `pip3 install -e .`
- Check Python version: `python3 --version` (requires 3.8+)

---

## FILES

**~/.discoursemap/config.yaml** - Default configuration file  
**./config.yaml** - Project-specific configuration  
**./partial_scan_*.json** - Resume files for interrupted scans

---

## ENVIRONMENT VARIABLES

**DISCOURSEMAP_PROXY** - Default proxy server  
**DISCOURSEMAP_THREADS** - Default thread count  
**DISCOURSEMAP_TIMEOUT** - Default request timeout

---

## SEE ALSO

- GitHub: https://github.com/ibrahmsql/discoursemap
- Documentation: https://github.com/ibrahmsql/discoursemap#readme
- Discourse Security: https://meta.discourse.org/c/security

---

## BUGS

Report bugs at: https://github.com/ibrahmsql/discoursemap/issues

---

## AUTHOR

Written by ibrahimsql (ibrahimsql@proton.me)

---

## COPYRIGHT

Copyright © 2025 ibrahimsql. MIT License.

This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

---

## VERSION

DiscourseMap v2.1.0 (January 2025)
