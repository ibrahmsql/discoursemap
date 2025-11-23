# DiscourseMap - Quick Start Guide

## Installation

```bash
# Clone repository
git clone https://github.com/ibrahmsql/discoursemap.git
cd discoursemap

# Install with pip3
pip3 install -e .

# Verify installation
discoursemap --help
```

## Quick Examples

### 1. Basic Scan
```bash
discoursemap -u https://forum.example.com
```

### 2. Quick Security Check
```bash
discoursemap -u https://forum.example.com --quick
```

### 3. Specific Modules
```bash
discoursemap -u https://forum.example.com -m info vuln auth
```

### 4. Generate HTML Report
```bash
discoursemap -u https://forum.example.com -o html -f report.html
```

### 5. Safe Production Scan
```bash
discoursemap -u https://production.com --safe --sync
```

### 6. With Proxy (Burp Suite)
```bash
discoursemap -u https://target.com -p http://127.0.0.1:8080
```

## Common Options

| Option | Description | Example |
|--------|-------------|---------|
| `-u URL` | Target URL (required) | `-u https://forum.com` |
| `-m MODULES` | Select modules | `-m info vuln` |
| `-o FORMAT` | Output format | `-o html` |
| `-t THREADS` | Thread count | `-t 10` |
| `--delay SECONDS` | Request delay | `--delay 0.1` |
| `--sync` | Synchronous mode | `--sync` |
| `--safe` | Safe preset | `--safe` |
| `--quick` | Quick scan | `--quick` |
| `-v` | Verbose output | `-v` |

## Available Modules

**Info & Discovery:**
- `info` - Site information
- `endpoint` - Endpoint discovery
- `user` - User enumeration

**Security Testing:**
- `vuln` - Vulnerability scan
- `auth` - Authentication
- `session` - Session security
- `cve` - CVE exploits

**Discourse-Specific:**
- `admin` - Admin panel
- `plugin_detection` - Plugins
- `rate_limit` - Rate limiting
- `badge` - Badge system
- `category` - Categories

## Performance Presets

### Fast (Development)
```bash
discoursemap -u URL --fast
# 50 threads, 0.01s delay
```

### Balanced (Default)
```bash
discoursemap -u URL --balanced
# 20 threads, 0.05s delay
```

### Safe (Production)
```bash
discoursemap -u URL --safe
# 10 threads, 0.1s delay
```

## Output Formats

### JSON (automation)
```bash
discoursemap -u URL -o json -f results.json
```

###HTML (reports)
```bash
discoursemap -u URL -o html -f report.html
```

### CSV (analysis)
```bash
discoursemap -u URL -o csv -f data.csv
```

## For More Help

See the full manual:
```bash
cat MANUAL.md
# or
man discoursemap  # if installed system-wide
```

GitHub: https://github.com/ibrahmsql/discoursemap
