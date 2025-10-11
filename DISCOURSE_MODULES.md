# Discourse-Specific Security Modules

This document describes all Discourse-specific security testing modules added to DiscourseMap v2.0.

## Overview

DiscourseMap v2.0 includes **comprehensive Discourse-specific testing modules** that provide deep security analysis of Discourse forum platforms. These modules are specifically designed to test Discourse features, APIs, and configurations.

---

## Module Categories

### 1. Discourse-Specific Modules (`discourse_specific/`)

#### Rate Limiting Module (`rate_limiting/`)
**Purpose**: Tests and analyzes rate limiting mechanisms

**Features**:
- Login endpoint rate limit testing
- API endpoint rate limit detection
- Search rate limit analysis
- Topic/post creation rate limits
- Rate limit header inspection
- Bypass technique testing (X-Forwarded-For, User-Agent rotation)

**Security Checks**:
- ✓ Unprotected endpoints detection
- ✓ Rate limit threshold analysis
- ✓ Bypass vulnerability testing
- ✓ Security recommendations

**Usage**:
```python
from discoursemap.discourse_specific import RateLimitModule

module = RateLimitModule(target_url, verbose=True)
results = module.scan()
module.print_results()
```

---

#### Session Security Module (`session/`)
**Purpose**: Tests session management and security

**Features**:
- Cookie security attribute testing (Secure, HttpOnly, SameSite)
- CSRF protection verification
- Session fixation testing
- Session timeout configuration
- Concurrent session analysis
- Session regeneration validation

**Security Checks**:
- ✓ Insecure cookie detection
- ✓ Missing CSRF protection
- ✓ Session fixation vulnerabilities
- ✓ Secure transmission validation

**Usage**:
```python
from discoursemap.discourse_specific import SessionSecurityModule

module = SessionSecurityModule(target_url, verbose=True)
results = module.scan()
module.print_results()
```

---

#### Admin Panel Module (`admin/`)
**Purpose**: Tests admin panel security and access controls

**Features**:
- Admin endpoint discovery (20+ endpoints)
- Access control testing
- Admin API security
- Privilege escalation testing
- Default credential checking
- Admin log exposure testing

**Tested Endpoints**:
- `/admin/dashboard`
- `/admin/users`
- `/admin/site_settings`
- `/admin/plugins`
- `/admin/backups`
- `/admin/logs`
- `/admin/web_hooks`
- `/admin/api`
- And 12+ more...

**Security Checks**:
- ✓ Unauthorized admin access
- ✓ Exposed admin information
- ✓ Default credentials
- ✓ Privilege escalation vectors

---

#### Webhook Security Module (`webhooks/`)
**Purpose**: Tests webhook configuration and security

**Features**:
- Webhook endpoint discovery
- Signature validation testing (HMAC-SHA256)
- Replay attack protection
- Webhook configuration exposure

**Security Checks**:
- ✓ Exposed webhook configuration
- ✓ Signature validation bypass
- ✓ Replay attack protection
- ✓ HTTPS enforcement

---

#### Email Security Module (`email/`)
**Purpose**: Tests email security configuration

**Features**:
- SPF record validation
- DKIM record detection
- DMARC policy checking
- Email enumeration testing
- Email bounce handling
- Email injection testing

**DNS Checks**:
- ✓ SPF record existence and policy
- ✓ DKIM selector detection
- ✓ DMARC policy validation
- ✓ Weak policy detection

**Usage**:
```python
from discoursemap.discourse_specific import EmailSecurityModule

module = EmailSecurityModule(target_url, verbose=True)
results = module.scan()
module.print_results()
```

---

#### Search Security Module (`search/`)
**Purpose**: Tests search functionality security

**Features**:
- Search endpoint testing
- Injection vulnerability testing (SQL, XSS, SSTI)
- Information disclosure via search
- DoS vector testing
- Search filter bypass

**Test Payloads**:
- SQL injection patterns
- XSS payloads
- Template injection
- Path traversal
- DoS patterns (wildcards, long queries)

**Security Checks**:
- ✓ Search injection vulnerabilities
- ✓ Sensitive information exposure
- ✓ DoS potential
- ✓ Access control bypass

---

#### Cache Security Module (`cache/`)
**Purpose**: Tests caching mechanisms and CDN

**Features**:
- Cache header analysis
- Cache poisoning testing
- CDN detection (Cloudflare, Fastly, Akamai, AWS CloudFront, Varnish)
- Cache key manipulation

**Tested Headers**:
- Cache-Control
- Pragma
- Expires
- ETag
- X-Cache
- CF-Cache-Status
- X-Varnish

**Security Checks**:
- ✓ Cache poisoning vulnerabilities
- ✓ Public caching of sensitive data
- ✓ CDN security configuration
- ✓ Header injection

---

### 2. Testing & Validation Modules (`testing/`)

#### Discourse Validator (`validators/`)
**Purpose**: Validates if target is a Discourse forum

**Features**:
- Discourse detection via multiple indicators
- Version extraction
- Confidence scoring
- API endpoint validation
- Asset file detection

**Detection Methods**:
- Meta tag analysis
- API endpoint verification (`/site.json`, `/about.json`)
- Discourse-specific headers
- Asset file detection
- Version extraction

**Confidence Levels**:
- 100% - All indicators present
- 80%+ - High confidence
- 60%+ - Medium confidence (threshold)
- <60% - Not Discourse

**Usage**:
```python
from discoursemap.testing.validators import DiscourseValidator

validator = DiscourseValidator(target_url, verbose=True)
results = validator.validate()

if results['is_discourse']:
    print(f"Discourse {results['version']} detected!")
    print(f"Confidence: {results['confidence']}%")
```

---

## Module Integration

### Importing Modules

**Individual Modules**:
```python
from discoursemap.discourse_specific import (
    RateLimitModule,
    SessionSecurityModule,
    AdminPanelModule,
    WebhookSecurityModule,
    EmailSecurityModule,
    SearchSecurityModule,
    CacheSecurityModule
)
```

**All at Once**:
```python
from discoursemap import (
    RateLimitModule,
    SessionSecurityModule,
    AdminPanelModule,
    WebhookSecurityModule,
    EmailSecurityModule,
    SearchSecurityModule,
    CacheSecurityModule,
    DiscourseValidator
)
```

---

## Complete Testing Workflow

### Step 1: Validate Target
```python
from discoursemap import DiscourseValidator

validator = DiscourseValidator("https://forum.example.com")
results = validator.validate()

if not results['is_discourse']:
    print("Error: Not a Discourse forum!")
    exit(1)

print(f"✓ Discourse {results['version']} detected!")
```

### Step 2: Run Discourse-Specific Tests
```python
from discoursemap.discourse_specific import (
    RateLimitModule,
    SessionSecurityModule,
    AdminPanelModule,
    EmailSecurityModule
)

target = "https://forum.example.com"

# Rate limiting test
rate_limit = RateLimitModule(target, verbose=True)
rate_results = rate_limit.scan()

# Session security test
session = SessionSecurityModule(target, verbose=True)
session_results = session.scan()

# Admin panel test
admin = AdminPanelModule(target, verbose=True)
admin_results = admin.scan()

# Email security test
email = EmailSecurityModule(target, verbose=True)
email_results = email.scan()

# Print all results
rate_limit.print_results()
session.print_results()
admin.print_results()
email.print_results()
```

### Step 3: Generate Report
```python
from discoursemap import Reporter

reporter = Reporter(
    target_url=target,
    all_results={
        'rate_limiting': rate_results,
        'session': session_results,
        'admin': admin_results,
        'email': email_results
    }
)

# Generate reports
reporter.generate_html_report('discourse_security_report.html')
reporter.generate_json_report('discourse_security_report.json')
```

---

## Security Coverage Matrix

| Security Area | Module | Coverage |
|--------------|---------|----------|
| **Rate Limiting** | RateLimitModule | ✓✓✓✓ |
| **Session Management** | SessionSecurityModule | ✓✓✓✓ |
| **Access Control** | AdminPanelModule | ✓✓✓✓ |
| **Webhook Security** | WebhookSecurityModule | ✓✓✓ |
| **Email Security** | EmailSecurityModule | ✓✓✓✓ |
| **Search Security** | SearchSecurityModule | ✓✓✓✓ |
| **Cache Security** | CacheSecurityModule | ✓✓✓ |
| **Validation** | DiscourseValidator | ✓✓✓✓ |

**Legend**: ✓✓✓✓ (Comprehensive) | ✓✓✓ (Good) | ✓✓ (Basic)

---

## Vulnerability Detection

### Critical Severity
- Exposed admin panel without authentication
- Missing HTTPS enforcement
- Default admin credentials
- Privilege escalation vulnerabilities
- Session fixation

### High Severity
- Missing rate limiting on login
- No CSRF protection
- Exposed admin API
- SPF record misconfiguration
- Search injection vulnerabilities
- Cache poisoning

### Medium Severity
- Insecure cookie attributes
- Missing DKIM/DMARC
- Weak rate limiting
- Information disclosure via search
- Exposed webhook configuration

### Low Severity
- Missing cache headers
- Weak DMARC policy
- Reflected input in search

---

## Best Practices

### 1. Always Validate First
```python
validator = DiscourseValidator(target_url)
if not validator.validate()['is_discourse']:
    raise ValueError("Target is not a Discourse forum")
```

### 2. Use Verbose Mode for Debugging
```python
module = RateLimitModule(target_url, verbose=True)
```

### 3. Test with Session Sharing
```python
import requests

session = requests.Session()
session.headers.update({'Authorization': 'Bearer YOUR_TOKEN'})

rate_limit = RateLimitModule(target_url, session=session)
admin = AdminPanelModule(target_url, session=session)
```

### 4. Handle Results Programmatically
```python
results = module.scan()

if results['vulnerabilities']:
    print(f"Found {len(results['vulnerabilities'])} vulnerabilities!")
    for vuln in results['vulnerabilities']:
        if vuln['severity'] == 'CRITICAL':
            alert_security_team(vuln)
```

---

## Future Enhancements

### Planned Modules
- [ ] Discourse Plugin Vulnerability Scanner
- [ ] Two-Factor Authentication Testing
- [ ] SSO/OAuth Integration Testing
- [ ] Backup Security Analysis
- [ ] Job Queue Security
- [ ] CDN Configuration Testing
- [ ] Load Testing & Performance
- [ ] Fuzzing Module

### Planned Features
- Automated exploitation
- Report generation improvements
- CI/CD integration
- Docker scanning support
- Multi-target scanning
- Scheduled scans

---

## Module Statistics

- **Total Modules**: 8 (7 security + 1 validation)
- **Total Security Checks**: 100+
- **Tested Endpoints**: 50+
- **Injection Payloads**: 30+
- **DNS Checks**: 3 (SPF, DKIM, DMARC)
- **CDN Detection**: 5 providers
- **Lines of Code**: 2,500+

---

## Contributing

To add a new Discourse-specific module:

1. Create module directory: `discoursemap/discourse_specific/new_module/`
2. Create `__init__.py` and `new_module.py`
3. Implement scan() method returning results dict
4. Add to `discourse_specific/__init__.py`
5. Update this documentation
6. Add tests

---

**Version**: 2.0.0  
**Last Updated**: 2025-10-11  
**Author**: ibrahimsql
