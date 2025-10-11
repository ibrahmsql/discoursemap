# DiscourseMap Project Structure

This document describes the reorganized modular structure of the DiscourseMap project.

## Directory Structure

```
discoursemap/
├── analysis/              # Analysis and reconnaissance modules
│   ├── endpoints/         # Endpoint discovery and enumeration
│   ├── files/            # File integrity and malicious pattern detection
│   ├── info/             # Information gathering
│   ├── passive/          # Passive scanning
│   └── plugins/          # Plugin detection, bruteforce, and analysis
│
├── compliance/           # Compliance checking and reporting
│
├── core/                 # Core scanner components
│   ├── banner.py         # ASCII banner
│   ├── reporter.py       # Report generation
│   └── scanner.py        # Main scanner engine
│
├── infrastructure/       # Infrastructure security modules
│   ├── api/             # API security testing
│   ├── config/          # Configuration security
│   ├── database/        # Database security
│   └── network/         # Network security
│
├── lib/                  # Core utility libraries
│   ├── config_manager.py # Configuration management
│   ├── discourse_utils.py # Discourse-specific utilities
│   └── http_client.py    # HTTP client with retry logic
│
├── modules/              # Legacy compatibility layer (deprecated)
│
├── security/             # Security testing modules
│   ├── auth/            # Authentication testing
│   ├── crypto/          # Cryptography analysis
│   ├── exploits/        # CVE exploits
│   └── vulnerabilities/ # Vulnerability detection
│
└── utilities/            # Utility modules
    ├── user_agents.py   # User agent strings
    ├── user_module.py   # User enumeration
    └── waf_bypass_module.py # WAF bypass techniques
```

## Module Categories

### 1. Core Modules (`core/`)
Essential components for the scanner operation:
- **Scanner**: Main scanning engine with thread management
- **Reporter**: Multi-format report generation (HTML, JSON, XML, CSV)
- **Banner**: Application branding and version display

### 2. Analysis Modules (`analysis/`)
Reconnaissance and information gathering:
- **Endpoints**: API endpoint discovery, backup file detection, directory enumeration
- **Files**: Asset, core, theme, and plugin file checking
- **Info**: Version detection, configuration discovery, metadata extraction
- **Passive**: Non-intrusive scanning and analysis
- **Plugins**: Plugin detection, enumeration, and vulnerability checking

### 3. Security Modules (`security/`)
Active security testing:
- **Auth**: Authentication bypass, session management testing
- **Crypto**: SSL/TLS analysis, encryption strength testing
- **Exploits**: CVE exploitation modules
- **Vulnerabilities**: Known vulnerability detection and plugin vuln DB

### 4. Infrastructure Modules (`infrastructure/`)
System infrastructure testing:
- **API**: REST API security, rate limiting, authentication
- **Config**: Configuration security and misconfiguration detection
- **Database**: Database security testing
- **Network**: Network-level security checks

### 5. Compliance Modules (`compliance/`)
Standards and compliance checking:
- GDPR compliance
- Security best practices
- Privacy policy verification

### 6. Utilities (`utilities/`)
Helper modules:
- User agent rotation
- User enumeration
- WAF detection and bypass

### 7. Library (`lib/`)
Core utility functions:
- HTTP client with connection pooling
- Discourse-specific utilities
- Configuration management

## Import Examples

### New Import Style (Recommended)
```python
# Core components
from discoursemap.core import DiscourseScanner, Reporter, Banner

# Analysis modules
from discoursemap.analysis.info import InfoModule
from discoursemap.analysis.endpoints import EndpointModule
from discoursemap.analysis.plugins import PluginModule

# Security modules
from discoursemap.security.vulnerabilities import VulnerabilityModule
from discoursemap.security.exploits import CVEExploitModule

# Infrastructure modules
from discoursemap.infrastructure.api import APISecurityModule
from discoursemap.infrastructure.network import NetworkModule

# Utilities
from discoursemap.lib.discourse_utils import validate_url
from discoursemap.lib.http_client import HTTPClient
```

### Legacy Import Style (Still Works)
```python
# Backwards compatible imports through modules/__init__.py
from discoursemap.modules import DiscourseScanner, Reporter
from discoursemap.modules import InfoModule, VulnerabilityModule
```

## Benefits of New Structure

1. **Modular Organization**: Related functionality grouped together
2. **Clear Separation of Concerns**: Each category has a specific purpose
3. **Easier Navigation**: Find modules by their functional domain
4. **Better Scalability**: Easy to add new modules within existing categories
5. **Improved Maintainability**: Changes isolated to specific functional areas
6. **IDE-Friendly**: Better autocomplete and code navigation support

## Migration Notes

- The old `modules/` directory is kept for backwards compatibility
- All imports are redirected through `modules/__init__.py`
- New code should use the new import paths
- Legacy code will continue to work without modifications

## Version History

- **v2.0**: Complete structural reorganization into modular hierarchy
- **v1.0**: Original flat module structure
