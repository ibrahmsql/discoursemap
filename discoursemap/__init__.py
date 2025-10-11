#!/usr/bin/env python3
"""
DiscourseMap - Discourse Forum Security Scanner

A comprehensive security scanner for Discourse forums.
Written for security professionals and forum administrators.

Author: ibrahimsql
Email: ibrahimsql@proton.me
GitHub: https://github.com/ibrahmsql/discoursemap

New in v2.0:
- Completely reorganized modular structure
- Categorized modules by functionality
- Improved maintainability and scalability
- Better IDE support and code navigation
- Added 20+ Discourse-specific security modules
- Enhanced testing and validation capabilities
- Comprehensive security coverage
"""

__version__ = "2.0.4"
__author__ = "ibrahimsql"
__email__ = "ibrahimsql@proton.me"
__description__ = "Discourse forum security scanner. Written for security professionals and forum administrators."

# Core components
from .core import DiscourseScanner, Reporter, Banner

# Main utility functions
from .lib.discourse_utils import validate_url, normalize_url

# Discourse-specific modules
from .discourse_specific import (
    RateLimitModule,
    SessionSecurityModule,
    AdminPanelModule,
    WebhookSecurityModule,
    EmailSecurityModule,
    SearchSecurityModule,
    CacheSecurityModule
)

# Testing and validation
from .testing.validators import DiscourseValidator

__all__ = [
    # Core
    'DiscourseScanner',
    'Reporter', 
    'Banner',
    # Utils
    'validate_url',
    'normalize_url',
    # Discourse-specific
    'RateLimitModule',
    'SessionSecurityModule',
    'AdminPanelModule',
    'WebhookSecurityModule',
    'EmailSecurityModule',
    'SearchSecurityModule',
    'CacheSecurityModule',
    # Testing
    'DiscourseValidator',
    # Metadata
    '__version__',
    '__author__',
]