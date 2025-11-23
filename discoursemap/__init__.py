#!/usr/bin/env python3
"""
DiscourseMap - Discourse Forum Security Scanner

A comprehensive security scanner for Discourse forums.
Written for security professionals and forum administrators.

Author: ibrahimsql
Email: ibrahimsql@proton.me
GitHub: https://github.com/ibrahmsql/discoursemap

New in v2.1:
- Advanced modular architecture with 50+ specialized modules
- Rate limiting testing with bypass techniques
- Comprehensive security testing (injection, file upload, auth)
- Performance monitoring and load testing
- Health checking and uptime monitoring
- Multiple report formats (JSON, HTML, CSV, XML)
- External integrations (Slack, Webhooks)
- Advanced configuration management
- Network utilities and data processing tools
"""

__version__ = "2.1.0"
__author__ = "ibrahimsql"
__email__ = "ibrahimsql@proton.me"
__description__ = "Discourse forum security scanner. Written for security professionals and forum administrators."

# Core components
from .core import DiscourseScanner, Reporter, Banner

# Main utility functions
from .lib.discourse_utils import validate_url, clean_url

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
    'clean_url',
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