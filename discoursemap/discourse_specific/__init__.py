#!/usr/bin/env python3
"""Discourse-Specific Modules

This package contains modules specifically designed for Discourse forum security testing.
These modules test Discourse-specific features, APIs, and configurations.
"""

from .rate_limiting import RateLimitModule
from .session import SessionSecurityModule
from .admin import AdminPanelModule
from .webhooks import WebhookSecurityModule
from .email import EmailSecurityModule
from .search import SearchSecurityModule
from .cache import CacheSecurityModule
from .badges import BadgeSecurityModule
from .trust_levels import TrustLevelSecurityModule
from .categories import CategorySecurityModule

__all__ = [
    'RateLimitModule',
    'SessionSecurityModule',
    'AdminPanelModule',
    'WebhookSecurityModule',
    'EmailSecurityModule',
    'SearchSecurityModule',
    'CacheSecurityModule',
    'BadgeSecurityModule',
    'TrustLevelSecurityModule',
    'CategorySecurityModule'
]
