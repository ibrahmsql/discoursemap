#!/usr/bin/env python3
"""Discourse Security Scanner Modules

This package contains all security scanning modules for Discourse forums.
Includes vulnerability testing, endpoint discovery, user enumeration, and more.
"""

__version__ = "1.0.0"
__author__ = "ibrahimsql"

from .utils import (
    validate_url, normalize_url, make_request, extract_csrf_token,
    extract_discourse_version, generate_payloads, random_user_agent,
    format_time, print_progress, save_json, load_json, is_discourse_site, clean_url
)
from .scanner import DiscourseScanner
from .reporter import Reporter
from .info_module import InfoModule
from .vulnerability_module import VulnerabilityModule
from .endpoint_module import EndpointModule
from .user_module import UserModule
from .cve_exploit_module import CVEExploitModule
from .banner import Banner
__all__ = [
    'validate_url', 'normalize_url', 'make_request', 'extract_csrf_token',
    'extract_discourse_version', 'generate_payloads', 'random_user_agent',
    'format_time', 'print_progress', 'save_json', 'load_json', 'is_discourse_site',
    'clean_url', 'DiscourseScanner', 'Reporter', 'InfoModule', 'VulnerabilityModule',
    'EndpointModule', 'UserModule', 'CVEExploitModule'
]
