#!/usr/bin/env python3
"""Discourse Security Scanner Modules (Legacy)

This package is kept for backwards compatibility.
New imports should use the reorganized structure.
"""

__version__ = "2.0.0"
__author__ = "ibrahimsql"

# Import from new structure for backwards compatibility
from ..lib.discourse_utils import (
    validate_url, normalize_url, extract_csrf_token, is_discourse_forum
)
from ..core.scanner import DiscourseScanner
from ..core.reporter import Reporter
from ..analysis.info import InfoModule
from ..security.vulnerabilities import VulnerabilityModule
from ..analysis.endpoints import EndpointModule
from ..utilities import UserModule
from ..security.exploits import CVEExploitModule
from ..core.banner import Banner

__all__ = [
    'validate_url', 'normalize_url', 'extract_csrf_token', 'is_discourse_forum',
    'DiscourseScanner', 'Reporter', 'InfoModule', 'VulnerabilityModule',
    'EndpointModule', 'UserModule', 'CVEExploitModule', 'Banner'
]
