#!/usr/bin/env python3
"""
DiscourseMap - Discourse Security Scanner

A comprehensive security scanning tool for Discourse forum platforms.
Similar to sqlmap, Metasploit, and wpscan for Discourse-specific vulnerabilities.
"""

__version__ = "1.0.0"
__author__ = "ibrahimsql"
__description__ = "Comprehensive security scanner for Discourse forums"
__url__ = "https://github.com/ibrahmsql/discoursemap"

from .modules import (
    DiscourseScanner, Reporter, InfoModule, VulnerabilityModule,
    EndpointModule, UserModule, CVEExploitModule
)

__all__ = [
    'DiscourseScanner', 'Reporter', 'InfoModule', 'VulnerabilityModule',
    'EndpointModule', 'UserModule', 'CVEExploitModule'
]