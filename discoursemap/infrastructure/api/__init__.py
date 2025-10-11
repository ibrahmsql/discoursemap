#!/usr/bin/env python3
"""API Security Module

This package contains API security scanning and testing tools.
"""

from .api_module import APIModule

__all__ = ['APIModule']

# Alias for backwards compatibility
APISecurityModule = APIModule
