#!/usr/bin/env python3
"""
Scanner Module

Modular scanner components for Discourse security assessment.
"""

from .base_scanner import BaseScanner
from .module_manager import ModuleManager
from .async_scanner import AsyncScanner

# Alias for backward compatibility
DiscourseScanner = BaseScanner

__all__ = ['BaseScanner', 'ModuleManager', 'AsyncScanner', 'DiscourseScanner']