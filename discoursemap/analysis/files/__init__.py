#!/usr/bin/env python3
"""File Analysis Modules

This package contains file integrity checking, suspicious file scanning,
and malicious pattern detection tools.
"""

from .file_integrity_module import FileIntegrityModule
from .asset_file_checker import AssetFileChecker
from .core_file_checker import CoreFileChecker
from .theme_file_checker import ThemeFileChecker
from .suspicious_file_scanner import SuspiciousFileScanner
from .malicious_pattern_checker import MaliciousPatternChecker

__all__ = [
    'FileIntegrityModule',
    'AssetFileChecker',
    'CoreFileChecker',
    'ThemeFileChecker',
    'SuspiciousFileScanner',
    'MaliciousPatternChecker'
]
