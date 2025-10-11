#!/usr/bin/env python3
"""
Malicious Pattern Checker - Utility for detecting malicious content patterns

Provides pattern matching for suspicious and malicious content detection
"""

import re

class MaliciousPatternChecker:
    """Utility class for detecting malicious patterns in content"""

    def __init__(self):
        """
        Initialize MaliciousPatternChecker with compiled detection pattern lists.
        
        Sets three attributes used for content scanning:
        - malicious_patterns: list of regular-expression strings targeting common server-side and shell-injection constructs (e.g., eval, exec, file operations, base64/gzinflate, superglobals, and common shell binaries).
        - suspicious_js_patterns: list of regular-expression strings targeting JavaScript constructs that often appear in injected or dynamic script payloads (e.g., document.write, innerHTML assignments, eval, timers, XHR/fetch, location/cookie/storage access).
        - suspicious_js_indicators: list of simple JavaScript substring indicators used for lightweight heuristic counting of suspicious snippets.
        
        These attributes are plain lists of strings intended for use with case-insensitive regex searches or substring checks elsewhere in the class.
        """
        self.malicious_patterns = [
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'shell_exec\s*\(',
            r'passthru\s*\(',
            r'base64_decode\s*\(',
            r'gzinflate\s*\(',
            r'str_rot13\s*\(',
            r'\$_GET\s*\[',
            r'\$_POST\s*\[',
            r'\$_REQUEST\s*\[',
            r'file_get_contents\s*\(',
            r'fopen\s*\(',
            r'fwrite\s*\(',
            r'curl_exec\s*\(',
            r'wget\s+',
            r'nc\s+-',
            r'/bin/sh',
            r'/bin/bash'
        ]

        self.suspicious_js_patterns = [
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'XMLHttpRequest\s*\(',
            r'fetch\s*\(',
            r'window\.location',
            r'document\.cookie',
            r'localStorage',
            r'sessionStorage'
        ]

        self.suspicious_js_indicators = [
            'eval(',
            'document.write(',
            'unescape(',
            'String.fromCharCode(',
            'atob(',
            'btoa(',
            'setTimeout(',
            'setInterval('
        ]

    def check_malicious_patterns(self, content):
        """
        Scan the given text for any configured malicious regex patterns.
        
        Parameters:
        	content (str): Text to scan for malicious or risky patterns.
        
        Returns:
        	found_patterns (list[str]): List of regex patterns from `self.malicious_patterns` that matched the content.
        """
        found_patterns = []
        for pattern in self.malicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns.append(pattern)
        return found_patterns

    def check_suspicious_plugin_content(self, content):
        """
        Check plugin content for suspicious JavaScript patterns.
        
        Parameters:
            content (str): Text to scan for suspicious JavaScript patterns.
        
        Returns:
            list[str]: Regex patterns from `suspicious_js_patterns` that matched the content.
        """
        found_patterns = []
        for pattern in self.suspicious_js_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns.append(pattern)
        return found_patterns

    def has_suspicious_js_content(self, content):
        """
        Determine whether JavaScript content contains suspicious patterns based on known indicators.
        
        Parameters:
            content (str): Text to analyze for presence of suspicious JavaScript indicator substrings.
        
        Returns:
            bool: `True` if more than three indicators are present, `False` otherwise.
        """
        count = sum(1 for indicator in self.suspicious_js_indicators if indicator in content)
        return count > 3