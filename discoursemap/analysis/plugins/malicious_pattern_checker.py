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
        Initialize pattern lists used to detect malicious and suspicious JavaScript content.
        
        Creates and populates three attributes:
        - `malicious_patterns`: regular expression strings for broad malicious constructs (e.g., code execution, file/network access, shell usage).
        - `suspicious_js_patterns`: regular expression strings for suspicious JavaScript constructs (e.g., dynamic document modification, remote requests, access to location/cookies/storage).
        - `suspicious_js_indicators`: short string indicators used for heuristic detection of suspicious JavaScript behavior.
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
        Identify which configured malicious regex patterns appear in the given content.
        
        Parameters:
            content (str): Text to scan for malicious patterns.
        
        Returns:
            matched_patterns (list[str]): List of regex pattern strings from `self.malicious_patterns` that matched the content (case-insensitive).
        """
        found_patterns = []
        for pattern in self.malicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns.append(pattern)
        return found_patterns

    def check_suspicious_plugin_content(self, content):
        """
        Scan plugin content for known suspicious JavaScript patterns.
        
        Parameters:
            content (str): Text content of the plugin or source to inspect.
        
        Returns:
            list: Pattern strings from `self.suspicious_js_patterns` that matched content (case-insensitive).
        """
        found_patterns = []
        for pattern in self.suspicious_js_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns.append(pattern)
        return found_patterns

    def has_suspicious_js_content(self, content):
        """
        Determine whether JavaScript content contains multiple common suspicious indicators.
        
        Parameters:
            content (str): The JavaScript or text content to scan for suspicious indicators.
        
        Returns:
            True if more than three suspicious indicators are present in the content, False otherwise.
        """
        count = sum(1 for indicator in self.suspicious_js_indicators if indicator in content)
        return count > 3