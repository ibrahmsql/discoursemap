#!/usr/bin/env python3
"""
Malicious Pattern Checker - Utility for detecting malicious content patterns

Provides pattern matching for suspicious and malicious content detection
"""

import re

class MaliciousPatternChecker:
    """Utility class for detecting malicious patterns in content"""
    
    def __init__(self):
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
        """Check content for malicious patterns"""
        found_patterns = []
        for pattern in self.malicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns.append(pattern)
        return found_patterns
    
    def check_suspicious_plugin_content(self, content):
        """Check plugin content for suspicious patterns"""
        found_patterns = []
        for pattern in self.suspicious_js_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns.append(pattern)
        return found_patterns
    
    def has_suspicious_js_content(self, content):
        """Check if JavaScript content has suspicious characteristics"""
        count = sum(1 for indicator in self.suspicious_js_indicators if indicator in content)
        return count > 3