#!/usr/bin/env python3
"""
Discourse Security Scanner - Network Security Module

Tests network-level security issues and configurations
"""

import re
import time
import json
import socket
import threading
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import make_request

class NetworkModule:
    """Network security testing module for Discourse forums"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'Network Security Testing',
            'target': scanner.target_url,
            'port_scan': [],
            'service_detection': [],
            'ssl_analysis': [],
            'dns_analysis': [],
            'subdomain_enum': [],
            'cdn_detection': [],
            'load_balancer': [],
            'firewall_detection': [],
            'rate_limiting': [],
            'ddos_protection': []
        }
        self.target_host = urlparse(scanner.target_url).hostname
        
    def run_scan(self):
        """Run complete network security scan"""
        print(f"\n{self.scanner.colors['info']}[*] Starting network security scan...{self.scanner.colors['reset']}")
        
        # Port scanning
        self._port_scan()
        
        # Servis tespiti
        self._service_detection()
        
        # SSL analizi
        self._ssl_analysis()
        
        # DNS analizi
        self._dns_analysis()
        
        # Subdomain numaralandırma
        self._subdomain_enumeration()
        
        # CDN tespiti
        self._cdn_detection()
        
        # Load balancer tespiti
        self._load_balancer_detection()
        
        # Firewall tespiti
        self._firewall_detection()
        
        # Rate limiting testi
        self._rate_limiting_test()
        
        # DDoS koruması testi
        self._ddos_protection_test()
        
        return self.results
    
    def _port_scan(self):
        """Perform port scan on target"""
        print(f"{self.scanner.colors['info']}[*] Performing port scan...{self.scanner.colors['reset']}")
        
        # Common ports to scan
        common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            993,   # IMAPS
            995,   # POP3S
            1433,  # MSSQL
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5984,  # CouchDB
            6379,  # Redis
            8080,  # HTTP Alt
            8443,  # HTTPS Alt
            9200,  # Elasticsearch
            27017, # MongoDB
        ]
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.target_host, port))
                sock.close()
                
                if result == 0:
                    return {
                        'port': port,
                        'status': 'open',
                        'service': self._get_service_name(port)
                    }
            except Exception:
                pass
            return None
        
        # Threaded port scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in common_ports]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results['port_scan'].append(result)
    
    def _get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5984: 'CouchDB',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            9200: 'Elasticsearch',
            27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')
    
    def _service_detection(self):
        """Detect services running on open ports"""
        print(f"{self.scanner.colors['info']}[*] Servis tespiti yapılıyor...{self.scanner.colors['reset']}")
        
        for port_info in self.results['port_scan']:
            port = port_info['port']
            
            try:
                # Banner grabbing
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target_host, port))
                
                # Send HTTP request for web services
                if port in [80, 443, 8080, 8443]:
                    request = f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\n\r\n"
                    sock.send(request.encode())
                
                # Receive banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if banner:
                    service_info = self._analyze_banner(port, banner)
                    if service_info:
                        self.results['service_detection'].append(service_info)
                        
            except Exception:
                pass
    
    def _analyze_banner(self, port, banner):
        """Analyze service banner"""
        service_info = {
            'port': port,
            'banner': banner[:200],  # Limit banner length
            'service': 'Unknown',
            'version': 'Unknown',
            'vulnerabilities': []
        }
        
        # Web server detection
        if 'Server:' in banner:
            server_match = re.search(r'Server:\s*([^\r\n]+)', banner)
            if server_match:
                server = server_match.group(1)
                service_info['service'] = server
                
                # Check for known vulnerable versions
                if 'nginx' in server.lower():
                    version_match = re.search(r'nginx/([\d.]+)', server)
                    if version_match:
                        version = version_match.group(1)
                        service_info['version'] = version
                        service_info['vulnerabilities'] = self._check_nginx_vulns(version)
                
                elif 'apache' in server.lower():
                    version_match = re.search(r'Apache/([\d.]+)', server)
                    if version_match:
                        version = version_match.group(1)
                        service_info['version'] = version
                        service_info['vulnerabilities'] = self._check_apache_vulns(version)
        
        # SSH detection
        elif 'SSH-' in banner:
            ssh_match = re.search(r'SSH-([\d.]+)-([^\r\n]+)', banner)
            if ssh_match:
                version = ssh_match.group(1)
                implementation = ssh_match.group(2)
                service_info['service'] = f'SSH {implementation}'
                service_info['version'] = version
                service_info['vulnerabilities'] = self._check_ssh_vulns(implementation, version)
        
        # FTP detection
        elif 'FTP' in banner:
            service_info['service'] = 'FTP'
            if 'vsftpd' in banner:
                version_match = re.search(r'vsftpd ([\d.]+)', banner)
                if version_match:
                    service_info['version'] = version_match.group(1)
        
        return service_info if service_info['service'] != 'Unknown' else None
    
    def _check_nginx_vulns(self, version):
        """Check for nginx vulnerabilities"""
        vulns = []
        version_parts = [int(x) for x in version.split('.')]
        
        # Example vulnerability checks
        if version_parts < [1, 20, 1]:
            vulns.append({
                'cve': 'CVE-2021-23017',
                'description': 'DNS resolver off-by-one heap write',
                'severity': 'High'
            })
        
        if version_parts < [1, 16, 1]:
            vulns.append({
                'cve': 'CVE-2019-20372',
                'description': 'HTTP request smuggling',
                'severity': 'Medium'
            })
        
        return vulns
    
    def _check_apache_vulns(self, version):
        """Check for Apache vulnerabilities"""
        vulns = []
        version_parts = [int(x) for x in version.split('.')]
        
        # Example vulnerability checks
        if version_parts < [2, 4, 51]:
            vulns.append({
                'cve': 'CVE-2021-44790',
                'description': 'mod_lua buffer overflow',
                'severity': 'High'
            })
        
        if version_parts < [2, 4, 49]:
            vulns.append({
                'cve': 'CVE-2021-26691',
                'description': 'mod_session heap overflow',
                'severity': 'Medium'
            })
        
        return vulns
    
    def _check_ssh_vulns(self, implementation, version):
        """Check for SSH vulnerabilities"""
        vulns = []
        
        if 'OpenSSH' in implementation:
            version_match = re.search(r'([\d.]+)', version)
            if version_match:
                ssh_version = version_match.group(1)
                version_parts = [int(x) for x in ssh_version.split('.')]
                
                if version_parts < [8, 5]:
                    vulns.append({
                        'cve': 'CVE-2021-41617',
                        'description': 'SSH agent forwarding vulnerability',
                        'severity': 'Medium'
                    })
        
        return vulns
    
    def _ssl_analysis(self):
        """Analyze SSL/TLS configuration"""
        print(f"{self.scanner.colors['info']}[*] SSL/TLS analizi yapılıyor...{self.scanner.colors['reset']}")
        
        try:
            import ssl
            
            # Test different SSL/TLS versions
            ssl_versions = {
                'SSLv2': ssl.PROTOCOL_SSLv23,  # Will be rejected by modern systems
                'SSLv3': ssl.PROTOCOL_SSLv23,
                'TLSv1.0': ssl.PROTOCOL_TLSv1,
                'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
                'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            }
            
            # Add TLSv1.3 if available
            if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
                ssl_versions['TLSv1.3'] = ssl.PROTOCOL_TLSv1_3
            
            supported_versions = []
            
            for version_name, protocol in ssl_versions.items():
                try:
                    context = ssl.SSLContext(protocol)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((self.target_host, 443), timeout=10) as sock:
                        with context.wrap_socket(sock) as ssock:
                            supported_versions.append(version_name)
                            
                            # Get cipher info for first successful connection
                            if not self.results['ssl_analysis']:
                                cipher = ssock.cipher()
                                cert = ssock.getpeercert()
                                
                                self.results['ssl_analysis'].append({
                                    'cipher_suite': cipher[0] if cipher else 'Unknown',
                                    'protocol_version': cipher[1] if cipher else 'Unknown',
                                    'key_length': cipher[2] if cipher else 'Unknown',
                                    'certificate': self._analyze_certificate(cert)
                                })
                except Exception:
                    pass
            
            # Check for weak SSL versions
            weak_versions = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
            for weak_version in weak_versions:
                if weak_version in supported_versions:
                    self.results['ssl_analysis'].append({
                        'vulnerability': f'Weak SSL/TLS version supported: {weak_version}',
                        'severity': 'High' if weak_version in ['SSLv2', 'SSLv3'] else 'Medium'
                    })
                    
        except ImportError:
            self.results['ssl_analysis'].append({
                'error': 'SSL module not available for detailed analysis'
            })
    
    def _analyze_certificate(self, cert):
        """Analyze SSL certificate"""
        if not cert:
            return {'error': 'No certificate information available'}
        
        cert_info = {
            'subject': dict(x[0] for x in cert.get('subject', [])),
            'issuer': dict(x[0] for x in cert.get('issuer', [])),
            'version': cert.get('version'),
            'serial_number': cert.get('serialNumber'),
            'not_before': cert.get('notBefore'),
            'not_after': cert.get('notAfter'),
            'signature_algorithm': cert.get('signatureAlgorithm')
        }
        
        # Check for weak signature algorithms
        weak_algorithms = ['md5', 'sha1']
        if cert_info['signature_algorithm']:
            for weak_alg in weak_algorithms:
                if weak_alg in cert_info['signature_algorithm'].lower():
                    cert_info['vulnerability'] = f'Weak signature algorithm: {cert_info["signature_algorithm"]}'
        
        return cert_info
    
    def _dns_analysis(self):
        """Analyze DNS configuration"""
        print(f"{self.scanner.colors['info']}[*] DNS analizi yapılıyor...{self.scanner.colors['reset']}")
        
        try:
            import dns.resolver
            import dns.reversename
            
            # DNS record types to query
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.target_host, record_type)
                    records = [str(answer) for answer in answers]
                    
                    self.results['dns_analysis'].append({
                        'record_type': record_type,
                        'records': records
                    })
                    
                    # Analyze specific record types
                    if record_type == 'TXT':
                        self._analyze_txt_records(records)
                    elif record_type == 'MX':
                        self._analyze_mx_records(records)
                        
                except dns.resolver.NXDOMAIN:
                    pass
                except Exception as e:
                    self.results['dns_analysis'].append({
                        'record_type': record_type,
                        'error': str(e)
                    })
            
            # Reverse DNS lookup
            try:
                import socket
                ip_address = socket.gethostbyname(self.target_host)
                reverse_name = dns.reversename.from_address(ip_address)
                reverse_answer = dns.resolver.resolve(reverse_name, 'PTR')
                
                self.results['dns_analysis'].append({
                    'record_type': 'PTR',
                    'ip_address': ip_address,
                    'reverse_dns': str(reverse_answer[0])
                })
            except Exception:
                pass
                
        except ImportError:
            self.results['dns_analysis'].append({
                'error': 'dnspython module not available for DNS analysis'
            })
    
    def _analyze_txt_records(self, records):
        """Analyze TXT records for security information"""
        for record in records:
            # Check for SPF records
            if record.startswith('v=spf1'):
                if 'include:' in record and 'all' not in record:
                    self.results['dns_analysis'].append({
                        'security_issue': 'Incomplete SPF record',
                        'record': record,
                        'severity': 'Medium'
                    })
            
            # Check for DMARC records
            elif record.startswith('v=DMARC1'):
                if 'p=none' in record:
                    self.results['dns_analysis'].append({
                        'security_issue': 'DMARC policy set to none',
                        'record': record,
                        'severity': 'Low'
                    })
    
    def _analyze_mx_records(self, records):
        """Analyze MX records"""
        if not records:
            self.results['dns_analysis'].append({
                'security_issue': 'No MX records found',
                'severity': 'Low'
            })
    
    def _subdomain_enumeration(self):
        """Enumerate subdomains"""
        print(f"{self.scanner.colors['info']}[*] Subdomain numaralandırma yapılıyor...{self.scanner.colors['reset']}")
        
        # Common subdomain prefixes
        subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'blog', 'forum', 'shop', 'store', 'support', 'help', 'docs',
            'cdn', 'static', 'assets', 'img', 'images', 'media', 'files',
            'secure', 'ssl', 'vpn', 'remote', 'portal', 'dashboard',
            'beta', 'alpha', 'demo', 'sandbox', 'old', 'new', 'mobile',
            'app', 'apps', 'service', 'services', 'web', 'webmail'
        ]
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{self.target_host}"
                import socket
                ip = socket.gethostbyname(full_domain)
                return {
                    'subdomain': full_domain,
                    'ip_address': ip,
                    'status': 'active'
                }
            except socket.gaierror:
                return None
        
        # Threaded subdomain enumeration
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in subdomains]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results['subdomain_enum'].append(result)
                    
                    # Test HTTP/HTTPS on found subdomains
                    self._test_subdomain_services(result['subdomain'])
    
    def _test_subdomain_services(self, subdomain):
        """Test services on discovered subdomains"""
        protocols = ['http', 'https']
        
        for protocol in protocols:
            url = f"{protocol}://{subdomain}"
            response = make_request(self.scanner.session, 'GET', url, timeout=5)
            
            if response:
                # Update subdomain info with service details
                for sub_info in self.results['subdomain_enum']:
                    if sub_info['subdomain'] == subdomain:
                        if 'services' not in sub_info:
                            sub_info['services'] = []
                        
                        service_info = {
                            'protocol': protocol,
                            'status_code': response.status_code,
                            'server': response.headers.get('Server', 'Unknown')
                        }
                        
                        # Check for interesting content
                        if any(keyword in response.text.lower() for keyword in ['admin', 'login', 'dashboard']):
                            service_info['interesting'] = True
                        
                        sub_info['services'].append(service_info)
    
    def _cdn_detection(self):
        """Detect CDN usage"""
        print(f"{self.scanner.colors['info']}[*] CDN tespiti yapılıyor...{self.scanner.colors['reset']}")
        
        response = make_request(self.scanner.session, 'GET', self.scanner.target_url)
        
        if response:
            headers = response.headers
            
            # CDN detection patterns
            cdn_patterns = {
                'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
                'AWS CloudFront': ['x-amz-cf-id', 'cloudfront'],
                'Fastly': ['fastly', 'x-served-by'],
                'MaxCDN': ['maxcdn', 'x-cache'],
                'KeyCDN': ['keycdn'],
                'Akamai': ['akamai', 'x-akamai'],
                'Incapsula': ['incap_ses', 'x-iinfo'],
                'Sucuri': ['sucuri', 'x-sucuri']
            }
            
            detected_cdns = []
            
            for cdn_name, patterns in cdn_patterns.items():
                for pattern in patterns:
                    # Check headers
                    for header_name, header_value in headers.items():
                        if pattern.lower() in header_name.lower() or pattern.lower() in header_value.lower():
                            detected_cdns.append(cdn_name)
                            break
                    
                    # Check response body
                    if pattern.lower() in response.text.lower():
                        detected_cdns.append(cdn_name)
            
            # Remove duplicates
            detected_cdns = list(set(detected_cdns))
            
            if detected_cdns:
                self.results['cdn_detection'] = detected_cdns
            else:
                self.results['cdn_detection'] = ['None detected']
    
    def _load_balancer_detection(self):
        """Detect load balancer usage"""
        print(f"{self.scanner.colors['info']}[*] Load balancer tespiti yapılıyor...{self.scanner.colors['reset']}")
        
        # Make multiple requests to detect load balancing
        server_headers = []
        
        for i in range(5):
            response = make_request(self.scanner.session, 'GET', self.scanner.target_url)
            if response:
                server = response.headers.get('Server', '')
                x_served_by = response.headers.get('X-Served-By', '')
                x_cache = response.headers.get('X-Cache', '')
                
                server_info = {
                    'request': i + 1,
                    'server': server,
                    'x_served_by': x_served_by,
                    'x_cache': x_cache
                }
                server_headers.append(server_info)
            
            time.sleep(1)
        
        # Analyze for load balancing indicators
        unique_servers = set(info['server'] for info in server_headers if info['server'])
        unique_served_by = set(info['x_served_by'] for info in server_headers if info['x_served_by'])
        
        if len(unique_servers) > 1 or len(unique_served_by) > 1:
            self.results['load_balancer'].append({
                'detected': True,
                'evidence': 'Multiple server identifiers detected',
                'servers': list(unique_servers),
                'served_by': list(unique_served_by)
            })
        else:
            self.results['load_balancer'].append({
                'detected': False,
                'evidence': 'Consistent server responses'
            })
    
    def _firewall_detection(self):
        """Detect Web Application Firewall (WAF)"""
        print(f"{self.scanner.colors['info']}[*] Firewall tespiti yapılıyor...{self.scanner.colors['reset']}")
        
        # WAF detection payloads
        waf_payloads = [
            "<script>alert('xss')</script>",
            "' OR '1'='1",
            "../../../etc/passwd",
            "<?php phpinfo(); ?>",
            "<img src=x onerror=alert(1)>"
        ]
        
        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'AWS WAF': ['aws', 'x-amzn'],
            'Incapsula': ['incapsula', 'x-iinfo'],
            'Sucuri': ['sucuri', 'x-sucuri'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'F5 BIG-IP': ['f5', 'bigip'],
            'Barracuda': ['barracuda'],
            'Fortinet': ['fortinet', 'fortigate']
        }
        
        detected_wafs = []
        
        for payload in waf_payloads:
            # Test payload in URL parameter
            test_url = f"{self.scanner.target_url}?test={payload}"
            response = make_request(self.scanner.session, 'GET', test_url)
            
            if response:
                # Check for WAF blocking
                if response.status_code in [403, 406, 429, 503]:
                    # Analyze response for WAF signatures
                    for waf_name, signatures in waf_signatures.items():
                        for signature in signatures:
                            if signature.lower() in response.text.lower() or \
                               any(signature.lower() in header.lower() for header in response.headers.values()):
                                detected_wafs.append(waf_name)
                                break
                    
                    # Generic WAF detection
                    if not detected_wafs:
                        waf_keywords = ['blocked', 'forbidden', 'security', 'firewall', 'protection']
                        if any(keyword in response.text.lower() for keyword in waf_keywords):
                            detected_wafs.append('Generic WAF')
            
            time.sleep(1)  # Avoid triggering rate limits
        
        self.results['firewall_detection'] = list(set(detected_wafs)) if detected_wafs else ['None detected']
    
    def _rate_limiting_test(self):
        """Test rate limiting implementation"""
        print(f"{self.scanner.colors['info']}[*] Rate limiting testi yapılıyor...{self.scanner.colors['reset']}")
        
        # Test rapid requests
        start_time = time.time()
        request_count = 0
        blocked_count = 0
        
        for i in range(20):  # Send 20 rapid requests
            response = make_request(self.scanner.session, 'GET', self.scanner.target_url, timeout=5)
            request_count += 1
            
            if response:
                if response.status_code == 429:  # Too Many Requests
                    blocked_count += 1
                elif response.status_code in [403, 503]:  # Potential rate limiting
                    blocked_count += 1
            
            time.sleep(0.1)  # Small delay between requests
        
        end_time = time.time()
        duration = end_time - start_time
        
        rate_limit_info = {
            'requests_sent': request_count,
            'requests_blocked': blocked_count,
            'duration': round(duration, 2),
            'requests_per_second': round(request_count / duration, 2)
        }
        
        if blocked_count > 0:
            rate_limit_info['rate_limiting'] = 'Detected'
            rate_limit_info['effectiveness'] = f'{(blocked_count/request_count)*100:.1f}%'
        else:
            rate_limit_info['rate_limiting'] = 'Not detected'
        
        self.results['rate_limiting'].append(rate_limit_info)
    
    def _ddos_protection_test(self):
        """Test DDoS protection mechanisms"""
        print(f"{self.scanner.colors['info']}[*] DDoS koruması testi yapılıyor...{self.scanner.colors['reset']}")
        
        # Test with different user agents and patterns
        test_patterns = [
            {'name': 'Rapid requests', 'count': 50, 'delay': 0.05},
            {'name': 'Burst requests', 'count': 10, 'delay': 0},
            {'name': 'Sustained load', 'count': 30, 'delay': 0.5}
        ]
        
        for pattern in test_patterns:
            print(f"  Testing {pattern['name']}...")
            
            blocked_requests = 0
            total_requests = pattern['count']
            
            for i in range(total_requests):
                response = make_request(self.scanner.session, 'GET', self.scanner.target_url, timeout=5)
                
                if response:
                    # Check for DDoS protection responses
                    if response.status_code in [429, 503, 403]:
                        blocked_requests += 1
                    
                    # Check for challenge pages (CAPTCHA, JS challenge)
                    if any(keyword in response.text.lower() for keyword in 
                           ['challenge', 'captcha', 'checking your browser', 'ddos protection']):
                        blocked_requests += 1
                
                if pattern['delay'] > 0:
                    time.sleep(pattern['delay'])
            
            protection_info = {
                'test_pattern': pattern['name'],
                'total_requests': total_requests,
                'blocked_requests': blocked_requests,
                'protection_rate': f'{(blocked_requests/total_requests)*100:.1f}%'
            }
            
            if blocked_requests > 0:
                protection_info['ddos_protection'] = 'Active'
            else:
                protection_info['ddos_protection'] = 'Not detected'
            
            self.results['ddos_protection'].append(protection_info)
            
            time.sleep(2)  # Cool down between tests