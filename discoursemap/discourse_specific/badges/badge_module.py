#!/usr/bin/env python3
"""
Discourse Badge System Security Module

Comprehensive badge system security testing including:
- Badge enumeration and discovery
- Badge manipulation and granting vulnerabilities
- Badge SQL query exposure
- Badge grouping privilege escalation
- Automatic badge assignment flaws
- Badge trigger manipulation
- Custom badge creation vulnerabilities
"""

from urllib.parse import urljoin
from colorama import Fore, Style
import re


class BadgeSecurityModule:
    """Advanced badge system security testing for Discourse"""
    
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.verbose = verbose
        self.results = {
            'module': 'Badge Security (Advanced)',
            'badges_found': [],
            'badge_types': {
                'gold': [],
                'silver': [],
                'bronze': []
            },
            'badge_manipulation': [],
            'badge_enumeration': [],
            'sql_query_exposure': [],
            'auto_badge_flaws': [],
            'custom_badge_vulns': [],
            'badge_grouping_issues': [],
            'vulnerabilities': [],
            'recommendations': [],
            'total_tests': 0
        }
    
    def scan(self):
        """Execute comprehensive badge security scan"""
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting Advanced Badge System Scan...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Target: {self.target_url}{Style.RESET_ALL}\n")
        
        # Phase 1: Badge Discovery
        self._enumerate_badges()
        self._discover_hidden_badges()
        self._enumerate_badge_types()
        
        # Phase 2: Manipulation Testing
        self._test_badge_granting()
        self._test_badge_revocation()
        self._test_badge_creation()
        
        # Phase 3: SQL & Query Analysis
        self._check_badge_sql_exposure()
        self._test_badge_trigger_manipulation()
        
        # Phase 4: Privilege Escalation
        self._test_badge_group_privileges()
        self._test_automatic_badge_assignment()
        
        # Phase 5: Advanced Tests
        self._test_badge_caching()
        self._test_badge_notifications()
        
        # Generate recommendations
        self._generate_recommendations()
        
        if self.verbose:
            print(f"\n{Fore.GREEN}[+] Badge scan complete: {self.results['total_tests']} tests performed{Style.RESET_ALL}")
        
        return self.results
    
    def _enumerate_badges(self):
        """Comprehensive badge enumeration"""
        self.results['total_tests'] += 1
        
        try:
            import requests
            badge_url = urljoin(self.target_url, '/badges.json')
            response = requests.get(badge_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                badges = data.get('badges', [])
                badge_groupings = data.get('badge_groupings', [])
                
                for badge in badges:
                    badge_info = {
                        'id': badge.get('id'),
                        'name': badge.get('name'),
                        'description': badge.get('description'),
                        'badge_type_id': badge.get('badge_type_id'),
                        'grant_count': badge.get('grant_count', 0),
                        'allow_title': badge.get('allow_title', False),
                        'multiple_grant': badge.get('multiple_grant', False),
                        'icon': badge.get('icon'),
                        'image_url': badge.get('image_url'),
                        'listable': badge.get('listable', True),
                        'enabled': badge.get('enabled', True),
                        'auto_revoke': badge.get('auto_revoke', False),
                        'badge_grouping_id': badge.get('badge_grouping_id')
                    }
                    
                    self.results['badges_found'].append(badge_info)
                    
                    # Categorize by type
                    badge_type = badge.get('badge_type_id', 0)
                    if badge_type == 1:  # Gold
                        self.results['badge_types']['gold'].append(badge_info)
                    elif badge_type == 2:  # Silver
                        self.results['badge_types']['silver'].append(badge_info)
                    elif badge_type == 3:  # Bronze
                        self.results['badge_types']['bronze'].append(badge_info)
                    
                    # Check for security issues
                    if badge.get('multiple_grant'):
                        self.results['badge_manipulation'].append({
                            'badge': badge.get('name'),
                            'issue': 'Multiple grants allowed',
                            'severity': 'info',
                            'description': 'Badge can be granted multiple times'
                        })
                    
                    if not badge.get('listable'):
                        self.results['badge_enumeration'].append({
                            'badge': badge.get('name'),
                            'issue': 'Hidden badge',
                            'severity': 'low',
                            'description': 'Badge is not publicly listable'
                        })
                
                if self.verbose:
                    print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Found {len(badges)} badges")
                    print(f"    - Gold: {len(self.results['badge_types']['gold'])}")
                    print(f"    - Silver: {len(self.results['badge_types']['silver'])}")
                    print(f"    - Bronze: {len(self.results['badge_types']['bronze'])}")
                    
        except Exception as e:
            if self.verbose:
                print(f"  {Fore.RED}✗{Style.RESET_ALL} Badge enumeration failed: {str(e)}")
    
    def _discover_hidden_badges(self):
        """Discover hidden badges via ID enumeration"""
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Discovering hidden badges...")
        
        try:
            import requests
            known_ids = {b['id'] for b in self.results['badges_found']}
            hidden_found = 0
            
            # Test badge IDs 1-100
            for badge_id in range(1, 101):
                if badge_id in known_ids:
                    continue
                
                try:
                    badge_url = urljoin(self.target_url, f'/badges/{badge_id}.json')
                    response = requests.get(badge_url, timeout=3)
                    
                    if response.status_code == 200:
                        data = response.json()
                        badge_data = data.get('badge', {})
                        
                        if badge_data:
                            hidden_found += 1
                            self.results['badge_enumeration'].append({
                                'badge_id': badge_id,
                                'badge_name': badge_data.get('name'),
                                'issue': 'Hidden badge discovered',
                                'severity': 'medium',
                                'description': f'Badge ID {badge_id} accessible but not in public list'
                            })
                            
                            self.results['vulnerabilities'].append({
                                'type': 'Hidden Badge Discovery',
                                'severity': 'medium',
                                'badge_id': badge_id,
                                'badge_name': badge_data.get('name'),
                                'description': 'Unlisted badge accessible via direct ID'
                            })
                except Exception as e:
                    if self.verbose:
                        print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} Error checking badge {badge_id}: {str(e)[:30]}")
                    continue
            
            if self.verbose:
                if hidden_found > 0:
                    print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} Found {hidden_found} hidden badges")
                else:
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} No hidden badges found")
                    
        except Exception as e:
            if self.verbose:
                print(f"    {Fore.RED}✗{Style.RESET_ALL} Hidden badge discovery failed")
    
    def _enumerate_badge_types(self):
        """Analyze badge type distribution"""
        self.results['total_tests'] += 1
        
        try:
            import requests
            types_url = urljoin(self.target_url, '/badge_types.json')
            response = requests.get(types_url, timeout=10)
            
            if response.status_code == 200:
                if self.verbose:
                    print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Badge types endpoint accessible")
        except:
            pass
    
    def _test_badge_granting(self):
        """Test badge granting vulnerabilities"""
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing badge granting...")
        
        try:
            import requests
            
            # Test 1: Unauthorized badge granting
            grant_url = urljoin(self.target_url, '/user_badges')
            response = requests.post(
                grant_url,
                json={'badge_id': 1, 'username': 'testuser'},
                timeout=5
            )
            
            if response.status_code == 200:
                self.results['vulnerabilities'].append({
                    'type': 'Unauthorized Badge Granting',
                    'severity': 'critical',
                    'endpoint': '/user_badges',
                    'description': 'Badge granting possible without authentication'
                })
                
                if self.verbose:
                    print(f"    {Fore.RED}✗ CRITICAL: Badge granting not protected!{Style.RESET_ALL}")
            
            # Test 2: Badge granting via API
            for badge in self.results['badges_found'][:3]:  # Test first 3
                api_grant_url = urljoin(self.target_url, f"/user_badges/grant/{badge['id']}")
                response = requests.post(api_grant_url, json={'username': 'test'}, timeout=5)
                
                if response.status_code in [200, 201]:
                    self.results['badge_manipulation'].append({
                        'badge': badge['name'],
                        'method': 'API grant',
                        'severity': 'high',
                        'description': f'Badge "{badge["name"]}" can be granted via API'
                    })
            
            if self.verbose and not self.results['vulnerabilities']:
                print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Badge granting properly protected")
                
        except Exception as e:
            if self.verbose:
                print(f"    {Fore.RED}✗{Style.RESET_ALL} Badge granting test failed")
    
    def _test_badge_revocation(self):
        """Test badge revocation vulnerabilities"""
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing badge revocation...")
        
        try:
            import requests
            
            # Test unauthorized revocation
            revoke_url = urljoin(self.target_url, '/user_badges/1')
            response = requests.delete(revoke_url, timeout=5)
            
            if response.status_code == 200:
                self.results['vulnerabilities'].append({
                    'type': 'Unauthorized Badge Revocation',
                    'severity': 'high',
                    'endpoint': '/user_badges',
                    'description': 'Badge revocation possible without authorization'
                })
                
                if self.verbose:
                    print(f"    {Fore.RED}✗ HIGH: Badge revocation not protected!{Style.RESET_ALL}")
            else:
                if self.verbose:
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Badge revocation protected")
        except:
            pass
    
    def _test_badge_creation(self):
        """Test custom badge creation vulnerabilities"""
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing badge creation...")
        
        try:
            import requests
            
            # Try to create custom badge (admin only)
            create_url = urljoin(self.target_url, '/admin/badges')
            response = requests.post(
                create_url,
                json={
                    'name': 'Test Badge',
                    'badge_type_id': 3,
                    'description': 'Test'
                },
                timeout=5
            )
            
            if response.status_code in [200, 201]:
                self.results['custom_badge_vulns'].append({
                    'issue': 'Unauthorized badge creation',
                    'severity': 'critical',
                    'description': 'Custom badges can be created without admin privileges'
                })
                
                self.results['vulnerabilities'].append({
                    'type': 'Custom Badge Creation',
                    'severity': 'critical',
                    'endpoint': '/admin/badges',
                    'description': 'Badge creation endpoint not properly protected'
                })
                
                if self.verbose:
                    print(f"    {Fore.RED}✗ CRITICAL: Badge creation accessible!{Style.RESET_ALL}")
            else:
                if self.verbose:
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Badge creation protected")
        except:
            pass
    
    def _check_badge_sql_exposure(self):
        """Check for exposed badge SQL queries (security risk)"""
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Checking SQL query exposure...")
        
        try:
            import requests
            sql_exposed = 0
            
            for badge in self.results['badges_found']:
                badge_id = badge.get('id')
                badge_url = urljoin(self.target_url, f'/badges/{badge_id}.json')
                response = requests.get(badge_url, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    badge_data = data.get('badge', {})
                    query = badge_data.get('query')
                    
                    if query:
                        sql_exposed += 1
                        
                        # Check for dangerous SQL patterns
                        dangerous_patterns = [
                            'SELECT', 'FROM', 'WHERE', 'JOIN',
                            'users.', 'posts.', 'topics.'
                        ]
                        
                        found_patterns = [p for p in dangerous_patterns if p in query]
                        
                        self.results['sql_query_exposure'].append({
                            'badge_name': badge.get('name'),
                            'badge_id': badge_id,
                            'query_exposed': True,
                            'query_snippet': query[:100] + '...' if len(query) > 100 else query,
                            'patterns_found': found_patterns,
                            'severity': 'high' if len(found_patterns) > 3 else 'medium'
                        })
                        
                        # This is a vulnerability - SQL queries shouldn't be exposed
                        if len(found_patterns) > 3:
                            self.results['vulnerabilities'].append({
                                'type': 'Badge SQL Query Exposure',
                                'severity': 'high',
                                'badge': badge.get('name'),
                                'description': f'Badge SQL query fully exposed, revealing database schema'
                            })
            
            if self.verbose:
                if sql_exposed > 0:
                    print(f"    {Fore.RED}✗ SECURITY RISK: {sql_exposed} badge queries exposed{Style.RESET_ALL}")
                else:
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} No SQL queries exposed")
                    
        except Exception as e:
            if self.verbose:
                print(f"    {Fore.RED}✗{Style.RESET_ALL} SQL exposure check failed")
    
    def _test_badge_trigger_manipulation(self):
        """Test if badge triggers can be manipulated"""
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing badge trigger manipulation...")
        
        try:
            import requests
            
            # Test if we can trigger badge updates
            trigger_url = urljoin(self.target_url, '/admin/badges/trigger')
            response = requests.post(trigger_url, json={'badge_id': 1}, timeout=5)
            
            if response.status_code in [200, 202]:
                self.results['badge_manipulation'].append({
                    'issue': 'Badge trigger accessible',
                    'severity': 'high',
                    'description': 'Badge trigger endpoint can be called without authorization'
                })
                
                if self.verbose:
                    print(f"    {Fore.RED}✗ Badge trigger not protected{Style.RESET_ALL}")
            else:
                if self.verbose:
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Badge trigger protected")
        except:
            pass
    
    def _test_badge_group_privileges(self):
        """Test badge-based group privileges"""
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing badge group privileges...")
        
        try:
            import requests
            
            # Check if badges grant group membership
            for badge in self.results['badges_found'][:10]:
                badge_url = urljoin(self.target_url, f'/badges/{badge["id"]}.json')
                response = requests.get(badge_url, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    badge_data = data.get('badge', {})
                    
                    # Check for automatic group membership
                    if badge_data.get('auto_revoke') == False and badge_data.get('allow_title'):
                        self.results['badge_grouping_issues'].append({
                            'badge': badge['name'],
                            'issue': 'Permanent privilege badge',
                            'severity': 'medium',
                            'description': 'Badge grants permanent privileges without auto-revoke'
                        })
            
            if self.verbose:
                if self.results['badge_grouping_issues']:
                    print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} Found {len(self.results['badge_grouping_issues'])} privilege issues")
                else:
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} No badge privilege issues found")
        except:
            pass
    
    def _test_automatic_badge_assignment(self):
        """Test automatic badge assignment flaws"""
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing automatic badge assignment...")
        
        # Check for badges with no grant requirements
        flawed_badges = 0
        for badge in self.results['badges_found']:
            if badge.get('grant_count', 0) > 1000 and badge.get('badge_type_id') == 1:  # Gold with many grants
                flawed_badges += 1
                self.results['auto_badge_flaws'].append({
                    'badge': badge['name'],
                    'issue': 'Suspicious grant count',
                    'grant_count': badge['grant_count'],
                    'severity': 'low',
                    'description': 'Gold badge with unusually high grant count'
                })
        
        if self.verbose:
            if flawed_badges > 0:
                print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} {flawed_badges} suspicious badges found")
            else:
                print(f"    {Fore.GREEN}✓{Style.RESET_ALL} No suspicious automatic assignments")
    
    def _test_badge_caching(self):
        """Test badge caching vulnerabilities"""
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing badge caching...")
        
        try:
            import requests
            
            # Test if badge list is cached and reveals user data
            badge_url = urljoin(self.target_url, '/badges.json')
            response = requests.get(badge_url, timeout=10)
            
            if response.status_code == 200:
                cache_header = response.headers.get('Cache-Control', '')
                if 'public' in cache_header.lower():
                    if self.verbose:
                        print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} Badge data publicly cached")
        except:
            pass
    
    def _test_badge_notifications(self):
        """Test badge notification privacy"""
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing badge notifications...")
        
        # Check if badge notifications leak information
        try:
            import requests
            
            notif_url = urljoin(self.target_url, '/notifications.json')
            response = requests.get(notif_url, timeout=5)
            
            if response.status_code == 200:
                if self.verbose:
                    print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} Notification endpoint accessible")
        except:
            pass
    
    def _generate_recommendations(self):
        """Generate security recommendations"""
        
        if self.results['sql_query_exposure']:
            self.results['recommendations'].append({
                'priority': 'HIGH',
                'issue': f"{len(self.results['sql_query_exposure'])} badge SQL queries exposed",
                'recommendation': 'Hide badge SQL queries from public API responses'
            })
        
        if self.results['vulnerabilities']:
            critical = len([v for v in self.results['vulnerabilities'] if v['severity'] == 'critical'])
            if critical > 0:
                self.results['recommendations'].append({
                    'priority': 'CRITICAL',
                    'issue': f'{critical} critical badge vulnerabilities',
                    'recommendation': 'Implement proper authorization checks on badge endpoints'
                })
        
        if len(self.results['badge_types']['gold']) > 50:
            self.results['recommendations'].append({
                'priority': 'LOW',
                'issue': 'Large number of gold badges',
                'recommendation': 'Review badge type distribution - too many gold badges may devalue them'
            })
    
    def print_results(self):
        """Print scan results"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"BADGE SECURITY SCAN RESULTS")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        print(f"Target: {self.target_url}")
        print(f"Badges Found: {len(self.results['badges_found'])}")
        print(f"Vulnerabilities: {len(self.results['vulnerabilities'])}\n")
        
        if self.results['vulnerabilities']:
            print(f"{Fore.RED}[!] Vulnerabilities:{Style.RESET_ALL}")
            for vuln in self.results['vulnerabilities']:
                print(f"  - [{vuln['severity'].upper()}] {vuln['type']}")
                print(f"    {vuln['description']}")
