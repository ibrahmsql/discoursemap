#!/usr/bin/env python3
"""
Discourse Category Security Module - ADVANCED

Comprehensive category permission and security testing including:
- Category enumeration and discovery
- Permission bypass testing
- Hidden category discovery
- Category group permissions
- Read/Write/Create access control
- Subcategory security
- Category visibility manipulation
- Permission inheritance flaws
- Category archiving vulnerabilities
- Category ownership bypass
"""

from urllib.parse import urljoin
from colorama import Fore, Style
import re


class CategorySecurityModule:
    """Advanced category permission security testing - 500+ lines"""
    
    def __init__(self, target_url, verbose=False):
        """
        Initialize the CategorySecurityModule for running category-focused security tests against a Discourse instance.
        
        Parameters:
            target_url (str): Base URL of the target Discourse site (e.g., "https://forum.example.com").
            verbose (bool): When True, emit progress and diagnostic messages during scanning.
        
        Description:
            Sets instance configuration and initializes the results structure used to accumulate discovered categories,
            tree relationships, hidden/restricted findings, permission and bypass tests, vulnerabilities, recommendations,
            and a test counter.
        """
        self.target_url = target_url
        self.verbose = verbose
        self.results = {
            'module': 'Category Security (Advanced)',
            'categories_found': [],
            'category_tree': {},
            'hidden_categories': [],
            'restricted_categories': [],
            'permission_bypass': [],
            'group_permissions': [],
            'subcategory_issues': [],
            'visibility_issues': [],
            'ownership_bypass': [],
            'vulnerabilities': [],
            'recommendations': [],
            'total_tests': 0
        }
    
    def scan(self):
        """
        Run a full multi-phase security assessment of the target's categories.
        
        Performs category discovery, hidden-category enumeration, category tree construction, permission tests (read/write/create), bypass and group/API bypass testing, and advanced checks (subcategory inheritance, visibility, archiving, ownership). Generates remediation recommendations and accumulates findings.
        
        Returns:
            results (dict): Aggregated scan results including counts and lists such as 'categories_found', 'category_tree', 'hidden_categories', 'restricted_categories', 'bypasses', 'vulnerabilities' (list of dicts with severity and description), 'recommendations', 'total_tests', and other diagnostic metrics.
        """
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting Advanced Category Security Scan...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Target: {self.target_url}{Style.RESET_ALL}\n")
        
        # Phase 1: Category Discovery
        self._enumerate_categories()
        self._discover_hidden_categories()
        self._build_category_tree()
        
        # Phase 2: Permission Testing
        self._test_read_permissions()
        self._test_write_permissions()
        self._test_create_permissions()
        
        # Phase 3: Bypass Testing
        self._test_permission_bypass()
        self._test_group_bypass()
        self._test_api_permission_bypass()
        
        # Phase 4: Advanced Tests
        self._test_subcategory_security()
        self._test_category_visibility()
        self._test_category_archiving()
        self._test_ownership_bypass()
        self._test_permission_inheritance()
        
        # Generate recommendations
        self._generate_recommendations()
        
        if self.verbose:
            print(f"\n{Fore.GREEN}[+] Category scan complete: {self.results['total_tests']} tests performed{Style.RESET_ALL}")
        
        return self.results
    
    def _enumerate_categories(self):
        """
        Enumerates categories from the target Discourse instance and records each category's attributes and restricted status.
        
        Increments self.results['total_tests'], requests /categories.json, parses the returned category list into structured entries appended to self.results['categories_found'], and appends restricted categories to self.results['restricted_categories']. Emits progress and outcome messages when verbose is enabled.
        """
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Enumerating categories...")
        
        try:
            import requests
            
            categories_url = urljoin(self.target_url, '/categories.json')
            response = requests.get(categories_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                category_list = data.get('category_list', {})
                categories = category_list.get('categories', [])
                
                for cat in categories:
                    cat_info = {
                        'id': cat.get('id'),
                        'name': cat.get('name'),
                        'slug': cat.get('slug'),
                        'color': cat.get('color'),
                        'text_color': cat.get('text_color'),
                        'description': cat.get('description'),
                        'topic_count': cat.get('topic_count', 0),
                        'post_count': cat.get('post_count', 0),
                        'read_restricted': cat.get('read_restricted', False),
                        'parent_category_id': cat.get('parent_category_id'),
                        'permission_type': cat.get('permission', 'everyone'),
                        'has_children': cat.get('has_children', False),
                        'subcategory_count': len(cat.get('subcategory_list', []))
                    }
                    
                    self.results['categories_found'].append(cat_info)
                    
                    # Flag restricted categories
                    if cat.get('read_restricted'):
                        self.results['restricted_categories'].append(cat_info)
                
                if self.verbose:
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Found {len(categories)} categories")
                    print(f"      - Restricted: {len(self.results['restricted_categories'])}")
                    print(f"      - Public: {len(categories) - len(self.results['restricted_categories'])}")
                    
        except Exception as e:
            if self.verbose:
                print(f"    {Fore.RED}✗{Style.RESET_ALL} Category enumeration failed: {str(e)}")
    
    def _discover_hidden_categories(self):
        """
        Searches category IDs 1–50 to find hidden categories accessible via direct ID endpoints.
        
        Attempts to fetch /c/{id}.json for IDs not already discovered and, for each accessible category, appends a record to self.results['hidden_categories'] (including id, name, slug, read_restricted, and discovery_method = 'ID enumeration') and adds a corresponding medium-severity entry to self.results['vulnerabilities']. Also increments self.results['total_tests'] as part of its side effects and logs progress when verbose is enabled.
        """
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Discovering hidden categories...")
        
        try:
            import requests
            known_ids = {c['id'] for c in self.results['categories_found']}
            hidden_found = 0
            
            # Test category IDs 1-50
            for cat_id in range(1, 51):
                if cat_id in known_ids:
                    continue
                
                try:
                    # Try both slug and ID-based access
                    cat_url = urljoin(self.target_url, f'/c/{cat_id}.json')
                    response = requests.get(cat_url, timeout=3)
                    
                    if response.status_code == 200:
                        data = response.json()
                        category = data.get('category', {})
                        
                        if category and category.get('id'):
                            hidden_found += 1
                            self.results['hidden_categories'].append({
                                'id': cat_id,
                                'name': category.get('name'),
                                'slug': category.get('slug'),
                                'read_restricted': category.get('read_restricted', False),
                                'discovery_method': 'ID enumeration'
                            })
                            
                            self.results['vulnerabilities'].append({
                                'type': 'Hidden Category Discovery',
                                'severity': 'medium',
                                'category_id': cat_id,
                                'category_name': category.get('name'),
                                'description': f'Hidden category accessible via direct ID: {cat_id}'
                            })
                except:
                    continue
            
            if self.verbose:
                if hidden_found > 0:
                    print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} Found {hidden_found} hidden categories")
                else:
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} No hidden categories found")
                    
        except Exception:
            if self.verbose:
                print(f"    {Fore.RED}✗{Style.RESET_ALL} Hidden category discovery failed")
    
    def _build_category_tree(self):
        """
        Constructs a hierarchical category tree from the discovered categories.
        
        Increments the test counter and populates self.results['category_tree'] with entries for each root category (categories with no parent). Each entry maps the root category's id to a dict containing the root's `category` data and a `children` list populated with direct child category objects from self.results['categories_found'].
        """
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Building category tree...")
        
        # Build parent-child relationships
        for cat in self.results['categories_found']:
            parent_id = cat.get('parent_category_id')
            
            if not parent_id:
                # Root category
                self.results['category_tree'][cat['id']] = {
                    'category': cat,
                    'children': []
                }
        
        # Add children
        for cat in self.results['categories_found']:
            parent_id = cat.get('parent_category_id')
            if parent_id and parent_id in self.results['category_tree']:
                self.results['category_tree'][parent_id]['children'].append(cat)
        
        if self.verbose:
            root_count = len(self.results['category_tree'])
            print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Built tree: {root_count} root categories")
    
    def _test_read_permissions(self):
        """
        Check whether read-restricted categories are accessible without authentication.
        
        Increments results['total_tests']. For each category in results['restricted_categories'] attempts to access the category's public JSON endpoint; if the category is reachable (HTTP 200), appends a record to results['permission_bypass'] and a vulnerability entry to results['vulnerabilities']. When verbose, prints progress and per-category findings.
        """
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing read permissions...")
        
        try:
            import requests
            
            for cat in self.results['restricted_categories']:
                cat_url = urljoin(self.target_url, f"/c/{cat['slug']}.json")
                response = requests.get(cat_url, timeout=5)
                
                if response.status_code == 200:
                    self.results['permission_bypass'].append({
                        'category': cat['name'],
                        'bypass_type': 'Read permission',
                        'severity': 'high',
                        'description': f'Restricted category "{cat["name"]}" readable without authentication'
                    })
                    
                    self.results['vulnerabilities'].append({
                        'type': 'Read Permission Bypass',
                        'severity': 'high',
                        'category': cat['name'],
                        'description': 'Read-restricted category accessible'
                    })
                    
                    if self.verbose:
                        print(f"    {Fore.RED}✗ Read bypass: {cat['name']}{Style.RESET_ALL}")
            
            if self.verbose and not self.results['permission_bypass']:
                print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Read permissions enforced")
                
        except Exception:
            pass
    
    def _test_write_permissions(self):
        """
        Check whether topics can be created in categories without proper authorization.
        
        Increments the module's test counter and attempts to create a topic in up to the first five discovered categories. If a topic creation succeeds, records a critical "Write permission" bypass entry in self.results['permission_bypass'] and, when verbose, prints an alert. This method has no return value.
        """
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing write permissions...")
        
        try:
            import requests
            
            for cat in self.results['categories_found'][:5]:
                # Try to create a topic in category
                create_url = urljoin(self.target_url, '/posts')
                response = requests.post(
                    create_url,
                    json={
                        'title': 'Test Topic',
                        'raw': 'Test content',
                        'category': cat['id']
                    },
                    timeout=5
                )
                
                if response.status_code in [200, 201]:
                    self.results['permission_bypass'].append({
                        'category': cat['name'],
                        'bypass_type': 'Write permission',
                        'severity': 'critical',
                        'description': f'Can create topics in "{cat["name"]}" without authorization'
                    })
                    
                    if self.verbose:
                        print(f"    {Fore.RED}✗ CRITICAL: Write bypass in {cat['name']}{Style.RESET_ALL}")
                    break
        except:
            pass
    
    def _test_create_permissions(self):
        """
        Check whether the target allows creating categories without admin privileges.
        
        Attempts to create a category on the target site; if the request succeeds (HTTP 200 or 201) a critical
        'Unauthorized Category Creation' finding is appended to self.results['vulnerabilities']. This method
        also increments self.results['total_tests'] and, when verbose, prints progress and the outcome.
        """
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing category creation...")
        
        try:
            import requests
            
            # Try to create a category (admin only)
            create_cat_url = urljoin(self.target_url, '/categories')
            response = requests.post(
                create_cat_url,
                json={
                    'name': 'Test Category',
                    'color': '0088CC',
                    'text_color': 'FFFFFF'
                },
                timeout=5
            )
            
            if response.status_code in [200, 201]:
                self.results['vulnerabilities'].append({
                    'type': 'Unauthorized Category Creation',
                    'severity': 'critical',
                    'description': 'Categories can be created without admin privileges'
                })
                
                if self.verbose:
                    print(f"    {Fore.RED}✗ CRITICAL: Category creation accessible!{Style.RESET_ALL}")
            else:
                if self.verbose:
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Category creation protected")
        except:
            pass
    
    def _test_permission_bypass(self):
        """
        Attempt multiple alternate endpoints for up to three restricted categories and record any successful access as permission bypass findings.
        
        This method increments the internal test counter and, for up to three categories marked as restricted, tries alternative category endpoints. When an endpoint returns HTTP 200, it appends a high-severity finding to self.results['permission_bypass'] containing the category name, bypass method, severity, and description. Network or other runtime errors are caught and ignored; this method does not raise on request failures.
        """
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing permission bypass techniques...")
        
        try:
            import requests
            
            for cat in self.results['restricted_categories'][:3]:
                # Try different access methods
                bypass_attempts = [
                    f"/c/{cat['id']}/l/latest.json",
                    f"/c/{cat['slug']}/l/top.json",
                    f"/category/{cat['id']}.json"
                ]
                
                for attempt in bypass_attempts:
                    url = urljoin(self.target_url, attempt)
                    response = requests.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        self.results['permission_bypass'].append({
                            'category': cat['name'],
                            'bypass_method': attempt,
                            'severity': 'high',
                            'description': f'Bypass via alternate endpoint: {attempt}'
                        })
                        
                        if self.verbose:
                            print(f"    {Fore.RED}✗ Bypass found: {attempt}{Style.RESET_ALL}")
                        break
        except:
            pass
    
    def _test_group_bypass(self):
        """
        Check whether group membership can be manipulated to join groups without authorization.
        
        Queries the instance's /groups.json endpoint and attempts to join up to the first five groups by posting to each group's members endpoint. If joining a group succeeds, records a critical 'Unauthorized group join' vulnerability in results['group_permissions'] and emits verbose output when enabled.
        """
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing group permissions...")
        
        try:
            import requests
            
            # Check if group membership can be manipulated for access
            groups_url = urljoin(self.target_url, '/groups.json')
            response = requests.get(groups_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                groups = data.get('groups', [])
                
                for group in groups[:5]:
                    # Try to join group (should be restricted)
                    join_url = urljoin(self.target_url, f"/groups/{group.get('id')}/members")
                    response = requests.post(join_url, json={'usernames': 'test'}, timeout=5)
                    
                    if response.status_code in [200, 201]:
                        self.results['group_permissions'].append({
                            'group': group.get('name'),
                            'issue': 'Unauthorized group join',
                            'severity': 'critical',
                            'description': f'Can join group "{group.get("name")}" without authorization'
                        })
                        
                        if self.verbose:
                            print(f"    {Fore.RED}✗ Group join bypass: {group.get('name')}{Style.RESET_ALL}")
                        break
        except:
            pass
    
    def _test_api_permission_bypass(self):
        """
        Check whether restricted categories are accessible via the Discourse API endpoints.
        
        Attempts to fetch up to two categories from /c/{id}/show.json and, for any successful (HTTP 200) responses, appends a high-severity "API Permission Bypass" entry to self.results['vulnerabilities'] identifying the category and the API URL. Network errors and other exceptions are suppressed.
        """
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing API permission bypass...")
        
        try:
            import requests
            
            # Test if API allows bypassing web permissions
            for cat in self.results['restricted_categories'][:2]:
                api_url = urljoin(self.target_url, f"/c/{cat['id']}/show.json")
                response = requests.get(api_url, timeout=5)
                
                if response.status_code == 200:
                    self.results['vulnerabilities'].append({
                        'type': 'API Permission Bypass',
                        'severity': 'high',
                        'category': cat['name'],
                        'description': f'Restricted category accessible via API: {api_url}'
                    })
                    
                    if self.verbose:
                        print(f"    {Fore.RED}✗ API bypass: {cat['name']}{Style.RESET_ALL}")
        except:
            pass
    
    def _test_subcategory_security(self):
        """
        Assess subcategory permission inheritance and record any inheritance violations.
        
        Scans the built category tree for cases where a parent category is read-restricted but a direct child is not, increments the total test counter, and appends a high-severity issue entry to `self.results['subcategory_issues']` for each violation (including parent/child names and a description).
        """
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing subcategory security...")
        
        # Check if subcategories properly inherit permissions
        for root_id, tree in self.results['category_tree'].items():
            root = tree['category']
            children = tree['children']
            
            if root.get('read_restricted') and children:
                for child in children:
                    if not child.get('read_restricted'):
                        self.results['subcategory_issues'].append({
                            'parent': root['name'],
                            'child': child['name'],
                            'issue': 'Permission inheritance broken',
                            'severity': 'high',
                            'description': f'Subcategory "{child["name"]}" not restricted despite restricted parent'
                        })
                        
                        if self.verbose:
                            print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} Inheritance issue: {child['name']}")
    
    def _test_category_visibility(self):
        """
        Attempt to change category visibility and record unauthorized manipulation findings.
        
        Tries to set `read_restricted` to False for up to the first three discovered categories by issuing a PUT to each category endpoint. If a request succeeds (status 200 or 201), adds a critical entry to `self.results['visibility_issues']` describing the visibility manipulation and stops further attempts. May print progress or alerts when `self.verbose` is True.
        """
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing category visibility...")
        
        # Check if visibility can be manipulated
        try:
            import requests
            
            for cat in self.results['categories_found'][:3]:
                # Try to change visibility (admin only)
                update_url = urljoin(self.target_url, f"/categories/{cat['id']}")
                response = requests.put(
                    update_url,
                    json={'read_restricted': False},
                    timeout=5
                )
                
                if response.status_code in [200, 201]:
                    self.results['visibility_issues'].append({
                        'category': cat['name'],
                        'issue': 'Visibility manipulation',
                        'severity': 'critical',
                        'description': 'Category visibility can be changed without authorization'
                    })
                    
                    if self.verbose:
                        print(f"    {Fore.RED}✗ CRITICAL: Visibility manipulation possible{Style.RESET_ALL}")
                    break
        except:
            pass
    
    def _test_category_archiving(self):
        """
        Check whether categories can be archived without authorization.
        
        Attempts to archive the category at /categories/1/archive and, on HTTP 200 or 201, records a high-severity "Unauthorized Category Archiving" entry in self.results['vulnerabilities'] and increments the module's test counter. When verbose, prints progress and any detected archive bypass.
        """
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing category archiving...")
        
        # Check if categories can be archived without proper permissions
        try:
            import requests
            
            archive_url = urljoin(self.target_url, '/categories/1/archive')
            response = requests.put(archive_url, timeout=5)
            
            if response.status_code in [200, 201]:
                self.results['vulnerabilities'].append({
                    'type': 'Unauthorized Category Archiving',
                    'severity': 'high',
                    'description': 'Categories can be archived without proper authorization'
                })
                
                if self.verbose:
                    print(f"    {Fore.RED}✗ Archive bypass detected{Style.RESET_ALL}")
        except:
            pass
    
    def _test_ownership_bypass(self):
        """
        Checks whether categories can be deleted without proper ownership.
        
        If a category can be deleted by the current client, records a critical ownership bypass entry in results['ownership_bypass'] containing the category name, action, severity, and description. The method increments the total test counter and examines up to two discovered categories.
        """
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing ownership bypass...")
        
        # Test if non-owners can modify categories
        try:
            import requests
            
            for cat in self.results['categories_found'][:2]:
                # Try to delete category (owner/admin only)
                delete_url = urljoin(self.target_url, f"/categories/{cat['id']}")
                response = requests.delete(delete_url, timeout=5)
                
                if response.status_code in [200, 204]:
                    self.results['ownership_bypass'].append({
                        'category': cat['name'],
                        'action': 'delete',
                        'severity': 'critical',
                        'description': f'Category "{cat["name"]}" can be deleted without ownership'
                    })
                    
                    if self.verbose:
                        print(f"    {Fore.RED}✗ CRITICAL: Ownership bypass{Style.RESET_ALL}")
                    break
        except:
            pass
    
    def _test_permission_inheritance(self):
        """
        Evaluate subcategory permission inheritance and report any inheritance issues.
        
        Increments the module's total_tests counter and determines the number of inheritance issues by counting entries in self.results['subcategory_issues']. When verbose, prints a summary indicating the number of issues found or that permission inheritance is correct.
        """
        self.results['total_tests'] += 1
        
        if self.verbose:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Testing permission inheritance...")
        
        # Final check for inheritance issues
        inheritance_issues = len(self.results['subcategory_issues'])
        
        if self.verbose:
            if inheritance_issues > 0:
                print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} {inheritance_issues} inheritance issues found")
            else:
                print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Permission inheritance correct")
    
    def _generate_recommendations(self):
        """
        Builds remediation recommendations based on discovered category security findings.
        
        Adds recommendation entries to self.results['recommendations'] when specific conditions are met:
        - If any hidden categories were discovered, adds a MEDIUM-priority recommendation noting the count and advising access control on category endpoints.
        - If any permission bypass findings include critical severity, adds a CRITICAL-priority recommendation urging immediate review and fixes to category permission checks.
        - If subcategory permission inheritance issues were detected, adds a HIGH-priority recommendation to ensure subcategories inherit parent permissions correctly.
        - If more than 70% of discovered categories are restricted, adds an INFO-priority recommendation to review whether that many restrictions are necessary.
        """
        
        if self.results['hidden_categories']:
            self.results['recommendations'].append({
                'priority': 'MEDIUM',
                'issue': f"{len(self.results['hidden_categories'])} hidden categories discoverable",
                'recommendation': 'Implement proper access control on all category endpoints'
            })
        
        if self.results['permission_bypass']:
            critical_bypasses = len([b for b in self.results['permission_bypass'] if b['severity'] == 'critical'])
            if critical_bypasses > 0:
                self.results['recommendations'].append({
                    'priority': 'CRITICAL',
                    'issue': f'{critical_bypasses} critical permission bypass vulnerabilities',
                    'recommendation': 'Immediately review and fix category permission checks'
                })
        
        if self.results['subcategory_issues']:
            self.results['recommendations'].append({
                'priority': 'HIGH',
                'issue': 'Permission inheritance issues in subcategories',
                'recommendation': 'Ensure subcategories inherit parent category permissions correctly'
            })
        
        if len(self.results['restricted_categories']) > len(self.results['categories_found']) * 0.7:
            self.results['recommendations'].append({
                'priority': 'INFO',
                'issue': 'High percentage of restricted categories',
                'recommendation': 'Review if so many restricted categories are necessary'
            })
    
    def print_results(self):
        """
        Prints a formatted summary of the scan results to standard output.
        
        Outputs the target URL, counts of discovered categories (total, restricted, hidden),
        the number of tests performed, a list of discovered vulnerabilities including
        severity and descriptions, and any generated remediation recommendations with
        their priority and suggested actions.
        """
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"CATEGORY SECURITY SCAN RESULTS")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        print(f"Target: {self.target_url}")
        print(f"Categories Found: {len(self.results['categories_found'])}")
        print(f"  - Restricted: {len(self.results['restricted_categories'])}")
        print(f"  - Hidden: {len(self.results['hidden_categories'])}")
        print(f"Tests Performed: {self.results['total_tests']}")
        print(f"Vulnerabilities: {len(self.results['vulnerabilities'])}\n")
        
        if self.results['vulnerabilities']:
            print(f"{Fore.RED}[!] Vulnerabilities:{Style.RESET_ALL}")
            for vuln in self.results['vulnerabilities']:
                print(f"  - [{vuln['severity'].upper()}] {vuln['type']}")
                print(f"    {vuln['description']}")
        
        if self.results['recommendations']:
            print(f"\n{Fore.YELLOW}[!] Recommendations:{Style.RESET_ALL}")
            for rec in self.results['recommendations']:
                print(f"  - [{rec['priority']}] {rec['issue']}")
                print(f"    → {rec['recommendation']}")