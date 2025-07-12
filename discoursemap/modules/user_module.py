#!/usr/bin/env python3
"""
Discourse Security Scanner - User Security Module

Tests user-related security issues including authentication and authorization
"""

import re
import time
import json
import random
import string
from urllib.parse import urljoin, quote
from bs4 import BeautifulSoup
from .utils import extract_csrf_token

class UserModule:
    """User security testing module for Discourse forums"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.results = {
            'module_name': 'User Security Testing',
            'target': scanner.target_url,
            'user_enumeration': [],
            'weak_passwords': [],
            'brute_force_results': [],
            'session_issues': [],
            'password_reset_issues': [],
            'registration_issues': [],
            'privilege_escalation': [],
            'tests_performed': 0,
            'scan_time': 0
        }
        self.start_time = time.time()
        self.discovered_users = []
    
    def run(self):
        """Run user security testing module"""
        self.scanner.log("Starting user security testing...")
        
        # User enumeration
        self._test_user_enumeration()
        
        # Weak password testing
        self._test_weak_passwords()
        
        # Brute force testing (limited)
        self._test_brute_force_protection()
        
        # Session management testing
        self._test_session_management()
        
        # Password reset testing
        self._test_password_reset_flaws()
        
        # Registration testing
        self._test_registration_flaws()
        
        # Privilege escalation testing
        self._test_privilege_escalation()
        
        # Trust level system analysis
        self._analyze_trust_levels()
        
        # Badge system detection
        self._detect_badge_system()
        
        self.results['scan_time'] = time.time() - self.start_time
        return self.results
    
    def _test_user_enumeration(self):
        """Test for user enumeration vulnerabilities"""
        self.scanner.log("Testing user enumeration...", 'debug')
        
        # Extended list of common usernames to test
        common_usernames = [
            'admin', 'administrator', 'root', 'user', 'test',
            'guest', 'demo', 'support', 'moderator', 'mod',
            'staff', 'owner', 'webmaster', 'discourse',
            'system', 'service', 'api', 'bot', 'help',
            'info', 'contact', 'sales', 'marketing', 'dev',
            'developer', 'manager', 'supervisor', 'leader',
            'team', 'group', 'community', 'forum', 'board',
            'member', 'subscriber', 'customer', 'client',
            'operator', 'maintainer', 'editor', 'author',
            'writer', 'blogger', 'poster', 'contributor',
            'reviewer', 'tester', 'qa', 'quality', 'security',
            'backup', 'archive', 'temp', 'temporary', 'new',
            'old', 'legacy', 'default', 'example', 'sample'
        ]
        
        # Try to discover users from public endpoints
        self._discover_users_from_public_endpoints()
        
        # Try to discover users from directory listing
        self._discover_users_from_directory()
        
        # Try to discover users from search functionality
        self._discover_users_from_search()
        
        # Test user enumeration via different endpoints
        enumeration_endpoints = [
            '/u/{username}',
            '/u/{username}.json',
            '/users/{username}',
            '/users/{username}.json',
            '/users/by-external/{username}'
        ]
        
        valid_users = []
        
        for username in common_usernames:
            for endpoint_template in enumeration_endpoints:
                endpoint = endpoint_template.format(username=username)
                url = urljoin(self.scanner.target_url, endpoint)
                
                response = self.scanner.make_request(url)
                
                if response:
                    if response.status_code == 200:
                        # User exists
                        user_info = {
                            'username': username,
                            'endpoint': endpoint,
                            'status': 'exists',
                            'method': 'direct_access'
                        }
                        
                        # Try to extract additional info
                        if endpoint.endswith('.json'):
                            try:
                                user_data = response.json()
                                if 'user' in user_data:
                                    user_info.update({
                                        'id': user_data['user'].get('id'),
                                        'name': user_data['user'].get('name'),
                                        'username': user_data['user'].get('username'),
                                        'avatar_template': user_data['user'].get('avatar_template'),
                                        'trust_level': user_data['user'].get('trust_level'),
                                        'last_seen': user_data['user'].get('last_seen_at'),
                                        'last_posted': user_data['user'].get('last_posted_at'),
                                        'post_count': user_data['user'].get('post_count'),
                                        'topic_count': user_data['user'].get('topic_count'),
                                        'likes_given': user_data['user'].get('likes_given'),
                                        'likes_received': user_data['user'].get('likes_received'),
                                        'days_visited': user_data['user'].get('days_visited'),
                                        'posts_read_count': user_data['user'].get('posts_read_count'),
                                        'topics_entered': user_data['user'].get('topics_entered'),
                                        'time_read': user_data['user'].get('time_read'),
                                        'recent_time_read': user_data['user'].get('recent_time_read'),
                                        'primary_group_name': user_data['user'].get('primary_group_name'),
                                        'primary_group_flair_url': user_data['user'].get('primary_group_flair_url'),
                                        'primary_group_flair_bg_color': user_data['user'].get('primary_group_flair_bg_color'),
                                        'primary_group_flair_color': user_data['user'].get('primary_group_flair_color'),
                                        'featured_badge_id': user_data['user'].get('featured_badge_id'),
                                        'card_badge': user_data['user'].get('card_badge'),
                                        'bio_raw': user_data['user'].get('bio_raw'),
                                        'bio_cooked': user_data['user'].get('bio_cooked'),
                                        'website': user_data['user'].get('website'),
                                        'website_name': user_data['user'].get('website_name'),
                                        'location': user_data['user'].get('location'),
                                        'can_edit': user_data['user'].get('can_edit'),
                                        'can_edit_username': user_data['user'].get('can_edit_username'),
                                        'can_edit_email': user_data['user'].get('can_edit_email'),
                                        'can_edit_name': user_data['user'].get('can_edit_name'),
                                        'uploaded_avatar_id': user_data['user'].get('uploaded_avatar_id'),
                                        'has_title_badges': user_data['user'].get('has_title_badges'),
                                        'pending_count': user_data['user'].get('pending_count'),
                                        'profile_view_count': user_data['user'].get('profile_view_count'),
                                        'second_factor_enabled': user_data['user'].get('second_factor_enabled'),
                                        'can_upload_profile_header': user_data['user'].get('can_upload_profile_header'),
                                        'can_upload_user_card_background': user_data['user'].get('can_upload_user_card_background'),
                                        'groups': user_data['user'].get('groups', []),
                                        'group_users': user_data['user'].get('group_users', []),
                                        'featured_user_badge_ids': user_data['user'].get('featured_user_badge_ids', []),
                                        'invited_by': user_data['user'].get('invited_by'),
                                        'custom_fields': user_data['user'].get('custom_fields', {}),
                                        'user_fields': user_data['user'].get('user_fields', {}),
                                        'topic_post_count': user_data['user'].get('topic_post_count', {}),
                                        'can_see_private_messages': user_data['user'].get('can_see_private_messages'),
                                        'can_send_private_messages': user_data['user'].get('can_send_private_messages'),
                                        'can_send_private_message_to_user': user_data['user'].get('can_send_private_message_to_user'),
                                        'mutual_following': user_data['user'].get('mutual_following'),
                                        'is_followed': user_data['user'].get('is_followed'),
                                        'muted': user_data['user'].get('muted'),
                                        'can_mute_user': user_data['user'].get('can_mute_user'),
                                        'can_ignore_user': user_data['user'].get('can_ignore_user'),
                                        'system_avatar_upload_id': user_data['user'].get('system_avatar_upload_id'),
                                        'system_avatar_template': user_data['user'].get('system_avatar_template'),
                                        'gravatar_avatar_upload_id': user_data['user'].get('gravatar_avatar_upload_id'),
                                        'gravatar_avatar_template': user_data['user'].get('gravatar_avatar_template'),
                                        'custom_avatar_upload_id': user_data['user'].get('custom_avatar_upload_id'),
                                        'custom_avatar_template': user_data['user'].get('custom_avatar_template'),
                                        'has_posted': user_data['user'].get('has_posted'),
                                        'email': user_data['user'].get('email'),
                                        'secondary_emails': user_data['user'].get('secondary_emails', []),
                                        'unconfirmed_emails': user_data['user'].get('unconfirmed_emails', []),
                                        'associated_accounts': user_data['user'].get('associated_accounts', []),
                                        'can_change_bio': user_data['user'].get('can_change_bio'),
                                        'can_change_location': user_data['user'].get('can_change_location'),
                                        'can_change_website': user_data['user'].get('can_change_website'),
                                        'user_api_keys': user_data['user'].get('user_api_keys', []),
                                        'user_auth_tokens': user_data['user'].get('user_auth_tokens', []),
                                        'user_notification_schedule': user_data['user'].get('user_notification_schedule', {}),
                                        'use_logo_small_as_avatar': user_data['user'].get('use_logo_small_as_avatar'),
                                        'sidebar_category_ids': user_data['user'].get('sidebar_category_ids', []),
                                        'sidebar_tag_names': user_data['user'].get('sidebar_tag_names', []),
                                        'display_sidebar_tags': user_data['user'].get('display_sidebar_tags'),
                                        'timezone': user_data['user'].get('timezone'),
                                        'skip_new_user_tips': user_data['user'].get('skip_new_user_tips'),
                                        'seen_notification_id': user_data['user'].get('seen_notification_id'),
                                        'sidebar_list_destination': user_data['user'].get('sidebar_list_destination'),
                                        'hide_profile_and_presence': user_data['user'].get('hide_profile_and_presence'),
                                        'text_size': user_data['user'].get('text_size'),
                                        'text_size_seq': user_data['user'].get('text_size_seq'),
                                        'title_count_mode': user_data['user'].get('title_count_mode'),
                                        'enable_quoting': user_data['user'].get('enable_quoting'),
                                        'enable_defer': user_data['user'].get('enable_defer'),
                                        'external_links_in_new_tab': user_data['user'].get('external_links_in_new_tab'),
                                        'dynamic_favicon': user_data['user'].get('dynamic_favicon'),
                                        'automatically_unpin_topics': user_data['user'].get('automatically_unpin_topics'),
                                        'digest_after_minutes': user_data['user'].get('digest_after_minutes'),
                                        'new_topic_duration_minutes': user_data['user'].get('new_topic_duration_minutes'),
                                        'auto_track_topics_after_msecs': user_data['user'].get('auto_track_topics_after_msecs'),
                                        'notification_level_when_replying': user_data['user'].get('notification_level_when_replying'),
                                        'email_level': user_data['user'].get('email_level'),
                                        'email_messages_level': user_data['user'].get('email_messages_level'),
                                        'email_previous_replies': user_data['user'].get('email_previous_replies'),
                                        'email_in_reply_to': user_data['user'].get('email_in_reply_to'),
                                        'like_notification_frequency': user_data['user'].get('like_notification_frequency'),
                                        'mailing_list_mode': user_data['user'].get('mailing_list_mode'),
                                        'mailing_list_mode_frequency': user_data['user'].get('mailing_list_mode_frequency'),
                                        'include_tl0_in_digests': user_data['user'].get('include_tl0_in_digests'),
                                        'theme_ids': user_data['user'].get('theme_ids', []),
                                        'theme_key_seq': user_data['user'].get('theme_key_seq'),
                                        'allow_private_messages': user_data['user'].get('allow_private_messages'),
                                        'enable_allowed_pm_users': user_data['user'].get('enable_allowed_pm_users'),
                                        'homepage_id': user_data['user'].get('homepage_id'),
                                        'hide_profile_and_presence': user_data['user'].get('hide_profile_and_presence'),
                                        'user_option': user_data['user'].get('user_option', {})
                                    })
                                    
                                    # Extract avatar URLs if available
                                    if user_data['user'].get('avatar_template'):
                                        avatar_template = user_data['user']['avatar_template']
                                        user_info['avatar_urls'] = {
                                            'small': avatar_template.replace('{size}', '25'),
                                            'medium': avatar_template.replace('{size}', '45'),
                                            'large': avatar_template.replace('{size}', '120'),
                                            'extra_large': avatar_template.replace('{size}', '240')
                                        }
                            except json.JSONDecodeError:
                                pass
                        
                        valid_users.append(user_info)
                        self.scanner.log(f"User found: {username}", 'success')
                        break
                    
                    elif response.status_code == 404:
                        # User doesn't exist - this is normal
                        pass
                    
                    elif response.status_code == 403:
                        # User exists but access denied
                        user_info = {
                            'username': username,
                            'endpoint': endpoint,
                            'status': 'exists_protected',
                            'method': 'access_denied'
                        }
                        valid_users.append(user_info)
                        self.scanner.log(f"Protected user found: {username}", 'info')
                
                self.results['tests_performed'] += 1
                time.sleep(0.02)
    
    def _analyze_trust_levels(self):
        """Analyze Discourse trust level system"""
        self.scanner.log("Analyzing Discourse trust level system...", 'debug')
        
        trust_level_info = {
            'trust_levels_found': [],
            'trust_level_distribution': {},
            'trust_level_permissions': {},
            'potential_issues': []
        }
        
        # Check trust level information from discovered users
        for user_info in self.results.get('user_enumeration', []):
            if 'trust_level' in user_info and user_info['trust_level'] is not None:
                tl = user_info['trust_level']
                username = user_info.get('username', 'unknown')
                
                if tl not in trust_level_info['trust_levels_found']:
                    trust_level_info['trust_levels_found'].append(tl)
                
                if tl not in trust_level_info['trust_level_distribution']:
                    trust_level_info['trust_level_distribution'][tl] = []
                trust_level_info['trust_level_distribution'][tl].append(username)
        
        # Check for trust level endpoints
        trust_level_endpoints = [
            '/admin/users/list/trust_level_0',
            '/admin/users/list/trust_level_1', 
            '/admin/users/list/trust_level_2',
            '/admin/users/list/trust_level_3',
            '/admin/users/list/trust_level_4'
        ]
        
        for endpoint in trust_level_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list) and len(data) > 0:
                        tl = endpoint.split('_')[-1]
                        trust_level_info['trust_level_permissions'][f'TL{tl}'] = {
                            'accessible': True,
                            'user_count': len(data),
                            'endpoint': endpoint
                        }
                        
                        # Check if sensitive information is exposed
                        for user in data[:5]:  # Check first 5 users
                            if isinstance(user, dict):
                                sensitive_fields = ['email', 'ip_address', 'registration_ip_address']
                                exposed_fields = [field for field in sensitive_fields if field in user]
                                if exposed_fields:
                                    trust_level_info['potential_issues'].append({
                                        'issue': 'sensitive_data_exposure',
                                        'trust_level': f'TL{tl}',
                                        'exposed_fields': exposed_fields,
                                        'severity': 'high'
                                    })
                except json.JSONDecodeError:
                    pass
            
            time.sleep(0.02)
        
        # Analyze trust level patterns
        if trust_level_info['trust_level_distribution']:
            # Check for unusual trust level distributions
            total_users = sum(len(users) for users in trust_level_info['trust_level_distribution'].values())
            
            for tl, users in trust_level_info['trust_level_distribution'].items():
                percentage = (len(users) / total_users) * 100
                
                # Flag unusual patterns
                if tl == 4 and percentage > 10:  # Too many TL4 users
                    trust_level_info['potential_issues'].append({
                        'issue': 'excessive_high_trust_users',
                        'trust_level': f'TL{tl}',
                        'percentage': percentage,
                        'severity': 'medium'
                    })
                elif tl == 0 and percentage > 80:  # Too many new users
                    trust_level_info['potential_issues'].append({
                        'issue': 'high_new_user_ratio',
                        'trust_level': f'TL{tl}',
                        'percentage': percentage,
                        'severity': 'low'
                    })
        
        self.results['trust_level_analysis'] = trust_level_info
        self.scanner.log(f"Trust level analysis completed. Found levels: {trust_level_info['trust_levels_found']}", 'info')
    
    def _detect_badge_system(self):
        """Detect and analyze Discourse badge system"""
        self.scanner.log("Analyzing Discourse badge system...", 'debug')
        
        badge_info = {
            'badges_found': [],
            'badge_categories': {},
            'user_badges': {},
            'potential_issues': []
        }
        
        # Check badges endpoint
        badges_url = urljoin(self.scanner.target_url, '/badges.json')
        response = self.scanner.make_request(badges_url)
        
        if response and response.status_code == 200:
            try:
                data = response.json()
                
                if 'badges' in data:
                    for badge in data['badges']:
                        badge_data = {
                            'id': badge.get('id'),
                            'name': badge.get('name'),
                            'description': badge.get('description'),
                            'badge_type_id': badge.get('badge_type_id'),
                            'grant_count': badge.get('grant_count', 0),
                            'allow_title': badge.get('allow_title', False),
                            'multiple_grant': badge.get('multiple_grant', False),
                            'listable': badge.get('listable', True),
                            'enabled': badge.get('enabled', True),
                            'auto_revoke': badge.get('auto_revoke', True),
                            'target_posts': badge.get('target_posts', False),
                            'show_posts': badge.get('show_posts', False),
                            'trigger': badge.get('trigger'),
                            'badge_grouping_id': badge.get('badge_grouping_id'),
                            'system': badge.get('system', False)
                        }
                        
                        badge_info['badges_found'].append(badge_data)
                        
                        # Categorize badges
                        badge_type = badge.get('badge_type_id', 'unknown')
                        if badge_type not in badge_info['badge_categories']:
                            badge_info['badge_categories'][badge_type] = []
                        badge_info['badge_categories'][badge_type].append(badge_data)
                        
                        # Check for potential security issues
                        if badge.get('allow_title') and not badge.get('system'):
                            badge_info['potential_issues'].append({
                                'issue': 'custom_title_badge',
                                'badge_name': badge.get('name'),
                                'badge_id': badge.get('id'),
                                'severity': 'low',
                                'description': 'Non-system badge allows custom titles'
                            })
                        
                        if badge.get('multiple_grant') and badge.get('grant_count', 0) > 1000:
                            badge_info['potential_issues'].append({
                                'issue': 'excessive_badge_grants',
                                'badge_name': badge.get('name'),
                                'badge_id': badge.get('id'),
                                'grant_count': badge.get('grant_count'),
                                'severity': 'low',
                                'description': 'Badge has been granted excessively'
                            })
                
                # Check badge groupings
                if 'badge_groupings' in data:
                    badge_info['badge_groupings'] = data['badge_groupings']
                
                # Check badge types
                if 'badge_types' in data:
                    badge_info['badge_types'] = data['badge_types']
                    
            except json.JSONDecodeError:
                pass
        
        # Check user badges for discovered users
        for user_info in self.results.get('user_enumeration', []):
            username = user_info.get('username')
            if username:
                user_badges_url = urljoin(self.scanner.target_url, f'/user_badges/{username}.json')
                response = self.scanner.make_request(user_badges_url)
                
                if response and response.status_code == 200:
                    try:
                        data = response.json()
                        if 'user_badges' in data:
                            badge_info['user_badges'][username] = data['user_badges']
                            
                            # Check for unusual badge patterns
                            badge_count = len(data['user_badges'])
                            if badge_count > 50:  # User has many badges
                                badge_info['potential_issues'].append({
                                    'issue': 'user_excessive_badges',
                                    'username': username,
                                    'badge_count': badge_count,
                                    'severity': 'low',
                                    'description': f'User {username} has {badge_count} badges'
                                })
                    except json.JSONDecodeError:
                        pass
                
                time.sleep(0.02)
        
        # Analyze badge statistics
        if badge_info['badges_found']:
            total_badges = len(badge_info['badges_found'])
            system_badges = len([b for b in badge_info['badges_found'] if b.get('system')])
            custom_badges = total_badges - system_badges
            
            badge_info['statistics'] = {
                'total_badges': total_badges,
                'system_badges': system_badges,
                'custom_badges': custom_badges,
                'title_badges': len([b for b in badge_info['badges_found'] if b.get('allow_title')]),
                'multiple_grant_badges': len([b for b in badge_info['badges_found'] if b.get('multiple_grant')])
            }
            
            self.scanner.log(f"Badge analysis completed. Found {total_badges} badges ({system_badges} system, {custom_badges} custom)", 'info')
        
        self.results['badge_analysis'] = badge_info
        
        # Test login enumeration
        self._test_login_enumeration(common_usernames)
        
        # Test forgot password enumeration
        self._test_forgot_password_enumeration(common_usernames)
        
        self.results['user_enumeration'] = valid_users
        self.discovered_users = [user['username'] for user in valid_users]
        
        # Log total users found
        self.scanner.log(f"Total users discovered: {len(self.discovered_users)}", 'info')
        if self.discovered_users:
            self.scanner.log(f"Discovered users: {', '.join(self.discovered_users)}", 'info')
    
    def _discover_users_from_public_endpoints(self):
        """Discover users from public API endpoints"""
        self.scanner.log("Discovering users from public endpoints...", 'debug')
        
        # Try to get users from various public endpoints
        public_endpoints = [
            '/users.json',
            '/directory_items.json',
            '/directory_items.json?period=all&order=post_count',
            '/directory_items.json?period=all&order=likes_received',
            '/directory_items.json?period=all&order=likes_given',
            '/directory_items.json?period=all&order=topics_entered',
            '/directory_items.json?period=all&order=posts_read',
            '/directory_items.json?period=all&order=days_visited',
            '/about.json',
            '/site.json',
            '/groups.json',
            '/badges.json',
            '/user_badges.json'
        ]
        
        for endpoint in public_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    users_found = self._extract_users_from_json(data, endpoint)
                    if users_found:
                        self.scanner.log(f"Found {len(users_found)} users from {endpoint}", 'success')
                        for user in users_found:
                            if user not in self.discovered_users:
                                self.discovered_users.append(user)
                except json.JSONDecodeError:
                    pass
            
            time.sleep(0.02)
    
    def _discover_users_from_directory(self):
        """Discover users from directory pages and /u/ endpoint"""
        self.scanner.log("Discovering users from directory pages...", 'debug')
        
        # Try different directory pages
        directory_pages = [
            '/u',
            '/users',
            '/directory',
            '/directory?period=all',
            '/directory?order=post_count',
            '/directory?order=likes_received',
            '/directory?order=likes_given',
            '/directory?order=topics_entered'
        ]
        
        for page in directory_pages:
            url = urljoin(self.scanner.target_url, page)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                users_found = self._extract_users_from_html(response.text)
                if users_found:
                    self.scanner.log(f"Found {len(users_found)} users from {page}", 'success')
                    for user in users_found:
                        if user not in self.discovered_users:
                            self.discovered_users.append(user)
            
            time.sleep(0.02)
        
        # Special method to discover users from /u/ endpoint with ID enumeration
        self._discover_users_from_u_endpoint()
    
    def _discover_users_from_u_endpoint(self):
        """Discover users from /u/ endpoint by ID enumeration"""
        self.scanner.log("Discovering users from /u/ endpoint with ID enumeration...", 'debug')
        
        # Try to enumerate users by ID from /u/ endpoint
        # Start with low IDs and check for patterns
        user_ids_to_check = list(range(1, 201))  # Check first 200 IDs
        user_ids_to_check.extend([250, 300, 400, 500, 750, 1000, 1337, 1500, 2000, 2500, 3000, 4000, 5000, 7500, 10000])  # Add some common IDs
        
        # Add random IDs for comprehensive scanning
        import random
        user_ids_to_check.extend(random.sample(range(201, 1000), 50))  # 50 random IDs between 201-1000
        user_ids_to_check.extend(random.sample(range(1001, 5000), 25))  # 25 random IDs between 1001-5000
        user_ids_to_check.extend(random.sample(range(5001, 10000), 10))  # 10 random IDs between 5001-10000
        
        # Sort the list to check in order
        user_ids_to_check = sorted(list(set(user_ids_to_check)))
        
        found_users_count = 0
        
        for user_id in user_ids_to_check:
            # Try different /u/ endpoint patterns
            u_endpoints = [
                f'/u/by-external/{user_id}',
                f'/u/{user_id}',
                f'/users/{user_id}',
                f'/users/{user_id}.json'
            ]
            
            for endpoint in u_endpoints:
                url = urljoin(self.scanner.target_url, endpoint)
                response = self.scanner.make_request(url)
                
                if response and response.status_code == 200:
                    try:
                        if endpoint.endswith('.json'):
                            # JSON response
                            data = response.json()
                            if 'user' in data:
                                user_data = data['user']
                                username = user_data.get('username')
                                if username and username not in self.discovered_users:
                                    # Create detailed user info
                                    detailed_user = {
                                        'username': username,
                                        'id': user_data.get('id'),
                                        'name': user_data.get('name'),
                                        'avatar_template': user_data.get('avatar_template'),
                                        'trust_level': user_data.get('trust_level'),
                                        'last_seen': user_data.get('last_seen_at'),
                                        'last_posted': user_data.get('last_posted_at'),
                                        'post_count': user_data.get('post_count'),
                                        'topic_count': user_data.get('topic_count'),
                                        'likes_given': user_data.get('likes_given'),
                                        'likes_received': user_data.get('likes_received'),
                                        'days_visited': user_data.get('days_visited'),
                                        'posts_read_count': user_data.get('posts_read_count'),
                                        'topics_entered': user_data.get('topics_entered'),
                                        'time_read': user_data.get('time_read'),
                                        'primary_group_name': user_data.get('primary_group_name'),
                                        'bio_raw': user_data.get('bio_raw'),
                                        'website': user_data.get('website'),
                                        'location': user_data.get('location'),
                                        'groups': user_data.get('groups', []),
                                        'featured_user_badge_ids': user_data.get('featured_user_badge_ids', []),
                                        'custom_fields': user_data.get('custom_fields', {}),
                                        'user_fields': user_data.get('user_fields', {}),
                                        'email': user_data.get('email'),
                                        'secondary_emails': user_data.get('secondary_emails', []),
                                        'associated_accounts': user_data.get('associated_accounts', []),
                                        'timezone': user_data.get('timezone'),
                                        'discovery_method': 'id_enumeration',
                                        'discovery_endpoint': endpoint
                                    }
                                    
                                    # Extract avatar URLs if available
                                    if user_data.get('avatar_template'):
                                        avatar_template = user_data['avatar_template']
                                        detailed_user['avatar_urls'] = {
                                            'small': avatar_template.replace('{size}', '25'),
                                            'medium': avatar_template.replace('{size}', '45'),
                                            'large': avatar_template.replace('{size}', '120'),
                                            'extra_large': avatar_template.replace('{size}', '240')
                                        }
                                    
                                    # Add to results
                                    self.results['user_enumeration'].append(detailed_user)
                                    self.discovered_users.append(username)
                                    found_users_count += 1
                                    self.scanner.log(f"Found user via /u/ ID {user_id}: {username} (ID: {user_data.get('id')})", 'success')
                                    break
                        else:
                            # HTML response - extract username from page
                            users_found = self._extract_users_from_html(response.text)
                            for username in users_found:
                                if username not in self.discovered_users:
                                    self.discovered_users.append(username)
                                    found_users_count += 1
                                    self.scanner.log(f"Found user via /u/ ID {user_id}: {username}", 'success')
                            if users_found:
                                break
                    except (json.JSONDecodeError, KeyError):
                        # Try to extract from HTML even if JSON parsing fails
                        users_found = self._extract_users_from_html(response.text)
                        for username in users_found:
                            if username not in self.discovered_users:
                                self.discovered_users.append(username)
                                found_users_count += 1
                                self.scanner.log(f"Found user via /u/ ID {user_id}: {username}", 'success')
                        if users_found:
                            break
                
                time.sleep(0.05)  # Small delay between requests
            
            # If we found many users, continue with more IDs
            if found_users_count > 20 and user_id < 100:
                # Extend the range if we're finding many users
                additional_ids = list(range(user_id + 1, min(user_id + 50, 500)))
                user_ids_to_check.extend(additional_ids)
        
        if found_users_count > 0:
            self.scanner.log(f"Total users found via /u/ endpoint: {found_users_count}", 'info')
    
    def _discover_users_from_search(self):
        """Discover users from search functionality"""
        self.scanner.log("Discovering users from search...", 'debug')
        
        # Try to search for users using common search terms
        search_terms = ['a', 'e', 'i', 'o', 'u', 'admin', 'user', 'test', 'mod']
        
        for term in search_terms:
            # Try user search endpoint
            search_url = urljoin(self.scanner.target_url, f'/u/search/users?term={term}')
            response = self.scanner.make_request(search_url)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if 'users' in data:
                        for user_data in data['users']:
                            username = user_data.get('username')
                            if username and username not in self.discovered_users:
                                self.discovered_users.append(username)
                                self.scanner.log(f"Found user via search: {username}", 'success')
                except json.JSONDecodeError:
                    pass
            
            time.sleep(0.05)
    
    def _extract_users_from_json(self, data, endpoint):
        """Extract usernames from JSON data"""
        users = []
        
        # Handle different JSON structures
        if isinstance(data, dict):
            # Check for users array
            if 'users' in data:
                for user in data['users']:
                    if isinstance(user, dict) and 'username' in user:
                        users.append(user['username'])
            
            # Check for directory_items
            if 'directory_items' in data:
                for item in data['directory_items']:
                    if isinstance(item, dict) and 'user' in item:
                        user_data = item['user']
                        if isinstance(user_data, dict) and 'username' in user_data:
                            users.append(user_data['username'])
            
            # Check for moderators/admins in about.json
            if 'about' in data:
                about_data = data['about']
                if 'moderators' in about_data:
                    for mod in about_data['moderators']:
                        if isinstance(mod, dict) and 'username' in mod:
                            users.append(mod['username'])
                if 'admins' in about_data:
                    for admin in about_data['admins']:
                        if isinstance(admin, dict) and 'username' in admin:
                            users.append(admin['username'])
            
            # Check for groups with members
            if 'groups' in data:
                for group in data['groups']:
                    if isinstance(group, dict) and 'members' in group:
                        for member in group['members']:
                            if isinstance(member, dict) and 'username' in member:
                                users.append(member['username'])
            
            # Check for badge holders
            if 'user_badges' in data:
                for badge in data['user_badges']:
                    if isinstance(badge, dict) and 'user' in badge:
                        user_data = badge['user']
                        if isinstance(user_data, dict) and 'username' in user_data:
                            users.append(user_data['username'])
        
        return list(set(users))  # Remove duplicates
    
    def _extract_users_from_html(self, html_content):
        """Extract usernames from HTML content"""
        users = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Look for user links
            user_links = soup.find_all('a', href=re.compile(r'/u/[^/]+/?$'))
            for link in user_links:
                href = link.get('href')
                if href:
                    username = href.split('/u/')[-1].rstrip('/')
                    if username and username not in users:
                        users.append(username)
            
            # Look for username patterns in text
            username_pattern = r'@([a-zA-Z0-9_-]+)'
            matches = re.findall(username_pattern, html_content)
            for match in matches:
                if match not in users:
                    users.append(match)
            
            # Look for data attributes with usernames
            elements_with_username = soup.find_all(attrs={'data-username': True})
            for element in elements_with_username:
                username = element.get('data-username')
                if username and username not in users:
                    users.append(username)
        
        except Exception as e:
            self.scanner.log(f"Error parsing HTML for users: {e}", 'debug')
        
        return users
    
    def _test_login_enumeration(self, usernames):
        """Test user enumeration via login responses"""
        self.scanner.log("Testing login enumeration...", 'debug')
        
        login_url = urljoin(self.scanner.target_url, '/session')
        
        # Get CSRF token first
        login_page = self.scanner.make_request(urljoin(self.scanner.target_url, '/login'))
        csrf_token = None
        if login_page:
            csrf_token = extract_csrf_token(login_page.text)
        
        for username in usernames[:5]:  # Limit to avoid too many requests
            login_data = {
                'login': username,
                'password': 'invalid_password_12345',
            }
            
            if csrf_token:
                login_data['authenticity_token'] = csrf_token
            
            response = self.scanner.make_request(login_url, method='POST', data=login_data)
            
            if response:
                # Analyze response for enumeration indicators
                response_text = response.text.lower()
                
                if 'invalid username' in response_text or 'user not found' in response_text:
                    # Username doesn't exist
                    pass
                elif 'invalid password' in response_text or 'incorrect password' in response_text:
                    # Username exists, password wrong
                    enum_result = {
                        'username': username,
                        'method': 'login_response',
                        'status': 'exists',
                        'indicator': 'password_error_message'
                    }
                    self.results['user_enumeration'].append(enum_result)
                    self.scanner.log(f"User enumerated via login: {username}", 'warning')
            
            self.results['tests_performed'] += 1
            time.sleep(0.5)  # Longer delay for login attempts
    
    def _test_forgot_password_enumeration(self, usernames):
        """Test user enumeration via forgot password responses"""
        self.scanner.log("Testing forgot password enumeration...", 'debug')
        
        forgot_url = urljoin(self.scanner.target_url, '/session/forgot_password')
        
        # Get CSRF token
        forgot_page = self.scanner.make_request(urljoin(self.scanner.target_url, '/password-reset'))
        csrf_token = None
        if forgot_page:
            csrf_token = extract_csrf_token(forgot_page.text)
        
        for username in usernames[:3]:  # Very limited to avoid spam
            forgot_data = {
                'login': username
            }
            
            if csrf_token:
                forgot_data['authenticity_token'] = csrf_token
            
            response = self.scanner.make_request(forgot_url, method='POST', data=forgot_data)
            
            if response:
                response_text = response.text.lower()
                
                # Look for different responses that might indicate user existence
                if 'email sent' in response_text or 'check your email' in response_text:
                    enum_result = {
                        'username': username,
                        'method': 'forgot_password',
                        'status': 'likely_exists',
                        'indicator': 'email_sent_message'
                    }
                    self.results['user_enumeration'].append(enum_result)
                    self.scanner.log(f"User likely exists (forgot password): {username}", 'info')
            
            self.results['tests_performed'] += 1
            time.sleep(1.0)  # Long delay for forgot password
    
    def _test_weak_passwords(self):
        """Test for weak passwords on discovered users"""
        self.scanner.log("Testing for weak passwords...", 'debug')
        
        if not self.discovered_users:
            return
        
        # Common weak passwords
        weak_passwords = [
            'password', '123456', 'admin', 'password123',
            'qwerty', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'shadow', 'football'
        ]
        
        # Add username-based passwords
        for user in self.discovered_users[:3]:  # Limit users
            weak_passwords.extend([
                user,
                user + '123',
                user + '2023',
                user + '2024',
                user.lower(),
                user.upper()
            ])
        
        login_url = urljoin(self.scanner.target_url, '/session')
        
        for username in self.discovered_users[:2]:  # Very limited
            for password in weak_passwords[:10]:  # Limited passwords
                
                # Get fresh CSRF token
                login_page = self.scanner.make_request(urljoin(self.scanner.target_url, '/login'))
                csrf_token = None
                if login_page:
                    csrf_token = extract_csrf_token(login_page.text)
                
                login_data = {
                    'login': username,
                    'password': password
                }
                
                if csrf_token:
                    login_data['authenticity_token'] = csrf_token
                
                response = self.scanner.make_request(login_url, method='POST', data=login_data)
                
                if response:
                    # Check for successful login indicators
                    if (response.status_code == 200 and 
                        ('dashboard' in response.text.lower() or 
                         'logout' in response.text.lower() or
                         'welcome' in response.text.lower())):
                        
                        weak_pass_result = {
                            'username': username,
                            'password': password,
                            'severity': 'critical',
                            'description': f'Weak password found for user {username}'
                        }
                        self.results['weak_passwords'].append(weak_pass_result)
                        self.scanner.log(f"Weak password found: {username}:{password}", 'error')
                        break  # Stop testing this user
                
                self.results['tests_performed'] += 1
                time.sleep(2.0)  # Long delay between login attempts
    
    def _test_brute_force_protection(self):
        """Test brute force protection mechanisms"""
        self.scanner.log("Testing brute force protection...", 'debug')
        
        if not self.discovered_users:
            return
        
        login_url = urljoin(self.scanner.target_url, '/session')
        test_user = self.discovered_users[0] if self.discovered_users else 'admin'
        
        # Perform multiple failed login attempts
        failed_attempts = 0
        max_attempts = 5  # Limited to avoid actual brute force
        
        for attempt in range(max_attempts):
            # Get CSRF token
            login_page = self.scanner.make_request(urljoin(self.scanner.target_url, '/login'))
            csrf_token = None
            if login_page:
                csrf_token = extract_csrf_token(login_page.text)
            
            login_data = {
                'login': test_user,
                'password': f'invalid_password_{attempt}'
            }
            
            if csrf_token:
                login_data['authenticity_token'] = csrf_token
            
            start_time = time.time()
            response = self.scanner.make_request(login_url, method='POST', data=login_data)
            response_time = time.time() - start_time
            
            if response:
                if response.status_code == 429:
                    # Rate limiting detected
                    bf_result = {
                        'protection': 'rate_limiting',
                        'attempts_before_block': attempt + 1,
                        'status': 'protected',
                        'description': 'Rate limiting protection detected'
                    }
                    self.results['brute_force_results'].append(bf_result)
                    self.scanner.log("Brute force protection detected (rate limiting)", 'success')
                    break
                
                elif 'captcha' in response.text.lower():
                    # CAPTCHA protection
                    bf_result = {
                        'protection': 'captcha',
                        'attempts_before_captcha': attempt + 1,
                        'status': 'protected',
                        'description': 'CAPTCHA protection detected'
                    }
                    self.results['brute_force_results'].append(bf_result)
                    self.scanner.log("Brute force protection detected (CAPTCHA)", 'success')
                    break
                
                elif response_time > 3.0:
                    # Possible delay-based protection
                    bf_result = {
                        'protection': 'delay_based',
                        'response_time': response_time,
                        'status': 'possible_protection',
                        'description': f'Slow response detected ({response_time:.2f}s)'
                    }
                    self.results['brute_force_results'].append(bf_result)
                
                failed_attempts += 1
            
            self.results['tests_performed'] += 1
            time.sleep(1.0)
        
        # If no protection detected after max attempts
        if failed_attempts == max_attempts:
            bf_result = {
                'protection': 'none_detected',
                'attempts_tested': max_attempts,
                'status': 'vulnerable',
                'severity': 'medium',
                'description': 'No brute force protection detected in limited testing'
            }
            self.results['brute_force_results'].append(bf_result)
            self.scanner.log("No brute force protection detected", 'warning')
    
    def _test_session_management(self):
        """Test session management security"""
        self.scanner.log("Testing session management...", 'debug')
        
        # Test session fixation
        session_url = urljoin(self.scanner.target_url, '/session')
        
        # Get initial session
        response1 = self.scanner.make_request(self.scanner.target_url)
        if response1:
            initial_cookies = response1.cookies
            
            # Attempt login (will fail but might change session)
            login_data = {
                'login': 'testuser',
                'password': 'testpass'
            }
            
            response2 = self.scanner.make_request(session_url, method='POST', 
                                                data=login_data, cookies=initial_cookies)
            
            if response2:
                final_cookies = response2.cookies
                
                # Check if session ID changed
                session_changed = False
                for cookie_name in initial_cookies.keys():
                    if (cookie_name in final_cookies and 
                        initial_cookies[cookie_name] != final_cookies[cookie_name]):
                        session_changed = True
                        break
                
                if not session_changed:
                    session_issue = {
                        'issue': 'session_fixation_possible',
                        'severity': 'medium',
                        'description': 'Session ID does not change after login attempt'
                    }
                    self.results['session_issues'].append(session_issue)
                    self.scanner.log("Possible session fixation vulnerability", 'warning')
        
        # Test session cookie security
        response = self.scanner.make_request(self.scanner.target_url)
        if response:
            for cookie_name, cookie_value in response.cookies.items():
                cookie_obj = response.cookies.get(cookie_name)
                
                issues = []
                if not cookie_obj.secure:
                    issues.append('not_secure')
                if not cookie_obj.get('httponly'):
                    issues.append('not_httponly')
                if not cookie_obj.get('samesite'):
                    issues.append('no_samesite')
                
                if issues:
                    session_issue = {
                        'issue': 'insecure_cookie_attributes',
                        'cookie_name': cookie_name,
                        'problems': issues,
                        'severity': 'low',
                        'description': f'Cookie {cookie_name} has security issues: {issues}'
                    }
                    self.results['session_issues'].append(session_issue)
        
        self.results['tests_performed'] += 1
    
    def _test_password_reset_flaws(self):
        """Test password reset functionality for flaws"""
        self.scanner.log("Testing password reset flaws...", 'debug')
        
        # Test password reset token in URL
        reset_endpoints = [
            '/password-reset',
            '/users/password/new',
            '/session/forgot_password'
        ]
        
        for endpoint in reset_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            response = self.scanner.make_request(url)
            
            if response and response.status_code == 200:
                # Check if reset form is accessible
                if 'password' in response.text.lower() and 'reset' in response.text.lower():
                    # Look for potential issues in the form
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Check for token in URL parameters
                    if 'token=' in response.url or 'reset_token=' in response.url:
                        reset_issue = {
                            'issue': 'token_in_url',
                            'endpoint': endpoint,
                            'severity': 'medium',
                            'description': 'Password reset token exposed in URL'
                        }
                        self.results['password_reset_issues'].append(reset_issue)
                        self.scanner.log("Password reset token in URL detected", 'warning')
                    
                    # Check for missing CSRF protection
                    csrf_token = extract_csrf_token(response.text)
                    if not csrf_token:
                        reset_issue = {
                            'issue': 'missing_csrf_protection',
                            'endpoint': endpoint,
                            'severity': 'medium',
                            'description': 'Password reset form lacks CSRF protection'
                        }
                        self.results['password_reset_issues'].append(reset_issue)
            
            self.results['tests_performed'] += 1
            time.sleep(0.1)
    
    def _test_registration_flaws(self):
        """Test user registration for security flaws"""
        self.scanner.log("Testing registration flaws...", 'debug')
        
        signup_url = urljoin(self.scanner.target_url, '/u')
        signup_page_url = urljoin(self.scanner.target_url, '/signup')
        
        # Check if registration is open
        response = self.scanner.make_request(signup_page_url)
        
        if response and response.status_code == 200:
            if 'signup' in response.text.lower() or 'register' in response.text.lower():
                # Registration appears to be available
                
                # Test for missing CSRF protection
                csrf_token = extract_csrf_token(response.text)
                if not csrf_token:
                    reg_issue = {
                        'issue': 'missing_csrf_protection',
                        'severity': 'medium',
                        'description': 'Registration form lacks CSRF protection'
                    }
                    self.results['registration_issues'].append(reg_issue)
                
                # Test for weak username validation
                test_usernames = ['admin2', 'administrator2', 'root2', 'test123']
                
                for username in test_usernames[:2]:  # Limited testing
                    reg_data = {
                        'username': username,
                        'email': f'{username}@example.com',
                        'password': 'TestPassword123!'
                    }
                    
                    if csrf_token:
                        reg_data['authenticity_token'] = csrf_token
                    
                    reg_response = self.scanner.make_request(signup_url, method='POST', data=reg_data)
                    
                    if reg_response:
                        if reg_response.status_code == 200 and 'success' in reg_response.text.lower():
                            reg_issue = {
                                'issue': 'weak_username_validation',
                                'username': username,
                                'severity': 'low',
                                'description': f'Potentially sensitive username {username} allowed'
                            }
                            self.results['registration_issues'].append(reg_issue)
                    
                    self.results['tests_performed'] += 1
                    time.sleep(1.0)
        
        self.results['tests_performed'] += 1
    
    def _test_privilege_escalation(self):
        """Test for privilege escalation vulnerabilities"""
        self.scanner.log("Testing privilege escalation...", 'debug')
        
        # Test parameter manipulation for privilege escalation
        admin_endpoints = [
            '/admin/users',
            '/admin/dashboard',
            '/admin/site_settings'
        ]
        
        # Test with various privilege escalation parameters
        escalation_params = {
            'admin': 'true',
            'is_admin': '1',
            'role': 'admin',
            'trust_level': '4',
            'moderator': 'true',
            'staff': 'true'
        }
        
        for endpoint in admin_endpoints:
            url = urljoin(self.scanner.target_url, endpoint)
            
            # Test direct access first
            response = self.scanner.make_request(url)
            if response and response.status_code == 200:
                # Already accessible - not a privilege escalation issue
                continue
            
            # Test with escalation parameters
            for param, value in escalation_params.items():
                test_url = f"{url}?{param}={value}"
                response = self.scanner.make_request(test_url)
                
                if response and response.status_code == 200:
                    if 'admin' in response.text.lower() or 'dashboard' in response.text.lower():
                        priv_issue = {
                            'issue': 'parameter_based_privilege_escalation',
                            'endpoint': endpoint,
                            'parameter': f'{param}={value}',
                            'severity': 'critical',
                            'description': f'Privilege escalation via {param} parameter'
                        }
                        self.results['privilege_escalation'].append(priv_issue)
                        self.scanner.log(f"Privilege escalation found: {param}={value}", 'error')
                
                self.results['tests_performed'] += 1
                time.sleep(0.1)