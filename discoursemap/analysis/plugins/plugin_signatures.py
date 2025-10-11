#!/usr/bin/env python3
"""
Discourse Plugin Signatures Database

Contains fingerprints and detection patterns for Discourse plugins.
"""

def get_plugin_signatures():
    """
    Provide signatures used to detect Discourse plugins.
    
    Each signature value is a dictionary with the following keys:
    - paths: list of path patterns where the plugin may be hosted
    - markers: list of textual markers used to identify the plugin in content
    - files: list of specific file paths associated with the plugin
    - category: categorical classification (e.g., 'core', 'community', 'spam-protection', 'formatting')
    - risk_level: assigned risk level (e.g., 'low', 'medium')
    
    Returns:
        dict: Mapping of plugin identifier (e.g., 'discourse-poll') to its signature dictionary.
    """
    return {
        # Core Discourse Plugins
        'discourse-poll': {
            'paths': ['/plugins/poll/', '/assets/plugins/poll/'],
            'markers': ['discourse-poll', 'data-poll-', 'poll-container'],
            'files': ['/assets/plugins/poll.js'],
            'category': 'core',
            'risk_level': 'low'
        },
        'discourse-details': {
            'paths': ['/plugins/details/'],
            'markers': ['discourse-details', 'details-summary'],
            'files': ['/assets/plugins/details.js'],
            'category': 'core',
            'risk_level': 'low'
        },
        'discourse-solved': {
            'paths': ['/plugins/discourse-solved/'],
            'markers': ['discourse-solved', 'solved-indicator'],
            'files': ['/assets/plugins/discourse-solved.js'],
            'category': 'community',
            'risk_level': 'medium'
        },
        'discourse-akismet': {
            'paths': ['/plugins/discourse-akismet/'],
            'markers': ['discourse-akismet', 'akismet-'],
            'files': ['/assets/plugins/discourse-akismet.js'],
            'category': 'spam-protection',
            'risk_level': 'low'
        },
        'discourse-spoiler-alert': {
            'paths': ['/plugins/discourse-spoiler-alert/'],
            'markers': ['spoiler-alert', 'spoiled'],
            'files': ['/assets/plugins/discourse-spoiler-alert.js'],
            'category': 'formatting',
            'risk_level': 'low'
        },
        # Add 50+ more signatures...
    }

def get_technology_patterns():
    """
    Provide detection patterns and metadata for common front-end technologies.
    
    Returns:
        dict: Mapping of technology name to detection details. Each value is a dict that may contain:
            - js_patterns (list[str]): String patterns or regexes used to detect the technology in JavaScript.
            - css_patterns (list[str]): String patterns or regexes used to detect the technology in CSS.
            - files (list[str]): File paths commonly associated with the technology.
            - category (str): Classification such as 'javascript-library', 'javascript-framework', 'template-engine',
              'css-framework', 'icon-font', or 'date-library'.
    """
    return {
        'jQuery': {
            'js_patterns': [r'jQuery', r'\$\.fn\.jquery'],
            'files': ['/assets/jquery.js', '/javascripts/jquery.js'],
            'category': 'javascript-library'
        },
        'Ember.js': {
            'js_patterns': [r'Ember', r'Ember\.Application'],
            'files': ['/assets/ember.js'],
            'category': 'javascript-framework'
        },
        'Handlebars': {
            'js_patterns': [r'Handlebars', r'Handlebars\.compile'],
            'files': ['/assets/handlebars.js'],
            'category': 'template-engine'
        },
        'Bootstrap': {
            'css_patterns': [r'bootstrap', r'btn-primary'],
            'files': ['/assets/bootstrap.css'],
            'category': 'css-framework'
        },
        'Font Awesome': {
            'css_patterns': [r'font-awesome', r'fa-'],
            'files': ['/assets/font-awesome.css'],
            'category': 'icon-font'
        },
        'Moment.js': {
            'js_patterns': [r'moment', r'moment\.js'],
            'files': ['/assets/moment.js'],
            'category': 'date-library'
        }
    }