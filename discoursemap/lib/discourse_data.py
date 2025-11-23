#!/usr/bin/env python3
"""
Discourse Data

Contains plugin outlets and official plugin information.
"""

PLUGIN_OUTLETS = [
    "about-after-admins",
    "about-after-description",
    "about-after-moderators",
    "above-footer",
    "above-main-container",
    "above-review-filters",
    "above-site-header",
    "above-static",
    "above-user-preferences",
    "above-user-profile",
    "admin-below-plugins-index",
    "admin-customize-themes-list-item",
    "admin-customize-themes-show-top",
    "admin-dashboard-bottom",
    "admin-dashboard-general-bottom",
    "admin-dashboard-general-top",
    "admin-dashboard-moderation-bottom",
    "admin-dashboard-moderation-top",
    "admin-dashboard-security-bottom",
    "admin-dashboard-security-top",
    "admin-dashboard-top",
    "admin-menu",
    "admin-user-details",
    "admin-users-list-icon",
    "admin-users-list-nav-after",
    "advanced-search-options-above",
    "advanced-search-options-below",
    "after-d-editor",
    "after-reviewable-flagged-post-body",
    "after-reviewable-post-user",
    "after-topic-footer-buttons",
    "after-topic-footer-main-buttons",
    "after-topic-list",
    "after-user-details",
    "after-user-info",
    "after-user-name",
    "before-backup-list",
    "before-composer-toggles",
    "before-create-topic-button",
    "before-group-container",
    "before-groups-index-container",
    "before-topic-list",
    "before-topic-progress",
    "below-badges-title",
    "below-categories-only",
    "below-footer",
    "below-site-header",
    "below-static",
    "bread-crumbs-right",
    "category-custom-security",
    "category-custom-settings",
    "category-email-in",
    "category-heading",
    "category-list-above-each-category",
    "category-navigation",
    "category-title-before",
    "composer-action-after",
    "composer-after-save-or-cancel",
    "composer-fields",
    "composer-fields-below",
    "composer-open",
    "create-account-after-modal-footer",
    "create-account-before-modal-body",
    "discovery-above",
    "discovery-below",
    "discovery-list-container-top",
    "downloader",
    "editor-preview",
    "edit-topic",
    "evil-trout",
    "full-page-search-below-search-info",
    "full-page-search-category",
    "group-activity-bottom",
    "group-details-after",
    "group-edit",
    "group-email-in",
    "group-index-box-after",
    "group-reports-nav-item",
    "groups-form-membership-below-automatic",
    "login-after-modal-footer",
    "login-before-modal-body",
    "post-revisions",
    "quote-button-after",
    "quote-share-buttons-after",
    "revision-user-details-after",
    "topic-above-footer-buttons",
    "topic-above-posts",
    "topic-above-post-stream",
    "topic-above-suggested",
    "topic-category",
    "topic-footer-main-buttons-before-create",
    "topic-title",
    "top-notices",
    "upload-actions",
    "user-card-after-metadata",
    "user-card-after-username",
    "user-card-avatar-flair",
    "user-card-before-badges",
    "user-card-location-and-website",
    "user-card-metadata",
    "user-card-post-names",
    "user-custom-controls",
    "user-custom-preferences",
    "user-location-and-website",
    "user-main-nav",
    "user-messages-nav",
    "user-post-names",
    "user-preferences-account",
    "user-preferences-apps",
    "user-preferences-categories",
    "user-preferences-desktop-notifications",
    "user-preferences-emails",
    "user-preferences-emails-pref-email-settings",
    "user-preferences-interface",
    "user-preferences-interface-top",
    "user-preferences-nav",
    "user-preferences-nav-under-interface",
    "user-preferences-notifications",
    "user-preferences-profile",
    "user-profile-avatar-flair",
    "user-profile-controls",
    "user-profile-primary",
    "user-profile-public-fields",
    "user-profile-secondary",
    "users-top",
    "user-stream-item-header",
    "user-summary-stat",
    "web-hook-fields"
]

OFFICIAL_PLUGINS = {
    "apple-login": {
        "name": "Sign in with Apple",
        "description": "Support user authentication via Sign in with Apple",
        "tier": "pro"
    },
    "ads": {
        "name": "Advertising",
        "description": "Display ads on your site using Google Adsense, Google Ad Manager, Amazon Affiliates, and more.",
        "tier": "pro"
    },
    "chat-integration": {
        "name": "Chat Integration",
        "description": "Send notifications about new topics and posts to your favorite chat provider.",
        "tier": "pro"
    },
    "patreon": {
        "name": "Patreon",
        "description": "Reward your patrons with Discourse access including group synchronization and Patreon Social Login.",
        "tier": "pro"
    },
    "solved": {
        "name": "Solved",
        "description": "Great answer? Solved allows users to accept solutions to their topics.",
        "tier": "pro"
    },
    "github": {
        "name": "GitHub",
        "description": "Assign badges to contributors, create permalinks, and create linkbacks for commits on GitHub",
        "tier": "pro"
    },
    "subscriptions": {
        "name": "Subscriptions",
        "description": "Sell recurring and one-time subscriptions that grant access to Discourse groups.",
        "tier": "pro"
    },
    "yearly-review": {
        "name": "Yearly Review",
        "description": "Create a topic summarizing the previous year's community activity",
        "tier": "pro"
    },
    "graphviz": {
        "name": "Graphviz",
        "description": "Build your own custom graphs within posts.",
        "tier": "pro"
    },
    "data-explorer": {
        "name": "Data Explorer",
        "description": "Run SQL queries against your database, allowing for instant stats reporting.",
        "tier": "business"
    },
    "oauth": {
        "name": "OAuth 2.0 & OpenID Connect Support",
        "description": "Support authentication with a custom external provider via OAuth 2.0 or OpenID Connect",
        "tier": "business"
    },
    "amazon-microsoft-login": {
        "name": "Amazon & Microsoft Logins",
        "description": "Support user authentication via Amazon or Microsoft.",
        "tier": "business"
    },
    "user-notes": {
        "name": "User Notes",
        "description": "Attach notes to users for all staff to see.",
        "tier": "business"
    },
    "topic-voting": {
        "name": "Topic Voting",
        "description": "Let your community vote on their favorite topics.",
        "tier": "business"
    },
    "assign": {
        "name": "Assign",
        "description": "Ensure topics are handled by assigning them to your staff.",
        "tier": "business"
    },
    "templates": {
        "name": "Templates",
        "description": "Create and save common replies for repeated use",
        "tier": "business"
    },
    "calendar": {
        "name": "Calendar",
        "description": "Create and update a dynamic event calendar within a topic.",
        "tier": "business"
    },
    "zendesk": {
        "name": "Zendesk",
        "description": "Integrate your community with Zendesk",
        "tier": "business"
    },
    "lti": {
        "name": "Learning Management System Integration",
        "description": "Allow Discourse to integrate with learning management systems",
        "tier": "business"
    },
    "automation": {
        "name": "Automation",
        "description": "Automate complex workflows with predefined scripts and triggers",
        "tier": "business"
    },
    "policy": {
        "name": "Discourse Policy",
        "description": "Create policies and require members to accept them.",
        "tier": "business"
    },
    "gamification": {
        "name": "Gamification",
        "description": "Add points and leaderboards to your community",
        "tier": "business"
    },
    "post-voting": {
        "name": "Post Voting",
        "description": "Upvote or downvote posts within various topics; see the most popular posts.",
        "tier": "business"
    },
    "doc-categories": {
        "name": "Doc Categories",
        "description": "Neatly organize your documentation within categories",
        "tier": "business"
    }
}
