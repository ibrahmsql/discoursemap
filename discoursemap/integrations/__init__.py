#!/usr/bin/env python3
"""
Integrations Module

External system integrations for DiscourseMap.
"""

from .webhook_sender import WebhookSender
from .slack_notifier import SlackNotifier

__all__ = [
    'WebhookSender',
    'SlackNotifier'
]