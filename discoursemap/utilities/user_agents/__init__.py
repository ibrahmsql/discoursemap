#!/usr/bin/env python3
"""
User Agents Module

Provides user agent strings for different browsers and devices.
"""

import random
from .browser_agents import CHROME_AGENTS, FIREFOX_AGENTS, SAFARI_AGENTS, EDGE_AGENTS
from .mobile_agents import IPHONE_AGENTS, IPAD_AGENTS, ANDROID_AGENTS, KINDLE_AGENTS

# Combine all user agents
ALL_USER_AGENTS = (
    CHROME_AGENTS + 
    FIREFOX_AGENTS + 
    SAFARI_AGENTS + 
    EDGE_AGENTS + 
    IPHONE_AGENTS + 
    IPAD_AGENTS + 
    ANDROID_AGENTS + 
    KINDLE_AGENTS
)

def get_random_user_agent(agent_type: str = 'all') -> str:
    """
    Get a random user agent string.
    
    Args:
        agent_type: Type of agent ('all', 'chrome', 'firefox', 'safari', 'edge', 'mobile', 'desktop')
        
    Returns:
        Random user agent string
    """
    if agent_type == 'chrome':
        return random.choice(CHROME_AGENTS)
    elif agent_type == 'firefox':
        return random.choice(FIREFOX_AGENTS)
    elif agent_type == 'safari':
        return random.choice(SAFARI_AGENTS)
    elif agent_type == 'edge':
        return random.choice(EDGE_AGENTS)
    elif agent_type == 'mobile':
        mobile_agents = IPHONE_AGENTS + IPAD_AGENTS + ANDROID_AGENTS + KINDLE_AGENTS
        return random.choice(mobile_agents)
    elif agent_type == 'desktop':
        desktop_agents = CHROME_AGENTS + FIREFOX_AGENTS + SAFARI_AGENTS + EDGE_AGENTS
        return random.choice(desktop_agents)
    else:  # 'all' or any other value
        return random.choice(ALL_USER_AGENTS)

def get_user_agents_by_type(agent_type: str) -> list:
    """
    Get all user agents of a specific type.
    
    Args:
        agent_type: Type of agent
        
    Returns:
        List of user agent strings
    """
    type_mapping = {
        'chrome': CHROME_AGENTS,
        'firefox': FIREFOX_AGENTS,
        'safari': SAFARI_AGENTS,
        'edge': EDGE_AGENTS,
        'iphone': IPHONE_AGENTS,
        'ipad': IPAD_AGENTS,
        'android': ANDROID_AGENTS,
        'kindle': KINDLE_AGENTS,
        'all': ALL_USER_AGENTS
    }
    
    return type_mapping.get(agent_type, ALL_USER_AGENTS)

# Backward compatibility
user_agents = ALL_USER_AGENTS
USER_AGENTS = ALL_USER_AGENTS  # For legacy imports

__all__ = [
    'ALL_USER_AGENTS',
    'USER_AGENTS',
    'get_random_user_agent',
    'get_user_agents_by_type',
    'user_agents'
]