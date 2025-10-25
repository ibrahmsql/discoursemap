#!/usr/bin/env python3
"""
Configuration Loader

Handles loading and processing of configuration files.
"""

import os
import json
import yaml
from colorama import Fore, Style


def load_config(config_file):
    """Load configuration from YAML file"""
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        return {}
    except (FileNotFoundError, PermissionError) as e:
        print(f"{Fore.YELLOW}[!] Warning: Could not access config file {config_file}: {e}{Style.RESET_ALL}")
        return {}
    except (yaml.YAMLError, json.JSONDecodeError) as e:
        print(f"{Fore.YELLOW}[!] Warning: Invalid config file format {config_file}: {e}{Style.RESET_ALL}")
        return {}
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Warning: Unexpected error loading config file {config_file}: {e}{Style.RESET_ALL}")
        return {}


def load_resume_data(resume_file):
    """Load resume data from JSON file"""
    try:
        with open(resume_file, 'r') as f:
            data = json.load(f)
            completed_modules = list(data.get('modules', {}).keys())
            return completed_modules, data
    except (FileNotFoundError, PermissionError) as e:
        print(f"{Fore.RED}[!] Error: Cannot access resume file {resume_file}: {e}{Style.RESET_ALL}")
        raise
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}[!] Error: Invalid JSON in resume file {resume_file}: {e}{Style.RESET_ALL}")
        raise
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error loading resume file {resume_file}: {e}{Style.RESET_ALL}")
        raise


def apply_config_to_args(args, config):
    """Apply configuration values to arguments"""
    if config and not args.quick:
        args.url = args.url or config.get('target', {}).get('url')
        args.threads = args.threads or config.get('threads', 5)
        args.timeout = args.timeout or config.get('timeout', 10)
        args.delay = args.delay or config.get('delay', 0.05)
        args.user_agent = args.user_agent or config.get('user_agent')
        args.proxy = args.proxy or config.get('proxy')
    elif config:
        # In quick mode, only apply URL and proxy from config if not provided
        args.url = args.url or config.get('target', {}).get('url')
        args.proxy = args.proxy or config.get('proxy')
    
    return args