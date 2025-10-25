#!/usr/bin/env python3
"""
CLI Module

Command line interface components for DiscourseMap.
"""

from .argument_parser import parse_arguments, apply_performance_presets
from .config_loader import load_config, load_resume_data, apply_config_to_args
from .updater import handle_update
from .utils import (
    save_partial_results, print_scan_config, print_preset_info,
    determine_modules_to_run, handle_graceful_shutdown, merge_resume_data
)

__all__ = [
    'parse_arguments', 'apply_performance_presets',
    'load_config', 'load_resume_data', 'apply_config_to_args',
    'handle_update',
    'save_partial_results', 'print_scan_config', 'print_preset_info',
    'determine_modules_to_run', 'handle_graceful_shutdown', 'merge_resume_data'
]