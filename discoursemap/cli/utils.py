#!/usr/bin/env python3
"""
CLI Utilities

Utility functions for command line interface.
"""

import time
import json
from colorama import Fore, Style


def save_partial_results(results, filename=None):
    """Save partial scan results"""
    if not filename:
        filename = f"partial_scan_{int(time.time())}.json"
    
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        return filename
    except (IOError, OSError, PermissionError) as e:
        print(f"{Fore.RED}[!] File error saving partial results: {e}{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error saving partial results: {e}{Style.RESET_ALL}")
        return None


def print_scan_config(args):
    """Print scan configuration"""
    if not args.quiet:
        print(f"{Fore.CYAN}[*] Scan Configuration:{Style.RESET_ALL}")
        print(f"    Target: {args.url}")
        print(f"    Threads: {args.threads}")
        print(f"    User-Agent: {'Custom' if args.user_agent else 'Rotating'}")
        print(f"    Delay: {args.delay}s")
        print()


def print_preset_info(preset_name, performance_metrics, args):
    """Print performance preset information"""
    if preset_name:
        print(f"{Fore.CYAN}[*] Performance Preset: {preset_name}{Style.RESET_ALL}")
        if args.quick:
            print(f"{Fore.GREEN}[+] Quick scan modules: info, auth, api, vuln, waf_bypass{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Performance settings: {performance_metrics['threads']} threads, {performance_metrics['delay']}s delay, {performance_metrics['timeout']}s timeout{Style.RESET_ALL}")
        print()


def determine_modules_to_run(args, config, completed_modules=None):
    """Determine which modules to run"""
    if args.quick:
        # Quick scan mode - use predefined modules
        modules_to_run = ['info', 'auth', 'api', 'vuln', 'waf_bypass']
    elif args.modules:
        modules_to_run = args.modules
    elif config.get('modules'):
        modules_to_run = config['modules']
    else:
        modules_to_run = [
            'info', 'vuln', 'endpoint', 'user', 'cve', 'plugin_detection', 'plugin_bruteforce', 
            'api', 'auth', 'config', 'crypto', 'network', 'plugin', 'waf_bypass', 'compliance',
            'backup_scanner', 'passive_scanner', 'file_integrity'
        ]
    
    # Filter out completed modules if resuming
    if completed_modules:
        original_count = len(modules_to_run)
        modules_to_run = [m for m in modules_to_run if m not in completed_modules]
        skipped_count = original_count - len(modules_to_run)
        if skipped_count > 0:
            print(f"{Fore.YELLOW}[!] Skipping {skipped_count} completed modules{Style.RESET_ALL}")
        if not modules_to_run:
            print(f"{Fore.GREEN}[+] All modules already completed!{Style.RESET_ALL}")
            return None
    
    return modules_to_run


def handle_graceful_shutdown(scanner, start_time):
    """Handle graceful shutdown on KeyboardInterrupt"""
    end_time = time.time()
    duration = end_time - start_time
    print(f"\n{Fore.YELLOW}[!] Scan interrupted by user after {duration:.2f} seconds{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Performing graceful shutdown...{Style.RESET_ALL}")
    
    # Try to save partial results if available
    try:
        if hasattr(scanner, 'results'):
            print(f"{Fore.CYAN}[*] Saving partial scan results...{Style.RESET_ALL}")
            partial_file = save_partial_results(scanner.results)
            if partial_file:
                print(f"{Fore.GREEN}[+] Partial results saved: {partial_file}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Use --resume {partial_file} to continue scan{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Could not save partial results: {e}{Style.RESET_ALL}")


def merge_resume_data(results, resume_data):
    """Merge resume data with current results"""
    if resume_data:
        for module_name, module_results in resume_data.get('modules', {}).items():
            if module_name not in results.get('modules', {}):
                if 'modules' not in results:
                    results['modules'] = {}
                results['modules'][module_name] = module_results
    return results