#!/usr/bin/env python3
"""
DiscourseMap v2.1
Specialized Security Scanner for Discourse Forums Only

This tool is specifically designed for Discourse platform security assessment.
It is NOT a general-purpose web scanner and only works with Discourse forums.

Author: ibrahimsql
Version: 2.1
License: MIT

WARNING: This tool should only be used on authorized Discourse systems.
Unauthorized use is prohibited and may have legal consequences.
"""

import sys
import time
import asyncio
import traceback
import requests
from colorama import init, Fore, Style

from .core import DiscourseScanner, Reporter, Banner
from .lib.discourse_utils import validate_url, is_discourse_site
from .cli import (
    parse_arguments, apply_performance_presets,
    load_config, load_resume_data, apply_config_to_args,
    handle_update, save_partial_results, print_scan_config,
    print_preset_info, determine_modules_to_run,
    handle_graceful_shutdown, merge_resume_data
)

init(autoreset=False)




def main():
    """Main function"""
    print(Banner)
    start_time = time.time()
    
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Load configuration
        config = load_config(args.config)
        
        # Handle update mode
        if args.update:
            handle_update()
            return
        
        # Handle resume mode
        completed_modules = []
        resume_data = None
        if args.resume:
            print(f"{Fore.CYAN}[*] Resuming scan from: {args.resume}{Style.RESET_ALL}")
            try:
                completed_modules, resume_data = load_resume_data(args.resume)
                print(f"{Fore.GREEN}[+] Found {len(completed_modules)} completed modules{Style.RESET_ALL}")
            except Exception:
                sys.exit(1)
        
        # Handle performance presets and quick scan mode
        preset_name, performance_metrics = apply_performance_presets(args)
        print_preset_info(preset_name, performance_metrics, args)
        
        # Apply config defaults
        args = apply_config_to_args(args, config)
        
        # Check if URL is provided
        if not args.url:
            print(f"{Fore.RED}Error: Target URL is required. Provide via -u/--url or config file.{Style.RESET_ALL}")
            sys.exit(1)
        
        # URL validation
        if not validate_url(args.url):
            print(f"{Fore.RED}Error: Invalid URL format!{Style.RESET_ALL}")
            sys.exit(1)
        
        # Discourse site validation
        print(f"{Fore.CYAN}[*] Verifying target is a Discourse forum...{Style.RESET_ALL}")
        if not is_discourse_site(args.url, timeout=args.timeout, verify_ssl=not args.skip_ssl_verify):
            print(f"{Fore.RED}[!] Error: Target is not a Discourse forum!{Style.RESET_ALL}")
            print(f"{Fore.RED}[!] This tool is specifically designed for Discourse forums only.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Please ensure the target URL points to a valid Discourse installation.{Style.RESET_ALL}")
            sys.exit(1)
        else:
            print(f"{Fore.GREEN}[+] Target confirmed as Discourse forum{Style.RESET_ALL}")

        # Initialize scanner
        scanner = DiscourseScanner(
            target_url=args.url,
            threads=args.threads,
            timeout=args.timeout,
            proxy=args.proxy,
            user_agent=args.user_agent,
            delay=args.delay,
            verify_ssl=not args.skip_ssl_verify,
            verbose=args.verbose,
            quiet=args.quiet,
            config_file=args.config
        )
        
        # Show scan configuration
        print_scan_config(args)
        
        # Determine modules to run
        modules_to_run = determine_modules_to_run(args, config, completed_modules)
        if modules_to_run is None:
            return
        
        # Start scan (async by default, sync only if --sync flag is used)
        if getattr(args, 'sync', False):
            print(f"{Fore.CYAN}[*] Running synchronous scan mode...{Style.RESET_ALL}")
            results = scanner.run_scan(modules_to_run)
        else:
            print(f"{Fore.CYAN}[*] Running async scan mode...{Style.RESET_ALL}")
            results = asyncio.run(scanner.run_async_scan(modules_to_run))
        
        # Merge with resume data if available
        results = merge_resume_data(results, resume_data)
        
        # Save final results
        final_results_file = save_partial_results(results, f"final_scan_{int(time.time())}.json")
        if final_results_file:
            print(f"{Fore.GREEN}[+] Final results saved: {final_results_file}{Style.RESET_ALL}")
        
        # Calculate scan duration
        end_time = time.time()
        duration = end_time - start_time
        
        # Generate report
        if args.output:
            output_file = args.output_file or f"discourse_scan_report.{args.output}"
            
            if args.output == 'json':
                scanner.reporter.generate_json_report(results, output_file)
            elif args.output == 'html':
                scanner.reporter.generate_html_report(results, output_file)
            elif args.output == 'csv':
                scanner.reporter.generate_csv_report(results, output_file)
            
            print(f"{Fore.GREEN}[+] Report saved: {output_file}{Style.RESET_ALL}")
        
        # Show completion with duration
        print(f"{Fore.GREEN}[+] Scan completed in {duration:.2f} seconds!{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        handle_graceful_shutdown(scanner if 'scanner' in locals() else None, start_time)
        sys.exit(0)
    except (ConnectionError, TimeoutError, requests.RequestException) as e:
        end_time = time.time()
        duration = end_time - start_time
        print(f"{Fore.RED}[!] Network error after {duration:.2f} seconds: {str(e)}{Style.RESET_ALL}")
        if args.verbose if 'args' in locals() else False:
            traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        end_time = time.time()
        duration = end_time - start_time
        print(f"{Fore.RED}[!] Unexpected error after {duration:.2f} seconds: {str(e)}{Style.RESET_ALL}")
        if args.verbose if 'args' in locals() else False:
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
