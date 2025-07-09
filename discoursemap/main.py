#!/usr/bin/env python3
"""
DiscourseMap v1.1.1
Comprehensive Discourse forum security assessment tool

Author: ibrahimsql
Version: 1.1.1
License: MIT

WARNING: This tool should only be used on authorized systems.
Unauthorized use is prohibited and may have legal consequences.
"""

import argparse
import sys
import os
import time
from datetime import datetime
from colorama import init, Fore, Style
from discoursemap.modules.scanner import DiscourseScanner
from discoursemap.modules.reporter import Reporter
from discoursemap.modules.utils import validate_url
from discoursemap.modules.banner import Banner

init(autoreset=False)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='DiscourseMap v1.0.1 - Comprehensive Discourse security assessment tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -u https://forum.example.com --modules info vuln
  python3 main.py -u https://forum.example.com -o json --output-file report.json
  python3 main.py -u https://forum.example.com --verbose --threads 10
        """
    )
    
    # Required arguments
    parser.add_argument('-u', '--url', required=True,
                       help='Target Discourse forum URL')
    
    # Optional arguments
    parser.add_argument('-t', '--threads', type=int, default=5,
                       help='Number of threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='HTTP timeout duration (default: 10)')
    parser.add_argument('--proxy', type=str,
                       help='Proxy server (e.g: http://127.0.0.1:8080)')
    parser.add_argument('--user-agent', type=str,
                       help='Custom User-Agent string')
    parser.add_argument('--delay', type=float, default=0.5,
                       help='Delay between requests (seconds, default: 0.5)')
    
    # Scanning options
    parser.add_argument('--skip-ssl-verify', action='store_true',
                       help='Skip SSL certificate verification')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed output')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Show only results')
    
    # Module options
    parser.add_argument('--modules', nargs='+', 
                       choices=['info', 'vuln', 'endpoint', 'user', 'cve', 'plugin_detection', 'plugin_bruteforce', 
                               'api', 'auth', 'config', 'crypto', 'network', 'plugin', 'compliance'],
                       help='Modules to run (default: all)')
    
    # Output options
    parser.add_argument('-o', '--output', choices=['json', 'html', 'csv'],
                       help='Report format')
    parser.add_argument('--output-file', type=str,
                       help='Output file name')
    
    return parser.parse_args()

def main():
    """Main function"""
    print(Banner)
    start_time = time.time()
    
    try:
        # Parse arguments
        args = parse_arguments()
        
        # URL validation
        if not validate_url(args.url):
            print(f"{Fore.RED}Error: Invalid URL format!{Style.RESET_ALL}")
            sys.exit(1)
        
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
            quiet=args.quiet
        )
        
        # Show scan configuration
        if not args.quiet:
            print(f"{Fore.CYAN}[*] Scan Configuration:{Style.RESET_ALL}")
            print(f"    Target: {args.url}")
            print(f"    Threads: {args.threads}")
            print(f"    User-Agent: {'Custom' if args.user_agent else 'Rotating'}")
            print(f"    Delay: {args.delay}s")
            print()
        
        # Determine modules
        modules_to_run = args.modules if args.modules else ['info', 'vuln', 'endpoint', 'user', 'cve', 'plugin_detection', 'plugin_bruteforce', 
                                                           'api', 'auth', 'config', 'crypto', 'network', 'plugin', 'compliance']
        
        # Start scan
        results = scanner.run_scan(modules_to_run)
        
        # Calculate scan duration
        end_time = time.time()
        duration = end_time - start_time
        
        # Generate report
        if args.output:
            reporter = Reporter(results)
            output_file = args.output_file or f"discourse_scan_report.{args.output}"
            
            if args.output == 'json':
                reporter.generate_json_report(output_file)
            elif args.output == 'html':
                reporter.generate_html_report(output_file)
            elif args.output == 'csv':
                reporter.generate_csv_report(output_file)
            
            print(f"{Fore.GREEN}[+] Report saved: {output_file}{Style.RESET_ALL}")
        
        # Show completion with duration
        print(f"{Fore.GREEN}[+] Scan completed in {duration:.2f} seconds!{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        end_time = time.time()
        duration = end_time - start_time
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user after {duration:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Performing graceful shutdown...{Style.RESET_ALL}")
        
        # Try to save partial results if available
        try:
            if 'scanner' in locals() and hasattr(scanner, 'results'):
                print(f"{Fore.CYAN}[*] Saving partial scan results...{Style.RESET_ALL}")
                partial_file = f"partial_scan_{int(time.time())}.json"
                scanner.generate_json_report(partial_file)
                print(f"{Fore.GREEN}[+] Partial results saved: {partial_file}{Style.RESET_ALL}")
        except:
            pass
        
        sys.exit(0)
    except Exception as e:
        end_time = time.time()
        duration = end_time - start_time
        print(f"{Fore.RED}[!] Error after {duration:.2f} seconds: {str(e)}{Style.RESET_ALL}")
        if args.verbose if 'args' in locals() else False:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
