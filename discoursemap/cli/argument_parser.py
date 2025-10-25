#!/usr/bin/env python3
"""
Argument Parser

Command line argument parsing for DiscourseMap.
"""

import argparse


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="DiscourseMap v2.0.2 - Comprehensive Discourse security assessment tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -u https://forum.example.com -m info vuln
  python3 main.py -u https://forum.example.com -o json -f report.json
  python3 main.py -u https://forum.example.com -v -t 10
  python3 main.py -u https://forum.example.com -m cve -p http://127.0.0.1:8080
  python3 main.py -u https://forum.example.com -q  # Quick scan (maximum speed)
  python3 main.py -q -u https://forum.example.com -o json  # Quick scan with JSON output
        """
    )
    
    # Required arguments
    parser.add_argument('-u', '--url', required=False,
                       help='Target Discourse forum URL')
    
    # Optional arguments
    parser.add_argument('-t', '--threads', type=int, default=5,
                       help='Number of threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='HTTP timeout duration (default: 10)')
    parser.add_argument('-p', '--proxy', type=str,
                       help='Proxy server (e.g: http://127.0.0.1:8080)')
    parser.add_argument('--user-agent', type=str,
                       help='Custom User-Agent string')
    parser.add_argument('--delay', type=float, default=0.05,
                       help='Delay between requests (seconds, default: 0.05)')
    
    # Scanning options
    parser.add_argument('--skip-ssl-verify', action='store_true',
                       help='Skip SSL certificate verification')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed output')
    parser.add_argument('--quiet', action='store_true',
                       help='Show only results')
    parser.add_argument('-q', '--quick', action='store_true',
                       help='Quick scan mode: Maximum speed with info, auth, api, vuln, waf_bypass modules')
    parser.add_argument('--sync', action='store_true',
                       help='Use synchronous scanning mode (default is async for better performance)')
    
    # Performance presets
    parser.add_argument('--fast', action='store_true',
                       help='Maximum speed preset (50 threads, 0.01s delay)')
    parser.add_argument('--balanced', action='store_true',
                       help='Balanced preset (20 threads, 0.05s delay)')
    parser.add_argument('--safe', action='store_true',
                       help='Safe preset (10 threads, 0.1s delay)')
    
    # Module options
    parser.add_argument(
        '-m', '--modules',
        nargs='+',
        choices=['info', 'vuln', 'endpoint', 'user', 'cve', 
                 'plugin_detection', 'plugin_bruteforce', 'api', 'auth', 
                 'config', 'crypto', 'network', 'plugin', 'waf_bypass', 'compliance',
                 'badge', 'category', 'trust_level', 'rate_limit', 'session',
                 'admin', 'webhook', 'email', 'search', 'cache'],
        help='Modules to run (default: all). New in v2.0: badge, category, trust_level, rate_limit, session, admin, webhook, email, search, cache'
    )
    
    # Output options
    parser.add_argument('-o', '--output', choices=['json', 'html', 'csv'],
                       help='Report format')
    parser.add_argument('-f', '--output-file', type=str,
                       help='Output file name')
    
    # Resume and update options
    parser.add_argument('--resume', type=str,
                       help='Resume scan from partial results file')
    parser.add_argument('-c', '--config', type=str, default='config.yaml',
                       help='Configuration file path (default: config.yaml)')
    parser.add_argument('--update', action='store_true',
                       help='Update scan data and signatures')
    
    return parser.parse_args()


def apply_performance_presets(args):
    """Apply performance presets to arguments"""
    preset_name = None
    performance_metrics = {}
    
    if args.fast:
        preset_name = "Maximum Speed"
        args.threads = 50
        args.delay = 0.01
        args.timeout = 5
        args.quiet = True
        performance_metrics = {'threads': 50, 'delay': 0.01, 'timeout': 5}
    elif args.balanced:
        preset_name = "Balanced"
        args.threads = 20
        args.delay = 0.05
        args.timeout = 7
        performance_metrics = {'threads': 20, 'delay': 0.05, 'timeout': 7}
    elif args.safe:
        preset_name = "Safe Mode"
        args.threads = 10
        args.delay = 0.1
        args.timeout = 10
        performance_metrics = {'threads': 10, 'delay': 0.1, 'timeout': 10}
    elif args.quick:
        preset_name = "Quick Scan (Legacy)"
        args.threads = 30
        args.timeout = 5
        args.delay = 0.01
        args.quiet = True
        args.modules = ['info', 'auth', 'api', 'vuln', 'waf_bypass']
        performance_metrics = {'threads': 30, 'delay': 0.01, 'timeout': 5}
    
    return preset_name, performance_metrics