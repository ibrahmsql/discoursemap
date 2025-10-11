#!/usr/bin/env python3
"""
DiscourseMap v2.0 - Complete Security Assessment Example

This script demonstrates how to use all new Discourse-specific modules
to perform a comprehensive security assessment.
"""

import sys
import argparse
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Import DiscourseMap modules
from discoursemap import (
    # Validation
    DiscourseValidator,
    # Discourse-specific modules
    RateLimitModule,
    SessionSecurityModule,
    AdminPanelModule,
    WebhookSecurityModule,
    EmailSecurityModule,
    SearchSecurityModule,
    CacheSecurityModule,
    # Core
    Reporter
)


def print_banner():
    """Print assessment banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║       DiscourseMap v2.0 - Security Assessment Suite      ║
║          Comprehensive Discourse Security Testing         ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)


def validate_target(target_url, verbose=False):
    """
    Validate if target is a Discourse forum
    
    Args:
        target_url: Target forum URL
        verbose: Enable verbose output
        
    Returns:
        dict: Validation results
    """
    print(f"\n{Fore.YELLOW}[STEP 1/8] Validating Discourse Forum{Style.RESET_ALL}")
    print(f"Target: {target_url}")
    
    validator = DiscourseValidator(target_url, verbose=verbose)
    results = validator.validate()
    
    if results['is_discourse']:
        print(f"{Fore.GREEN}✓ Discourse forum detected!{Style.RESET_ALL}")
        if results['version']:
            print(f"  Version: {results['version']}")
        print(f"  Confidence: {results['confidence']}%")
    else:
        print(f"{Fore.RED}✗ Not a Discourse forum (Confidence: {results['confidence']}%){Style.RESET_ALL}")
        return None
    
    return results


def test_rate_limiting(target_url, verbose=False):
    """Test rate limiting mechanisms"""
    print(f"\n{Fore.YELLOW}[STEP 2/8] Testing Rate Limiting{Style.RESET_ALL}")
    
    module = RateLimitModule(target_url, verbose=verbose)
    results = module.scan()
    
    # Summary
    print(f"\n{Fore.CYAN}Rate Limiting Summary:{Style.RESET_ALL}")
    print(f"  Endpoints Tested: {len(results['endpoints_tested'])}")
    print(f"  Rate Limits Found: {len(results['rate_limits_found'])}")
    print(f"  Issues: {len([e for e in results['endpoints_tested'] if not e.get('rate_limited', True)])}")
    
    return results


def test_session_security(target_url, verbose=False):
    """Test session security"""
    print(f"\n{Fore.YELLOW}[STEP 3/8] Testing Session Security{Style.RESET_ALL}")
    
    module = SessionSecurityModule(target_url, verbose=verbose)
    results = module.scan()
    
    # Summary
    print(f"\n{Fore.CYAN}Session Security Summary:{Style.RESET_ALL}")
    print(f"  Cookies Analyzed: {results['cookie_security'].get('cookies_found', 0)}")
    csrf_status = "ENABLED" if results['csrf_protection'].get('protection_enabled') else "DISABLED"
    print(f"  CSRF Protection: {csrf_status}")
    print(f"  Vulnerabilities: {len(results['vulnerabilities'])}")
    
    return results


def test_admin_panel(target_url, verbose=False):
    """Test admin panel security"""
    print(f"\n{Fore.YELLOW}[STEP 4/8] Testing Admin Panel Security{Style.RESET_ALL}")
    
    module = AdminPanelModule(target_url, verbose=verbose)
    results = module.scan()
    
    # Summary
    print(f"\n{Fore.CYAN}Admin Panel Summary:{Style.RESET_ALL}")
    print(f"  Endpoints Discovered: {len(results['admin_endpoints'])}")
    print(f"  Accessible Without Auth: {len(results['accessible_endpoints'])}")
    print(f"  Vulnerabilities: {len(results['vulnerabilities'])}")
    
    return results


def test_webhooks(target_url, verbose=False):
    """Test webhook security"""
    print(f"\n{Fore.YELLOW}[STEP 5/8] Testing Webhook Security{Style.RESET_ALL}")
    
    module = WebhookSecurityModule(target_url, verbose=verbose)
    results = module.scan()
    
    # Summary
    print(f"\n{Fore.CYAN}Webhook Security Summary:{Style.RESET_ALL}")
    print(f"  Endpoints Tested: {len(results['webhook_endpoints'])}")
    print(f"  Vulnerabilities: {len(results['vulnerabilities'])}")
    
    return results


def test_email_security(target_url, verbose=False):
    """Test email security"""
    print(f"\n{Fore.YELLOW}[STEP 6/8] Testing Email Security (DNS){Style.RESET_ALL}")
    
    module = EmailSecurityModule(target_url, verbose=verbose)
    results = module.scan()
    
    # Summary
    print(f"\n{Fore.CYAN}Email Security Summary:{Style.RESET_ALL}")
    spf = "✓" if results['spf_record'].get('exists') else "✗"
    dkim = "✓" if results['dkim_record'].get('exists') else "✗"
    dmarc = "✓" if results['dmarc_record'].get('exists') else "✗"
    print(f"  SPF Record: {spf}")
    print(f"  DKIM Record: {dkim}")
    print(f"  DMARC Policy: {dmarc}")
    print(f"  Issues Found: {len(results['vulnerabilities'])}")
    
    return results


def test_search_security(target_url, verbose=False):
    """Test search security"""
    print(f"\n{Fore.YELLOW}[STEP 7/8] Testing Search Security{Style.RESET_ALL}")
    
    module = SearchSecurityModule(target_url, verbose=verbose)
    results = module.scan()
    
    # Summary
    print(f"\n{Fore.CYAN}Search Security Summary:{Style.RESET_ALL}")
    print(f"  Endpoints Tested: {len(results['search_endpoints'])}")
    print(f"  Injection Vulnerabilities: {len(results['injection_vulnerabilities'])}")
    print(f"  DoS Potential: {len(results['dos_potential'])}")
    
    return results


def test_cache_security(target_url, verbose=False):
    """Test cache security"""
    print(f"\n{Fore.YELLOW}[STEP 8/8] Testing Cache Security{Style.RESET_ALL}")
    
    module = CacheSecurityModule(target_url, verbose=verbose)
    results = module.scan()
    
    # Summary
    print(f"\n{Fore.CYAN}Cache Security Summary:{Style.RESET_ALL}")
    if results['cdn_detection'].get('detected'):
        print(f"  CDN: {', '.join(results['cdn_detection']['cdns'])}")
    print(f"  Cache Headers: {len(results['cache_headers'])}")
    print(f"  Poisoning Vulnerabilities: {len(results['cache_poisoning'])}")
    
    return results


def generate_final_report(target_url, all_results):
    """Generate final security report"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("FINAL SECURITY ASSESSMENT REPORT")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    print(f"🎯 Target: {target_url}")
    print(f"🔍 Modules Executed: 8\n")
    
    # Count vulnerabilities by severity
    all_vulns = []
    for results in all_results.values():
        if isinstance(results, dict) and 'vulnerabilities' in results:
            all_vulns.extend(results['vulnerabilities'])
    
    critical = len([v for v in all_vulns if v.get('severity') == 'CRITICAL'])
    high = len([v for v in all_vulns if v.get('severity') == 'HIGH'])
    medium = len([v for v in all_vulns if v.get('severity') == 'MEDIUM'])
    low = len([v for v in all_vulns if v.get('severity') == 'LOW'])
    
    print(f"{Fore.CYAN}📊 Vulnerability Summary:{Style.RESET_ALL}")
    if critical > 0:
        print(f"  {Fore.RED}🔴 Critical: {critical}{Style.RESET_ALL}")
    if high > 0:
        print(f"  {Fore.RED}🟠 High: {high}{Style.RESET_ALL}")
    if medium > 0:
        print(f"  {Fore.YELLOW}🟡 Medium: {medium}{Style.RESET_ALL}")
    if low > 0:
        print(f"  {Fore.GREEN}🟢 Low: {low}{Style.RESET_ALL}")
    
    total = critical + high + medium + low
    print(f"\n  Total Issues: {total}")
    
    # Security score
    score = max(0, 100 - (critical * 20 + high * 10 + medium * 5 + low * 2))
    
    if score >= 90:
        color = Fore.GREEN
        status = "EXCELLENT"
    elif score >= 70:
        color = Fore.YELLOW
        status = "GOOD"
    elif score >= 50:
        color = Fore.YELLOW
        status = "FAIR"
    else:
        color = Fore.RED
        status = "POOR"
    
    print(f"\n{color}🏆 Security Score: {score}/100 ({status}){Style.RESET_ALL}")
    
    # Top recommendations
    all_recs = []
    for results in all_results.values():
        if isinstance(results, dict) and 'recommendations' in results:
            all_recs.extend(results['recommendations'])
    
    if all_recs:
        print(f"\n{Fore.YELLOW}📋 Top Recommendations:{Style.RESET_ALL}")
        critical_recs = [r for r in all_recs if r.get('severity') in ['CRITICAL', 'HIGH']][:5]
        for i, rec in enumerate(critical_recs, 1):
            print(f"  {i}. [{rec['severity']}] {rec['issue']}")
            print(f"     → {rec['recommendation']}")
    
    print(f"\n{Fore.GREEN}✅ Assessment Complete!{Style.RESET_ALL}")


def main():
    """Main assessment function"""
    parser = argparse.ArgumentParser(
        description='DiscourseMap v2.0 - Complete Security Assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 discourse_security_assessment.py -u https://forum.example.com
  python3 discourse_security_assessment.py -u https://forum.example.com -v
  python3 discourse_security_assessment.py -u https://forum.example.com --quick
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target Discourse forum URL')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--quick', action='store_true', help='Quick scan (skip email/cache)')
    parser.add_argument('--output', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Step 1: Validate
    validation = validate_target(args.url, args.verbose)
    if not validation:
        print(f"\n{Fore.RED}[ERROR] Target is not a Discourse forum. Exiting.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Collect all results
    all_results = {
        'validation': validation
    }
    
    # Step 2-8: Security tests
    try:
        all_results['rate_limiting'] = test_rate_limiting(args.url, args.verbose)
        all_results['session'] = test_session_security(args.url, args.verbose)
        all_results['admin'] = test_admin_panel(args.url, args.verbose)
        all_results['webhooks'] = test_webhooks(args.url, args.verbose)
        
        if not args.quick:
            all_results['email'] = test_email_security(args.url, args.verbose)
            all_results['search'] = test_search_security(args.url, args.verbose)
            all_results['cache'] = test_cache_security(args.url, args.verbose)
        else:
            print(f"\n{Fore.YELLOW}[INFO] Skipping email/search/cache tests (quick mode){Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Assessment interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Final report
    generate_final_report(args.url, all_results)
    
    # Save to file if requested
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\n{Fore.GREEN}💾 Results saved to: {args.output}{Style.RESET_ALL}")


if __name__ == '__main__':
    main()
