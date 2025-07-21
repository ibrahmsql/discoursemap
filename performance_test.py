#!/usr/bin/env python3
"""
DiscourseMap Performance Test Script

Bu script, DiscourseMap'in performans iyileştirmelerini test eder ve karşılaştırır.
"""

import time
import sys
import os
import json
import argparse
from datetime import datetime
from colorama import init, Fore, Style

# Add the discoursemap module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'discoursemap'))

from discoursemap.modules.scanner import DiscourseScanner
from discoursemap.modules.utils import validate_url

init(autoreset=True)

class PerformanceTester:
    """DiscourseMap performans test sınıfı"""
    
    def __init__(self):
        self.results = {
            'test_date': datetime.now().isoformat(),
            'tests': []
        }
    
    def log(self, message, level='info'):
        """Log mesajı yazdır"""
        colors = {
            'info': Fore.CYAN,
            'success': Fore.GREEN,
            'warning': Fore.YELLOW,
            'error': Fore.RED
        }
        
        color = colors.get(level, Fore.WHITE)
        prefix = {
            'info': '[*]',
            'success': '[+]',
            'warning': '[!]',
            'error': '[!]'
        }.get(level, '[*]')
        
        print(f"{color}{prefix} {message}{Style.RESET_ALL}")
    
    def test_configuration(self, target_url, config_name, **kwargs):
        """Belirli bir konfigürasyonu test et"""
        
        self.log(f"Testing configuration: {config_name}")
        
        start_time = time.time()
        
        try:
            # Scanner'ı başlat
            scanner = DiscourseScanner(
                target_url=target_url,
                quiet=True,  # Sessiz mod
                **kwargs
            )
            
            # Sadece hızlı modülleri test et
            test_modules = ['info', 'endpoint']
            
            # Scan'i çalıştır
            results = scanner.run_scan(test_modules)
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Sonuçları kaydet
            test_result = {
                'config_name': config_name,
                'duration': duration,
                'success': True,
                'modules_tested': test_modules,
                'total_tests': sum(len(results['modules'].get(mod, {}).get('vulnerabilities', [])) 
                                 for mod in test_modules if mod in results['modules']),
                'config': kwargs
            }
            
            self.results['tests'].append(test_result)
            
            self.log(f"{config_name} completed in {duration:.2f} seconds", 'success')
            
            return test_result
            
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            
            test_result = {
                'config_name': config_name,
                'duration': duration,
                'success': False,
                'error': str(e),
                'config': kwargs
            }
            
            self.results['tests'].append(test_result)
            
            self.log(f"{config_name} failed after {duration:.2f} seconds: {e}", 'error')
            
            return test_result
    
    def run_performance_comparison(self, target_url):
        """Farklı konfigürasyonları karşılaştır"""
        
        self.log("Starting DiscourseMap Performance Comparison")
        self.log(f"Target: {target_url}")
        
        # Test konfigürasyonları
        configs = [
            {
                'name': 'Original (Slow)',
                'threads': 5,
                'delay': 0.5,
                'timeout': 10
            },
            {
                'name': 'Optimized (Fast)',
                'threads': 20,
                'delay': 0.05,
                'timeout': 7
            },
            {
                'name': 'Maximum Performance',
                'threads': 50,
                'delay': 0.01,
                'timeout': 5
            },
            {
                'name': 'Conservative Optimized',
                'threads': 15,
                'delay': 0.1,
                'timeout': 8
            }
        ]
        
        # Her konfigürasyonu test et
        for config in configs:
            config_params = {k: v for k, v in config.items() if k != 'name'}
            self.test_configuration(target_url, config['name'], **config_params)
            
            # Testler arası kısa bekleme
            time.sleep(2)
        
        # Sonuçları analiz et
        self.analyze_results()
    
    def analyze_results(self):
        """Test sonuçlarını analiz et ve rapor oluştur"""
        
        self.log("\n" + "="*60)
        self.log("PERFORMANCE TEST RESULTS", 'success')
        self.log("="*60)
        
        successful_tests = [t for t in self.results['tests'] if t['success']]
        
        if not successful_tests:
            self.log("No successful tests to analyze!", 'error')
            return
        
        # En hızlı ve en yavaş testleri bul
        fastest = min(successful_tests, key=lambda x: x['duration'])
        slowest = max(successful_tests, key=lambda x: x['duration'])
        
        self.log(f"\nFastest Configuration: {fastest['config_name']}")
        self.log(f"  Duration: {fastest['duration']:.2f} seconds")
        self.log(f"  Threads: {fastest['config']['threads']}")
        self.log(f"  Delay: {fastest['config']['delay']}s")
        
        self.log(f"\nSlowest Configuration: {slowest['config_name']}")
        self.log(f"  Duration: {slowest['duration']:.2f} seconds")
        self.log(f"  Threads: {slowest['config']['threads']}")
        self.log(f"  Delay: {slowest['config']['delay']}s")
        
        # Performans artışını hesapla
        if fastest != slowest:
            improvement = ((slowest['duration'] - fastest['duration']) / slowest['duration']) * 100
            speed_multiplier = slowest['duration'] / fastest['duration']
            
            self.log(f"\nPerformance Improvement: {improvement:.1f}%", 'success')
            self.log(f"Speed Multiplier: {speed_multiplier:.1f}x faster", 'success')
        
        # Detaylı sonuçlar
        self.log("\nDetailed Results:")
        for test in successful_tests:
            self.log(f"  {test['config_name']}: {test['duration']:.2f}s")
        
        # Öneriler
        self.log("\nRecommendations:", 'warning')
        
        if fastest['config']['threads'] >= 20:
            self.log("  ✓ High thread count provides best performance")
        
        if fastest['config']['delay'] <= 0.1:
            self.log("  ✓ Low delay significantly improves speed")
        
        if fastest['config']['timeout'] <= 7:
            self.log("  ✓ Reduced timeout helps with faster scanning")
        
        self.log("\nOptimal Configuration for your environment:")
        self.log(f"  --threads {fastest['config']['threads']}")
        self.log(f"  --delay {fastest['config']['delay']}")
        self.log(f"  --timeout {fastest['config']['timeout']}")
    
    def save_results(self, filename=None):
        """Sonuçları dosyaya kaydet"""
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"performance_test_results_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            
            self.log(f"Results saved to: {filename}", 'success')
            
        except Exception as e:
            self.log(f"Failed to save results: {e}", 'error')

def main():
    """Ana fonksiyon"""
    
    parser = argparse.ArgumentParser(
        description='DiscourseMap Performance Test Tool'
    )
    
    parser.add_argument('-u', '--url', required=True,
                       help='Target Discourse forum URL')
    parser.add_argument('-o', '--output', type=str,
                       help='Output file for results')
    
    args = parser.parse_args()
    
    # URL doğrulama
    if not validate_url(args.url):
        print(f"{Fore.RED}Error: Invalid URL format!{Style.RESET_ALL}")
        sys.exit(1)
    
    # Performance tester'ı başlat
    tester = PerformanceTester()
    
    try:
        # Performans karşılaştırmasını çalıştır
        tester.run_performance_comparison(args.url)
        
        # Sonuçları kaydet
        tester.save_results(args.output)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Test interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Test failed: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()