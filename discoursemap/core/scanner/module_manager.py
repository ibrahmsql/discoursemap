#!/usr/bin/env python3
"""
Module Manager

Manages security scanning modules and their execution.
"""

from typing import Dict, Any, List, Optional
from ...analysis.info import InfoModule
from ...security.vulnerabilities import VulnerabilityModule
from ...analysis.endpoints import EndpointModule
from ...utilities import UserModule
from ...security.exploits import CVEExploitModule
from ...analysis.plugins import PluginBruteforceModule
from ...analysis.plugins import PluginDetectionModule
from ...infrastructure.api import APISecurityModule
from ...security.auth import AuthModule
from ...infrastructure.config import ConfigModule
from ...security.crypto import CryptoModule
from ...infrastructure.network import NetworkModule
from ...analysis.plugins import PluginModule
from ...compliance import ComplianceModule
from ...utilities import WAFBypassModule
from ...analysis.passive import PassiveScannerModule
from ...analysis.files import FileIntegrityModule

# Discourse-specific security modules
from ...discourse_specific.badges import BadgeSecurityModule
from ...discourse_specific.categories import CategorySecurityModule
from ...discourse_specific.trust_levels import TrustLevelSecurityModule
from ...discourse_specific.rate_limiting import RateLimitModule
from ...discourse_specific.session import SessionSecurityModule
from ...discourse_specific.admin import AdminPanelModule
from ...discourse_specific.webhooks import WebhookSecurityModule
from ...discourse_specific.email import EmailSecurityModule
from ...discourse_specific.search import SearchSecurityModule
from ...discourse_specific.cache import CacheSecurityModule


class ModuleManager:
    """Manages security scanning modules"""
    
    def __init__(self, scanner):
        """
        Initialize module manager.
        
        Args:
            scanner: Base scanner instance
        """
        self.scanner = scanner
        self.modules = {}
        self._initialize_modules()
    
    def _initialize_modules(self):
        """Initialize all available modules"""
        try:
            # Core modules
            self.modules.update({
                'info': InfoModule(self.scanner),
                'vuln': VulnerabilityModule(self.scanner),
                'endpoint': EndpointModule(self.scanner),
                'user': UserModule(self.scanner),
                'cve': CVEExploitModule(self.scanner),
                'plugin_detection': PluginDetectionModule(self.scanner),
                'plugin_bruteforce': PluginBruteforceModule(self.scanner),
                'api': APISecurityModule(self.scanner),
                'auth': AuthModule(self.scanner),
                'config': ConfigModule(self.scanner),
                'crypto': CryptoModule(self.scanner),
                'network': NetworkModule(self.scanner),
                'plugin': PluginModule(self.scanner),
                'waf_bypass': WAFBypassModule(self.scanner),
                'compliance': ComplianceModule(self.scanner),
                'passive_scanner': PassiveScannerModule(self.scanner),
                'file_integrity': FileIntegrityModule(self.scanner)
            })
        except ImportError as e:
            self.scanner.log(f"Error importing core modules: {e}", 'warning')
    
    def get_module(self, module_name: str):
        """Get a specific module instance"""
        if module_name in self.modules:
            return self.modules[module_name]
        
        # Try to create discourse-specific modules on demand
        return self._create_discourse_module(module_name)
    
    def _create_discourse_module(self, module_name: str):
        """Create discourse-specific modules on demand"""
        try:
            if module_name == 'badge':
                return BadgeSecurityModule(self.scanner.target_url, verbose=self.scanner.verbose)
            elif module_name == 'category':
                return CategorySecurityModule(self.scanner.target_url, verbose=self.scanner.verbose)
            elif module_name == 'trust_level':
                return TrustLevelSecurityModule(self.scanner.target_url, verbose=self.scanner.verbose)
            elif module_name == 'rate_limit':
                return RateLimitModule(self.scanner.target_url, verbose=self.scanner.verbose)
            elif module_name == 'session':
                return SessionSecurityModule(self.scanner.target_url, verbose=self.scanner.verbose)
            elif module_name == 'admin':
                return AdminPanelModule(self.scanner.target_url, verbose=self.scanner.verbose)
            elif module_name == 'webhook':
                return WebhookSecurityModule(self.scanner.target_url, verbose=self.scanner.verbose)
            elif module_name == 'email':
                return EmailSecurityModule(self.scanner.target_url, verbose=self.scanner.verbose)
            elif module_name == 'search':
                return SearchSecurityModule(self.scanner.target_url, verbose=self.scanner.verbose)
            elif module_name == 'cache':
                return CacheSecurityModule(self.scanner.target_url, verbose=self.scanner.verbose)
        except ImportError as e:
            self.scanner.log(f"Error importing discourse module {module_name}: {e}", 'warning')
        
        return None
    
    def run_module_safe(self, module, module_name: str) -> Dict[str, Any]:
        """Execute a module safely and return results"""
        try:
            self.scanner.log(f"Executing {module_name} module...", 'info')
            result = module.run()
            return result
        except (ImportError, AttributeError, TypeError) as e:
            self.scanner.log(f"Module error in {module_name}: {str(e)}", 'error')
            return {'error': str(e), 'error_type': 'module_error'}
        except Exception as e:
            self.scanner.log(f"Unexpected error in {module_name}: {str(e)}", 'error')
            return {'error': str(e), 'error_type': 'unexpected'}
    
    def get_available_modules(self) -> List[str]:
        """Get list of available module names"""
        core_modules = list(self.modules.keys())
        discourse_modules = [
            'badge', 'category', 'trust_level', 'rate_limit', 'session',
            'admin', 'webhook', 'email', 'search', 'cache'
        ]
        return core_modules + discourse_modules
    
    def get_default_modules(self) -> List[str]:
        """Get default modules to run"""
        return [
            'info', 'vuln', 'endpoint', 'user', 'cve', 'plugin_detection', 
            'plugin_bruteforce', 'api', 'auth', 'config', 'crypto', 
            'network', 'plugin', 'waf_bypass', 'compliance'
        ]