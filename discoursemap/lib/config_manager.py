#!/usr/bin/env python3
"""
Configuration Manager

Handles loading and validating configuration from files.
"""

import os
import yaml
import json
from typing import Dict, Any, Optional

class ConfigManager:
    """Configuration management class"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.config = {}
        self.scan_config = self._get_default_config()
        
        if config_file:
            self.load_config(config_file)
            
    def _get_default_config(self) -> Any:
        """Get default configuration object"""
        # Simple object to hold config values
        class Config:
            def __init__(self):
                self.threads = 10
                self.timeout = 10
                self.proxy = None
                self.user_agent = None
                self.delay = 0.1
                self.verify_ssl = True
                
        return Config()
        
    def load_config(self, config_file: str) -> None:
        """
        Load configuration from file.
        
        Args:
            config_file: Path to configuration file
        """
        if not os.path.exists(config_file):
            return
            
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith(('.yaml', '.yml')):
                    self.config = yaml.safe_load(f)
                elif config_file.endswith('.json'):
                    self.config = json.load(f)
                    
            # Update scan config
            self._update_scan_config()
            
        except Exception as e:
            print(f"Error loading config: {e}")
            
    def _update_scan_config(self) -> None:
        """Update scan config object from loaded dictionary"""
        if not self.config:
            return
            
        # Update attributes if they exist in config
        for key, value in self.config.items():
            if hasattr(self.scan_config, key):
                setattr(self.scan_config, key, value)
