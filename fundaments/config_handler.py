# PyFundaments: A Secure Python Architecture
# Copyright 2008-2025 - Volkan Kücükbudak
# Apache License V. 2
# Repo: https://github.com/VolkanSah/PyFundaments
# fundaments/config_handler.py
# This module loads environment variables without validation.
# Validation is handled by main.py based on required services.
import os
import sys
from dotenv import load_dotenv
from typing import Optional, Dict, Any

class ConfigHandler:
    """
    A universal configuration loader that reads all environment variables
    without imposing requirements. This ensures the config handler never
    needs updates regardless of what services are used.
    
    Validation is delegated to main.py which knows what services are needed.
    """
    
    def __init__(self):
        """
        Loads all environment variables from .env file and system environment.
        No validation is performed - that's main.py's responsibility.
        """
        load_dotenv()
        self.config = {}
        self.load_all_config()
    
    def load_all_config(self):
        """
        Loads all available environment variables into the config dictionary.
        No validation - main.py decides what's required based on enabled services.
        """
        # Load all environment variables
        for key, value in os.environ.items():
            if value:  # Only store non-empty values
                self.config[key] = value
    
    def get(self, key: str) -> Optional[str]:
        """
        Retrieves a configuration value by key.
        Returns None if the key doesn't exist.
        
        Args:
            key: The environment variable name
            
        Returns:
            The value as string or None if not found
        """
        return self.config.get(key)
    
    def get_bool(self, key: str, default: bool = False) -> bool:
        """
        Retrieves a boolean configuration value.
        Recognizes: true, false, 1, 0, yes, no (case insensitive)
        
        Args:
            key: The environment variable name
            default: Default value if key not found
            
        Returns:
            Boolean value
        """
        value = self.get(key)
        if value is None:
            return default
        
        return value.lower() in ('true', '1', 'yes', 'on')
    
    def get_int(self, key: str, default: int = 0) -> int:
        """
        Retrieves an integer configuration value.
        
        Args:
            key: The environment variable name
            default: Default value if key not found or invalid
            
        Returns:
            Integer value
        """
        value = self.get(key)
        if value is None:
            return default
        
        try:
            return int(value)
        except ValueError:
            return default
    
    def has(self, key: str) -> bool:
        """
        Checks if a configuration key exists and has a non-empty value.
        
        Args:
            key: The environment variable name
            
        Returns:
            True if key exists and has value, False otherwise
        """
        return key in self.config and bool(self.config[key])
    
    def get_all(self) -> Dict[str, str]:
        """
        Returns all loaded configuration as a dictionary.
        Useful for debugging or passing to other services.
        
        Returns:
            Dictionary of all loaded environment variables
        """
        return self.config.copy()

# Global singleton instance
config_service = ConfigHandler()
