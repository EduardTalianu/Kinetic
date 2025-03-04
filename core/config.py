import os
import json
import configparser

class ConfigManager:
    """
    Manages global configuration settings for the application
    """
    def __init__(self):
        self.config = {
            "app": {
                "name": "Kinetic Compliance Matrix",
                "version": "1.0.0",
                "debug": False
            },
            "server": {
                "default_port": 8080,
                "default_protocol": "http"
            },
            "client": {
                "default_beacon_interval": 5,
                "jitter_percentage": 20
            },
            "security": {
                "verification_threshold": 70,  # Confidence percentage required for verification
                "auto_key_rotation": True,
                "store_credentials": False
            },
            "ui": {
                "theme": "default",
                "auto_refresh_interval": 3000
            },
            "paths": {
                "campaigns_dir": "campaigns",
                "logs_dir": "logs"
            }
        }
        
        # Load config from file if exists
        self.config_file = "config.ini"
        if os.path.exists(self.config_file):
            self.load_config()
        else:
            self.save_config()
        
    def load_config(self):
        """Load configuration from file"""
        try:
            parser = configparser.ConfigParser()
            parser.read(self.config_file)
            
            for section in parser.sections():
                if section not in self.config:
                    self.config[section] = {}
                    
                for key, value in parser.items(section):
                    # Try to convert to appropriate types
                    if value.lower() in ["true", "false"]:
                        self.config[section][key] = (value.lower() == "true")
                    else:
                        try:
                            # Try to convert to int or float
                            if "." in value:
                                self.config[section][key] = float(value)
                            else:
                                self.config[section][key] = int(value)
                        except ValueError:
                            # Keep as string if not a number
                            self.config[section][key] = value
        except Exception as e:
            print(f"Error loading config: {e}")
            # Keep using default config
    
    def save_config(self):
        """Save configuration to file"""
        try:
            parser = configparser.ConfigParser()
            
            for section, items in self.config.items():
                parser.add_section(section)
                for key, value in items.items():
                    parser.set(section, key, str(value))
            
            with open(self.config_file, 'w') as f:
                parser.write(f)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get(self, section, key, default=None):
        """
        Get a configuration value
        
        Args:
            section: Configuration section
            key: Configuration key
            default: Default value if not found
            
        Returns:
            Configuration value or default if not found
        """
        if section in self.config and key in self.config[section]:
            return self.config[section][key]
        return default
    
    def set(self, section, key, value):
        """
        Set a configuration value
        
        Args:
            section: Configuration section
            key: Configuration key
            value: Configuration value
        """
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section][key] = value
        self.save_config()
    
    def get_all(self):
        """Get the complete configuration"""
        return self.config
    
    def get_section(self, section):
        """Get an entire configuration section"""
        return self.config.get(section, {})