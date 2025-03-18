from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union


class AgentPluginInterface(ABC):
    """Base interface for agent generation plugins"""
    
    @classmethod
    @abstractmethod
    def get_name(cls) -> str:
        """Return the name of this agent type for UI display"""
        pass
    
    @classmethod
    @abstractmethod
    def get_description(cls) -> str:
        """Return a description of this agent type"""
        pass
    
    @classmethod
    @abstractmethod
    def get_options(cls) -> Dict[str, Dict[str, Any]]:
        """
        Return a dictionary of configuration options for this agent type
        
        Format:
        {
            "option_name": {
                "type": "string|int|bool|list",
                "default": default_value,
                "description": "Human-readable description",
                "required": True|False,
                "values": [list, of, possible, values]  # Optional, for list type
            },
            ...
        }
        """
        pass
        
    @classmethod
    @abstractmethod
    def generate(cls, config: Dict[str, Any], campaign_settings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate the agent using the provided configuration
        
        Args:
            config: Dictionary containing plugin-specific configuration
            campaign_settings: Dictionary containing campaign-wide settings
            
        Returns:
            Dictionary containing:
                "code": Generated agent code
                "files": List of file paths generated (if any)
                "instructions": User instructions (if any)
                "summary": Short summary of what was generated
        """
        pass
    
    @classmethod
    def validate_config(cls, config: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Validate the provided configuration against plugin requirements
        
        Args:
            config: Dictionary containing plugin-specific configuration
            
        Returns:
            Dictionary of validation errors, where keys are option names and
            values are lists of error messages. Empty dict if validation passed.
        """
        errors = {}
        options = cls.get_options()
        
        # Check required options
        for option_name, option_info in options.items():
            if option_info.get("required", False) and (option_name not in config or config[option_name] is None):
                if option_name not in errors:
                    errors[option_name] = []
                errors[option_name].append(f"Option '{option_name}' is required")
                
            # If option is provided, check type
            elif option_name in config and config[option_name] is not None:
                option_type = option_info.get("type", "string")
                
                # Check type validation
                if option_type == "string" and not isinstance(config[option_name], str):
                    if option_name not in errors:
                        errors[option_name] = []
                    errors[option_name].append(f"Option '{option_name}' must be a string")
                    
                elif option_type == "int" and not isinstance(config[option_name], int):
                    if option_name not in errors:
                        errors[option_name] = []
                    errors[option_name].append(f"Option '{option_name}' must be an integer")
                    
                elif option_type == "bool" and not isinstance(config[option_name], bool):
                    if option_name not in errors:
                        errors[option_name] = []
                    errors[option_name].append(f"Option '{option_name}' must be a boolean")
                    
                elif option_type == "list" and "values" in option_info:
                    if config[option_name] not in option_info["values"]:
                        if option_name not in errors:
                            errors[option_name] = []
                        errors[option_name].append(
                            f"Option '{option_name}' must be one of: {', '.join(str(v) for v in option_info['values'])}"
                        )
        
        return errors
    
    @classmethod
    def get_supported_platforms(cls) -> List[str]:
        """
        Return a list of platforms supported by this agent type
        
        Default supported platforms: ["windows"]
        Override this method to specify different platforms.
        """
        return ["windows"]
    
    @classmethod
    def get_default_config(cls) -> Dict[str, Any]:
        """
        Return default configuration values for this plugin
        
        By default, extracts defaults from the options dictionary.
        """
        defaults = {}
        options = cls.get_options()
        
        for option_name, option_info in options.items():
            if "default" in option_info:
                defaults[option_name] = option_info["default"]
        
        return defaults
    
    @classmethod
    def get_agent_capabilities(cls) -> List[str]:
        """
        Return a list of capabilities this agent type supports
        
        Examples: "file_operations", "screenshot", "keylogging", etc.
        """
        return []