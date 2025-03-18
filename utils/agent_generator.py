import os
import base64
import json
import time
import datetime
from typing import Dict, Any, List, Optional

# Import the plugin manager
from plugins.plugin_manager import get_plugin_manager


def generate_agent_code(server_address, beacon_path=None, cmd_result_path=None, 
                       rotation_info=None, agent_config=None, agent_type="PowerShell"):
    """
    Generate agent code using the plugin system
    
    Args:
        server_address: C2 server address (hostname:port)
        beacon_path: Path for beacon requests (ignored in pool-only mode)
        cmd_result_path: Path for command results (ignored in pool-only mode)
        rotation_info: Path rotation information
        agent_config: Agent configuration dictionary
        agent_type: Type of agent to generate
        
    Returns:
        Generated agent code
    """
    # Get plugin manager
    plugin_manager = get_plugin_manager()
    
    # Get the specified plugin
    plugin = plugin_manager.get_plugin(agent_type)
    if not plugin:
        # Fallback to PowerShell if plugin not found
        plugin = plugin_manager.get_plugin("PowerShell")
        if not plugin:
            raise ValueError(f"Agent plugin '{agent_type}' not found and PowerShell plugin not available")
    
    # Use default configuration if not provided
    if agent_config is None:
        agent_config = {}
    
    # Fill in missing values with defaults
    default_config = plugin.get_default_config()
    for key, value in default_config.items():
        if key not in agent_config:
            agent_config[key] = value
    
    # Prepare campaign settings
    campaign_settings = {
        "server_address": server_address,
        "rotation_info": rotation_info
    }
    
    # Generate the agent
    result = plugin.generate(agent_config, campaign_settings)
    
    # Return the generated code
    return result["code"]


def generate_pwsh_base64_str(host, port, ssl, campaign_folder):
    """
    Generate a Base64 encoded PowerShell agent stager
    
    Args:
        host: Server hostname or IP
        port: Server port
        ssl: Whether to use SSL/TLS
        campaign_folder: Path to the campaign folder
        
    Returns:
        Dictionary containing the generated agent code and metadata
    """
    # Get plugin manager
    plugin_manager = get_plugin_manager()
    
    # Get PowerShell plugin
    plugin = plugin_manager.get_plugin("PowerShell")
    if not plugin:
        raise ValueError("PowerShell plugin not available")
    
    # Extract campaign name from folder path
    campaign_name = os.path.basename(campaign_folder).replace("_campaign", "")
    
    # Get agent configuration
    agent_config = {}
    
    # Try to load agent config
    agent_config_file = os.path.join(campaign_folder, "agent_config.json")
    if os.path.exists(agent_config_file):
        try:
            with open(agent_config_file, 'r') as f:
                agent_config = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load agent config: {e}")
    
    # Ensure required fields have defaults if not in the loaded config
    if "beacon_period" not in agent_config:
        agent_config["beacon_period"] = 5
    if "jitter_percentage" not in agent_config:
        agent_config["jitter_percentage"] = 20
    
    # Read path rotation configuration
    rotation_enabled = True  # Always enabled in pool-only mode
    rotation_interval = 3600  # Default
    rotation_id = 0  # Default
    next_rotation_time = int(time.time()) + rotation_interval  # Default
    
    # Try to load path rotation state
    path_rotation_file = os.path.join(campaign_folder, "path_rotation_state.json")
    if os.path.exists(path_rotation_file):
        try:
            with open(path_rotation_file, 'r') as f:
                rotation_state = json.load(f)
                rotation_id = rotation_state.get("rotation_counter", 0)
                next_rotation_time = rotation_state.get("next_rotation_time", next_rotation_time)
                rotation_interval = rotation_state.get("rotation_interval", rotation_interval)
                
                # Get path pool if available
                path_pool = rotation_state.get("current_paths", {}).get("path_pool", [])
        except Exception as e:
            print(f"Warning: Could not load path rotation state: {e}")
            path_pool = []
    else:
        path_pool = []
    
    # Create rotation info structure
    rotation_info = {
        "current_rotation_id": rotation_id,
        "next_rotation_time": next_rotation_time,
        "rotation_interval": rotation_interval,
        "current_paths": {"path_pool": path_pool}
    }
    
    # Set up server address with SSL
    http = "https" if ssl else "http"
    server_address = f"{host}:{port}"
    
    # Prepare campaign settings
    campaign_settings = {
        "server_address": server_address,
        "rotation_info": rotation_info,
        "campaign_folder": campaign_folder,
        "ssl_enabled": ssl,
        "http_protocol": http
    }
    
    # Set agent config to output in base64 format
    agent_config["format"] = "base64"
    
    # Generate the agent
    result = plugin.generate(agent_config, campaign_settings)
    
    # For backwards compatibility if result is a dictionary
    if isinstance(result, dict):
        # Create a formatted string summary that mimics the old return format
        summary = (
            f"Powershell Base64 agent generated and saved to {campaign_folder}/agents/\n\n"
            f"Powershell Base64:\n{result.get('code', '')}\n\n"
            f"Encryption: Dynamic key exchange with secure first contact\n"
            f"Security: No system information sent until encrypted channel established"
        )
        
        # Add the summary to the result dictionary for backwards compatibility
        result["summary_text"] = summary
        
        return result
    else:
        # If for some reason the result is already a string, return it as is
        return result