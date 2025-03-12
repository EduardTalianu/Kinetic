def execute(client_interaction_ui, client_id):
    """Check for installed security products"""
    # PowerShell script to check installed AV products
    av_check = """
    $avProducts = @()
    
    # Check Windows Defender status
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus) {
            $avProducts += [PSCustomObject]@{
                Product = "Windows Defender"
                Enabled = $defenderStatus.RealTimeProtectionEnabled
                Status = if($defenderStatus.RealTimeProtectionEnabled) {"Enabled"} else {"Disabled"}
            }
        }
    } catch {
        $avProducts += [PSCustomObject]@{ Product = "Windows Defender"; Enabled = "Unknown"; Status = "Error querying" }
    }
    
    # Check antivirus products using WMI
    try {
        Get-WmiObject -Namespace "root\\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object {
            $avProducts += [PSCustomObject]@{
                Product = $_.displayName
                Enabled = $true
                Status = "Installed"
            }
        }
    } catch {
        Write-Output "Error querying security products: $_"
    }
    
    # If no products found
    if (-not $avProducts) {
        Write-Output "No security products detected."
    } else {
        $avProducts | Format-Table -AutoSize
    }
    """
    client_interaction_ui.send_command(av_check)
    
def get_description():
    """Get command description"""
    return "Detect installed antivirus and security products"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard system query, low detection risk
        "requires_admin": False, # Generally doesn't require admin to query AV status
        "windows": True,         # Works on Windows
        "linux": False,          # Uses PowerShell and Windows-specific security features
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }