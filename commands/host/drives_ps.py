def execute(client_interaction_ui, client_id):
    """List disk drives with PowerShell"""
    # Get drive information using PowerShell
    client_interaction_ui.send_command("Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, VolumeName, @{Name='Size(GB)';Expression={[math]::round($_.Size / 1GB, 2)}}, @{Name='FreeSpace(GB)';Expression={[math]::round($_.FreeSpace / 1GB, 2)}}, DriveType | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "List all disk drives with size information"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard system command, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Uses PowerShell and WMI, Windows-specific
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }