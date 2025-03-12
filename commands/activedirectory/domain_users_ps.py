def execute(client_interaction_ui, client_id):
    """List domain users with PowerShell"""
    # PowerShell command to list domain users if domain joined
    script = """
    try {
        if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
            Get-ADUser -Filter * -Properties LastLogonDate, Enabled | Select-Object Name, Enabled, LastLogonDate | Format-Table -AutoSize
        } else {
            Write-Output "This computer is not joined to a domain."
        }
    } catch {
        Write-Output "Error: $_"
        Write-Output "Note: The ActiveDirectory module may not be installed."
    }
    """
    client_interaction_ui.send_command(script)
    
def get_description():
    """Get command description"""
    return "List all domain user accounts (requires AD module)"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard domain query, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Uses PowerShell and AD module, Windows-specific
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }