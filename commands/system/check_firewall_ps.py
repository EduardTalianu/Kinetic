def execute(client_interaction_ui, client_id):
    """Check Windows Firewall status"""
    # PowerShell script to check firewall status
    firewall_check = """
    try {
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $firewallProfiles | Select-Object Name, Enabled | Format-Table -AutoSize
    } catch {
        Write-Output "Error querying firewall status: $_"
    }
    """
    client_interaction_ui.send_command(firewall_check)
    
def get_description():
    """Get command description"""
    return "Check Windows Firewall status for all profiles"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard system query, low detection risk
        "requires_admin": False, # Reading firewall status doesn't require admin
        "windows": True,         # Works on Windows
        "linux": False,          # Uses PowerShell cmdlets, Windows-specific
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }
