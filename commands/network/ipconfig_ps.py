def execute(client_interaction_ui, client_id):
    """Get network configuration with PowerShell"""
    # Get network configuration using PowerShell
    client_interaction_ui.send_command("Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "Display network configuration details"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard network query, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Uses PowerShell cmdlets, Windows-specific
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }