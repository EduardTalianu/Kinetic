def execute(client_interaction_ui, client_id):
    """List local users with PowerShell"""
    # Get local users using PowerShell
    client_interaction_ui.send_command("Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "List all local user accounts with details"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard user query, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Uses PowerShell cmdlets, Windows-specific
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }