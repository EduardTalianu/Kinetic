def execute(client_interaction_ui, client_id):
    """Show PowerShell environment variables"""
    # Get environment variables using PowerShell
    client_interaction_ui.send_command("Get-ChildItem env: | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "List all environment variables"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard environment query, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Uses PowerShell cmdlets, Windows-specific
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }