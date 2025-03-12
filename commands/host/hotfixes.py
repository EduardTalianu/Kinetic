def execute(client_interaction_ui, client_id):
    """List installed Windows updates and hotfixes"""
    client_interaction_ui.send_command("Get-HotFix | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "List all installed Windows updates and hotfixes"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard system command, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Windows-specific (hotfixes concept)
        "powershell": True,      # Uses PowerShell command
        "cmd": False             # Not a CMD command
    }