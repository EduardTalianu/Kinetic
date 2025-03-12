def execute(client_interaction_ui, client_id):
    """Execute the whoami command"""
    # Simple command that works in PowerShell
    client_interaction_ui.send_command("[System.Security.Principal.WindowsIdentity]::GetCurrent().Name")

def get_description():
    """Get command description"""
    return "Display the current username"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Doesn't work on Linux
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }