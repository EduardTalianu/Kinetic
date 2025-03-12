def execute(client_interaction_ui, client_id):
    """Check if running with admin privileges"""
    client_interaction_ui.send_command("[bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544')")
    
def get_description():
    """Get command description"""
    return "Check if the client is running with administrative privileges"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard privilege check, low detection risk
        "requires_admin": False, # Doesn't require admin to check privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Uses Windows-specific security identifiers
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }