def execute(client_interaction_ui, client_id):
    """Execute the system identification command"""
    client_interaction_ui.send_command("Get-SystemIdentification", command_type="system_info")
    
def get_description():
    """Get command description"""
    return "Get detailed system identification"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Appears to be Windows-specific
        "powershell": True,      # Likely a PowerShell command
        "cmd": False             # Not a CMD command
    }