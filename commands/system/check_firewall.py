def execute(client_interaction_ui, client_id):
    """Display firewall status for all profiles"""
    client_interaction_ui.send_command("netsh advfirewall show allprofiles")
    
def get_description():
    """Get command description"""
    return "Display firewall status for all profiles"
    
def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard system command, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Windows-specific command
        "powershell": False,     # Not a PowerShell command
        "cmd": True              # Is a CMD command
    }