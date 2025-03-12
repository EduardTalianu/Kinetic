def execute(client_interaction_ui, client_id):
    """Execute the systeminfo command"""
    client_interaction_ui.send_command("systeminfo")
    
def get_description():
    """Get command description"""
    return "Display detailed system information"

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