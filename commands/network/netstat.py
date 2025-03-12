def execute(client_interaction_ui, client_id):
    """Execute the netstat command"""
    client_interaction_ui.send_command("netstat -ano")
    
def get_description():
    """Get command description"""
    return "Display active network connections"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard network query, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": True,           # Also works on Linux
        "powershell": False,     # Not a PowerShell command
        "cmd": True              # Is a CMD command
    }