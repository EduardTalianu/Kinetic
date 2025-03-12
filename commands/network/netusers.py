def execute(client_interaction_ui, client_id):
    """Execute the net user command"""
    client_interaction_ui.send_command("net user")
    
def get_description():
    """Get command description"""
    return "List all local user accounts"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard user query, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Windows-specific command
        "powershell": False,     # Not a PowerShell command
        "cmd": True              # Is a CMD command (net command)
    }