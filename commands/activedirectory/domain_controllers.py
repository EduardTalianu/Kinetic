def execute(client_interaction_ui, client_id):
    """Execute the domain controllers command"""
    client_interaction_ui.send_command("nltest /dclist:")
    
def get_description():
    """Get command description"""
    return "List domain controllers"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard domain query, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Windows-specific command (nltest)
        "powershell": False,     # Not a PowerShell command
        "cmd": True              # Is a CMD command
    }