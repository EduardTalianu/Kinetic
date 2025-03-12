def execute(client_interaction_ui, client_id):
    """Execute the whoami command"""
    client_interaction_ui.send_command("whoami")

def get_description():
    """Get command description"""
    return "Display the current username"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": True,           # Works on Linux
        "powershell": False,     # Not a PowerShell command
        "cmd": True              # Is a CMD command
    }