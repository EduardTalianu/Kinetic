def execute(client_interaction_ui, client_id):
    """Execute the scheduled tasks command"""
    client_interaction_ui.send_command("schtasks /query /fo LIST /v")
    
def get_description():
    """Get command description"""
    return "List all scheduled tasks"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard system query, low detection risk
        "requires_admin": False, # Does not require admin privileges for listing tasks
        "windows": True,         # Works on Windows
        "linux": False,          # Windows-specific command
        "powershell": False,     # Not a PowerShell command
        "cmd": True              # Is a CMD command (schtasks)
    }