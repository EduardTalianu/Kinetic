def execute(client_interaction_ui, client_id):
    """Execute the get drives command"""
    client_interaction_ui.send_command("wmic logicaldisk get deviceid, volumename, description")
    
def get_description():
    """Get command description"""
    return "List all disk drives"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard system command, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows (wmic is Windows-specific)
        "linux": False,          # Windows-specific command
        "powershell": False,     # Not a PowerShell command
        "cmd": True              # Is a CMD command
    }