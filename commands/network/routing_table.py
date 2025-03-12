def execute(client_interaction_ui, client_id):
    """Display routing table"""
    client_interaction_ui.send_command("route print")
    
def get_description():
    """Get command description"""
    return "Displays the routing table"
    
def get_tags():
    """Get command tags"""
    return {
        "opsec_safe": True,      # Standard network query, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Windows-specific command
        "powershell": False,     # Not a PowerShell command
        "cmd": True              # Is a CMD command
    }