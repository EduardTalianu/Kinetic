def execute(client_interaction_ui, client_id):
    """List all local groups"""
    client_interaction_ui.send_command("net localgroup")
    
def get_description():
    """Get command description"""
    return "Lists all local groups on the system"
    
def get_tags():
    """Get command tags"""
    return {
        "opsec_safe": True,
        "requires_admin": False,
        "windows": True,
        "linux": False,
        "powershell": False,
        "cmd": True
    }