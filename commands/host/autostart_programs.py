def execute(client_interaction_ui, client_id):
    """Query registry for autostart programs"""
    client_interaction_ui.send_command("reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    
def get_description():
    """Get command description"""
    return "Lists programs set to run at startup from the registry"
    
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