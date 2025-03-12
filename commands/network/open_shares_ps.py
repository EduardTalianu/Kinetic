def execute(client_interaction_ui, client_id):
    """List all open shares"""
    client_interaction_ui.send_command("Get-SmbShare | Select-Object Name, Path, Description | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "Lists all shared folders on the system"
    
def get_tags():
    """Get command tags"""
    return {
        "opsec_safe": True,
        "requires_admin": False,
        "windows": True,
        "linux": False,
        "powershell": True,
        "cmd": False
    }