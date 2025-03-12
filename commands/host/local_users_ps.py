def execute(client_interaction_ui, client_id):
    """List all local users with details"""
    client_interaction_ui.send_command("Get-LocalUser | Select-Object Name, Enabled, Description, LastLogon | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "Enumerates local users with status and last logon details"
    
def get_tags():
    """Get command tags"""
    return {
        "opsec_safe": True,
        "requires_admin": False,
        "windows": True,
        "linux": False,
        "powershell": True,      # Uses PowerShell
        "cmd": False
    }