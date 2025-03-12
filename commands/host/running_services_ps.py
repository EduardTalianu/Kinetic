def execute(client_interaction_ui, client_id):
    """List all running services"""
    client_interaction_ui.send_command("Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "Lists all running services with start type information"
    
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