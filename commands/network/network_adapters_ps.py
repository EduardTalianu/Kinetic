def execute(client_interaction_ui, client_id):
    """List network adapters with PowerShell"""
    client_interaction_ui.send_command("Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "Displays details of all network adapters on the system"
    
def get_tags():
    """Get command tags"""
    return {
        "opsec_safe": True,      # Standard query, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Uses PowerShell, Windows-specific
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }