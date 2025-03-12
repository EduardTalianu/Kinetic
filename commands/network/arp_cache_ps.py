def execute(client_interaction_ui, client_id):
    """Display network neighbors with PowerShell"""
    client_interaction_ui.send_command("Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "Displays the network neighbors (ARP cache)"
    
def get_tags():
    """Get command tags"""
    return {
        "opsec_safe": True,      # Standard network query, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Uses PowerShell, Windows-specific
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }