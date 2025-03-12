def execute(client_interaction_ui, client_id):
    """Display ARP cache"""
    client_interaction_ui.send_command("arp -a")
    
def get_description():
    """Get command description"""
    return "Displays the ARP cache showing IP to MAC address mappings"
    
def get_tags():
    """Get command tags"""
    return {
        "opsec_safe": True,      # Standard network query, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": True,           # Also works on Linux
        "powershell": False,     # Not a PowerShell command
        "cmd": True              # Is a CMD command
    }