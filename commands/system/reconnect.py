def execute(client_interaction_ui, client_id):
    """Execute the reconnect function"""
    client_interaction_ui.reconnect_client()
    
def get_description():
    """Get command description"""
    return "Reconnect the client"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": False,     # Reconnection could be detected by security monitoring
        "requires_admin": False, # Likely doesn't require admin for client reconnection
        "windows": True,         # Works on Windows
        "linux": True,           # Should work on Linux too as it's a client operation
        "powershell": False,     # Not a PowerShell command
        "cmd": False             # Not a CMD command (internal function)
    }