def execute(client_interaction_ui, client_id):
    """Execute the clear pending commands function"""
    client_interaction_ui.clear_pending_commands()
    
def get_description():
    """Get command description"""
    return "Clear all pending commands"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Client-side operation, not detectable on target
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": True,           # Should work on Linux too as it's a client operation
        "powershell": False,     # Not a PowerShell command
        "cmd": False             # Not a CMD command either (internal function)
    }