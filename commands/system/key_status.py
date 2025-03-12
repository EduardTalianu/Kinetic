def execute(client_interaction_ui, client_id):
    """Execute the key status command"""
    client_interaction_ui.send_command("echo 'Checking key status...'", command_type="key_status")
    
def get_description():
    """Get command description"""
    return "Check encryption key status"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Simple echo command, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": True,           # Echo command works on Linux too
        "powershell": False,     # Not specifically PowerShell
        "cmd": True              # Works with CMD/shell
    }