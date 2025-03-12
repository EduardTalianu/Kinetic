def execute(client_interaction_ui, client_id):
    """List installed software using PowerShell"""
    client_interaction_ui.send_command("Get-WmiObject Win32_Product | Select-Object Name, Version | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "List installed software"
    
def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard system command, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Uses PowerShell, Windows-specific
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }