def execute(client_interaction_ui, client_id):
    """Check if the system is domain-joined"""
    client_interaction_ui.send_command("(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain")
    
def get_description():
    """Get command description"""
    return "Check if the system is joined to an Active Directory domain"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard system query, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Uses WMI, Windows-specific
        "powershell": True,      # Uses PowerShell (Get-WmiObject)
        "cmd": False             # Not a CMD command
    }