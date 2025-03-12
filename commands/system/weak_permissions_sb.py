def execute(client_interaction_ui, client_id):
    """Check for weak permissions on service binaries"""
    client_interaction_ui.send_command("Get-WmiObject win32_service | ForEach-Object { icacls $_.PathName }")
    
def get_description():
    """Get command description"""
    return "Checks permissions on service executables for potential privilege escalation"
    
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