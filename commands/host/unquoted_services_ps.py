def execute(client_interaction_ui, client_id):
    """Check for unquoted service paths"""
    client_interaction_ui.send_command("Get-WmiObject win32_service | Where-Object {$_.PathName -notlike '\"*\"' -and $_.PathName -like '* *'} | Select-Object Name, PathName | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "Identifies services with unquoted paths vulnerable to privilege escalation"
    
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