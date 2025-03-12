def execute(client_interaction_ui, client_id):
    """Display DNS client cache with PowerShell"""
    client_interaction_ui.send_command("Get-DnsClientCache | Select-Object Entry, RecordName, RecordType, Status, Section, TimeToLive, Data | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "Displays the DNS client cache entries"
    
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