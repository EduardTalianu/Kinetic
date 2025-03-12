def execute(client_interaction_ui, client_id):
    """Get network connections with PowerShell"""
    # Get network connections using PowerShell
    client_interaction_ui.send_command("Get-NetTCPConnection -State Established,Listen | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "Display active network connections with process info"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard network query, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Uses PowerShell cmdlets, Windows-specific
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }