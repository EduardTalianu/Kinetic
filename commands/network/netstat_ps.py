def execute(client_interaction_ui, client_id):
    """Get network connections with PowerShell"""
    # Get network connections using PowerShell
    client_interaction_ui.send_command("Get-NetTCPConnection -State Established,Listen | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "Display active network connections with process info"