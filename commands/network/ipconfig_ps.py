def execute(client_interaction_ui, client_id):
    """Get network configuration with PowerShell"""
    # Get network configuration using PowerShell
    client_interaction_ui.send_command("Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "Display network configuration details"