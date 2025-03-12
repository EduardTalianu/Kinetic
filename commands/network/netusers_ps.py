def execute(client_interaction_ui, client_id):
    """List local users with PowerShell"""
    # Get local users using PowerShell
    client_interaction_ui.send_command("Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "List all local user accounts with details"