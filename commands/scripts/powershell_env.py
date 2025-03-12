def execute(client_interaction_ui, client_id):
    """Show PowerShell environment variables"""
    # Get environment variables using PowerShell
    client_interaction_ui.send_command("Get-ChildItem env: | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "List all environment variables"