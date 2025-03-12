def execute(client_interaction_ui, client_id):
    """Execute the PowerShell environment command"""
    client_interaction_ui.send_command("Get-ChildItem env:")
    
def get_description():
    """Get command description"""
    return "List all environment variables"