def execute(client_interaction_ui, client_id):
    """Execute the system identification command"""
    client_interaction_ui.send_command("Get-SystemIdentification", command_type="system_info")
    
def get_description():
    """Get command description"""
    return "Get detailed system identification"