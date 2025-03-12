def execute(client_interaction_ui, client_id):
    """Execute the scheduled tasks command"""
    client_interaction_ui.send_command("schtasks /query /fo LIST /v")
    
def get_description():
    """Get command description"""
    return "List all scheduled tasks"