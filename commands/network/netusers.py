def execute(client_interaction_ui, client_id):
    """Execute the net user command"""
    client_interaction_ui.send_command("net user")
    
def get_description():
    """Get command description"""
    return "List all local user accounts"