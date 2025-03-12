def execute(client_interaction_ui, client_id):
    """Execute the domain users command"""
    client_interaction_ui.send_command("net user /domain")
    
def get_description():
    """Get command description"""
    return "List all domain user accounts"