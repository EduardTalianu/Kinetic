def execute(client_interaction_ui, client_id):
    """Execute the whoami command"""
    client_interaction_ui.send_command("whoami")

def get_description():
    """Get command description"""
    return "Display the current username"