def execute(client_interaction_ui, client_id):
    """Execute the tasklist command"""
    client_interaction_ui.send_command("tasklist")
    
def get_description():
    """Get command description"""
    return "Display all running processes"