def execute(client_interaction_ui, client_id):
    """Execute the systeminfo command"""
    client_interaction_ui.send_command("systeminfo")
    
def get_description():
    """Get command description"""
    return "Display detailed system information"