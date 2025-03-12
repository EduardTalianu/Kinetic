def execute(client_interaction_ui, client_id):
    """Execute the ipconfig command"""
    client_interaction_ui.send_command("ipconfig /all")
    
def get_description():
    """Get command description"""
    return "Display network configuration"
