def execute(client_interaction_ui, client_id):
    """Execute the domain controllers command"""
    client_interaction_ui.send_command("nltest /dclist:")
    
def get_description():
    """Get command description"""
    return "List domain controllers"