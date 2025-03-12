def execute(client_interaction_ui, client_id):
    """Execute the screenshot command"""
    client_interaction_ui.send_command("screenshot", command_type="screenshot")
    
def get_description():
    """Get command description"""
    return "Capture the target's screen"