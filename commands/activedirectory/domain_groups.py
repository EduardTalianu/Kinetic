def execute(client_interaction_ui, client_id):
    """Execute the domain groups command"""
    client_interaction_ui.send_command("net group /domain")
    
def get_description():
    """Get command description"""
    return "List all domain groups"