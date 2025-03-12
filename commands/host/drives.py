def execute(client_interaction_ui, client_id):
    """Execute the get drives command"""
    client_interaction_ui.send_command("wmic logicaldisk get deviceid, volumename, description")
    
def get_description():
    """Get command description"""
    return "List all disk drives"
