def execute(client_interaction_ui, client_id):
    """Execute the netstat command"""
    client_interaction_ui.send_command("netstat -ano")
    
def get_description():
    """Get command description"""
    return "Display active network connections"