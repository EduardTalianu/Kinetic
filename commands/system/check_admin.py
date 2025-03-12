def execute(client_interaction_ui, client_id):
    """Check if running with admin privileges"""
    client_interaction_ui.send_command("[bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544')")
    
def get_description():
    """Get command description"""
    return "Check if the client is running with administrative privileges"