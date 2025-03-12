def execute(client_interaction_ui, client_id):
    """List installed Windows updates and hotfixes"""
    client_interaction_ui.send_command("Get-HotFix | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "List all installed Windows updates and hotfixes"