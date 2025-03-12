def execute(client_interaction_ui, client_id):
    """List scheduled tasks with PowerShell"""
    # Get scheduled tasks using PowerShell
    client_interaction_ui.send_command("Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskName, TaskPath, State, Author | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "List all active scheduled tasks"