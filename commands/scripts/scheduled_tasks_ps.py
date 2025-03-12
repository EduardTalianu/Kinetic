def execute(client_interaction_ui, client_id):
    """List scheduled tasks with PowerShell"""
    # Get scheduled tasks using PowerShell
    client_interaction_ui.send_command("Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskName, TaskPath, State, Author | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "List all active scheduled tasks"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard system query, low detection risk
        "requires_admin": False, # Does not require admin privileges for listing tasks
        "windows": True,         # Works on Windows
        "linux": False,          # Uses PowerShell cmdlets, Windows-specific
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }