def execute(client_interaction_ui, client_id):
    """Execute the whoami command"""
    # Simple command that works in PowerShell
    client_interaction_ui.send_command("[System.Security.Principal.WindowsIdentity]::GetCurrent().Name")

def get_description():
    """Get command description"""
    return "Display the current username"