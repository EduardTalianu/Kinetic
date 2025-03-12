def execute(client_interaction_ui, client_id):
    """List domain groups with PowerShell"""
    # PowerShell command to list domain groups if domain joined
    script = """
    try {
        if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
            Get-ADGroup -Filter * | Select-Object Name, GroupCategory, GroupScope | Format-Table -AutoSize
        } else {
            Write-Output "This computer is not joined to a domain."
        }
    } catch {
        Write-Output "Error: $_"
        Write-Output "Note: The ActiveDirectory module may not be installed."
    }
    """
    client_interaction_ui.send_command(script)
    
def get_description():
    """Get command description"""
    return "List all domain groups (requires AD module)"