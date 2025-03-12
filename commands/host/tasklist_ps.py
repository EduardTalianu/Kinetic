def execute(client_interaction_ui, client_id):
    """Execute the tasklist command"""
    # Get process information using WMI
    client_interaction_ui.send_command("Get-WmiObject Win32_Process | Select-Object Name, ProcessId, @{Name='Memory (MB)';Expression={[math]::round($_.WorkingSetSize / 1MB, 2)}}, CommandLine | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "Display formatted list of running processes"

def get_tags():
    """Get command tags for categorization and filtering"""
    return {
        "opsec_safe": True,      # Standard system command, low detection risk
        "requires_admin": False, # Does not require admin privileges
        "windows": True,         # Works on Windows
        "linux": False,          # Uses PowerShell and WMI, Windows-specific
        "powershell": True,      # Is a PowerShell command
        "cmd": False             # Not a CMD command
    }