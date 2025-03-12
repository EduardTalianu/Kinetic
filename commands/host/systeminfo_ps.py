def execute(client_interaction_ui, client_id):
    """Execute the systeminfo command"""
    # Get system information using WMI
    client_interaction_ui.send_command("Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture, CSName, LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory | Format-List")
    
def get_description():
    """Get command description"""
    return "Display detailed system information"

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