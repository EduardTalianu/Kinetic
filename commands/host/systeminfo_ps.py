def execute(client_interaction_ui, client_id):
    """Execute the systeminfo command"""
    # Get system information using WMI
    client_interaction_ui.send_command("Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture, CSName, LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory | Format-List")
    
def get_description():
    """Get command description"""
    return "Display detailed system information"