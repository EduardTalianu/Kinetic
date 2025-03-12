def execute(client_interaction_ui, client_id):
    """Execute the tasklist command"""
    # Get process information using WMI
    client_interaction_ui.send_command("Get-WmiObject Win32_Process | Select-Object Name, ProcessId, @{Name='Memory (MB)';Expression={[math]::round($_.WorkingSetSize / 1MB, 2)}}, CommandLine | Format-Table -AutoSize")
    
def get_description():
    """Get command description"""
    return "Display formatted list of running processes"