def execute(client_interaction_ui, client_id):
    """Kill a process by name"""
    # PowerShell script with UI to kill a process
    process_kill_script = """
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProcessName
    )
    
    try {
        $processes = Get-Process -Name $ProcessName -ErrorAction Stop
        foreach ($process in $processes) {
            Write-Output "Killing process: $($process.Name) (PID: $($process.Id))"
            $process.Kill()
        }
        Write-Output "Successfully terminated $($processes.Count) process(es) named '$ProcessName'"
    } catch {
        Write-Output "Error: $_"
    }
    
    # For interactive usage, you would call this with a process name:
    # e.g.: process_kill.ps1 -ProcessName "notepad"
    """
    
    # First provide the script for reference
    client_interaction_ui.send_command(process_kill_script)
    
    # Then prompt the user for the process name
    process_name = "notepad"  # Default example
    client_interaction_ui.append_output("\nTo use this command: Send a new command with the process name to kill.")
    client_interaction_ui.append_output("Example: Stop-Process -Name notepad -Force\n")
    
def get_description():
    """Get command description"""
    return "Kill a process by name (provides a script template)"