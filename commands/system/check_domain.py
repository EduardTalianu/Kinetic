def execute(client_interaction_ui, client_id):
    """Check if the system is domain-joined"""
    client_interaction_ui.send_command("(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain")
    
def get_description():
    """Get command description"""
    return "Check if the system is joined to an Active Directory domain"