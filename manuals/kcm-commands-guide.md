# Kinetic Compliance Matrix - Command Development Guide

## Introduction

This guide provides step-by-step instructions for adding new commands to the Kinetic Compliance Matrix (KCM) framework. KCM uses a simple, directory-based approach for command management, making it easy to add new functionality without modifying the core application.

## Command System Overview

Commands in KCM are organized into categories, with each category represented by a directory under the `commands` folder. The command loader automatically discovers and loads commands based on this directory structure.

### Directory Structure

```
commands/
├── system/
│   ├── commands.json
│   ├── whoami.py
│   └── system_info.py
├── network/
│   ├── commands.json
│   ├── ping.py
│   └── port_scan.py
├── files/
│   ├── commands.json
│   ├── download.py
│   └── upload.py
└── your_category/
    ├── commands.json
    └── your_command.py
```

## Adding a New Command

### Step 1: Choose or Create a Category

First, decide which category your command belongs to. You can either:
- Use an existing category (system, network, files, etc.)
- Create a new category by making a new directory under `commands/`

For example, to create a custom "persistence" category:
```bash
mkdir commands/persistence
```

### Step 2: Create the Command Implementation

Create a Python file in your chosen category directory. Name the file after your command (e.g., `add_registry_key.py`).

```python
# commands/persistence/add_registry_key.py

def add_registry_key(client_interface, client_id, key_path=None, key_name=None, key_value=None):
    """
    Add a registry key for persistence
    
    Args:
        client_interface: Interface for sending commands to the client
        client_id: ID of the client to execute the command on
        key_path: Registry path (e.g., HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)
        key_name: Name of the registry key
        key_value: Value to set
    """
    # Validate arguments
    if not key_path or not key_name or not key_value:
        client_interface.append_output("Error: Missing required parameters", color="#FF0000")
        client_interface.append_output("Usage: add_registry_key [key_path] [key_name] [key_value]", color="#FFCC00")
        return
    
    # Format the PowerShell command
    ps_command = f"New-ItemProperty -Path '{key_path}' -Name '{key_name}' -Value '{key_value}' -PropertyType 'String' -Force"
    
    # Log the action
    client_interface.append_output(f"Adding registry key: {key_path}\\{key_name}", color="#00FFFF")
    
    # Send the command to the client
    client_interface.send_command(client_id, "execute", ps_command)
```

### Step 3: Create or Update the commands.json File

Each category needs a `commands.json` file that defines the metadata for all commands in that category. Create or update this file:

```json
{
  "add_registry_key": {
    "function": "add_registry_key",
    "description": "Add a registry key for persistence",
    "help": "Usage: add_registry_key [key_path] [key_name] [key_value]",
    "tags": {
      "opsec_safe": false,
      "requires_admin": true,
      "windows": true,
      "linux": false,
      "powershell": true,
      "cmd": false
    }
  }
}
```

The JSON structure contains:
- **Key**: The command name (must match the function name)
- **function**: The function name to call
- **description**: Brief description shown in the UI
- **help**: Usage instructions
- **tags**: Metadata for filtering and categorization
  - **opsec_safe**: Whether the command is safe from an operational security perspective
  - **requires_admin**: Whether admin privileges are required
  - **windows/linux**: Platform compatibility
  - **powershell/cmd**: Command interpreter requirements

### Step 4: Create Multiple Commands in One File (Optional)

You can define multiple related commands in a single file:

```python
# commands/persistence/registry_operations.py

def add_registry_key(client_interface, client_id, key_path=None, key_name=None, key_value=None):
    """Add a registry key for persistence"""
    # Implementation as shown above
    pass

def remove_registry_key(client_interface, client_id, key_path=None, key_name=None):
    """Remove a registry key"""
    # Validate arguments
    if not key_path or not key_name:
        client_interface.append_output("Error: Missing required parameters", color="#FF0000")
        client_interface.append_output("Usage: remove_registry_key [key_path] [key_name]", color="#FFCC00")
        return
    
    # Format the PowerShell command
    ps_command = f"Remove-ItemProperty -Path '{key_path}' -Name '{key_name}' -Force"
    
    # Log the action
    client_interface.append_output(f"Removing registry key: {key_path}\\{key_name}", color="#00FFFF")
    
    # Send the command to the client
    client_interface.send_command(client_id, "execute", ps_command)
```

Then update the `commands.json` file to include both commands:

```json
{
  "add_registry_key": {
    "function": "add_registry_key",
    "description": "Add a registry key for persistence",
    "help": "Usage: add_registry_key [key_path] [key_name] [key_value]",
    "tags": {
      "opsec_safe": false,
      "requires_admin": true,
      "windows": true,
      "linux": false,
      "powershell": true,
      "cmd": false
    }
  },
  "remove_registry_key": {
    "function": "remove_registry_key",
    "description": "Remove a registry key",
    "help": "Usage: remove_registry_key [key_path] [key_name]",
    "tags": {
      "opsec_safe": false,
      "requires_admin": true,
      "windows": true,
      "linux": false,
      "powershell": true,
      "cmd": false
    }
  }
}
```

## Command Function Parameters

Every command function must accept these parameters:

1. **client_interface**: An object for interacting with the client
2. **client_id**: The ID of the client to execute the command on
3. **Additional parameters**: Optional parameters specific to your command

### The client_interface Object

The `client_interface` provides methods for:

- **send_command(client_id, command_type, args)**: Send a command to the client
- **append_output(text, color=None)**: Add text to the output console
- **log_message(message)**: Log a message to the application log

## Creating Platform-Specific Commands

For commands that should work on multiple platforms with different implementations:

```python
# commands/cross_platform/get_system_info.py

def get_system_info(client_interface, client_id):
    """Get detailed system information"""
    # Get client information to determine OS
    client_info = client_interface.client_manager.get_clients_info().get(client_id, {})
    os_version = client_info.get("system_info", {}).get("OsVersion", "").lower()
    
    # Choose appropriate command based on OS
    if "windows" in os_version:
        command = "Get-ComputerInfo | ConvertTo-Json"
        client_interface.append_output("Getting Windows system information...", color="#00FFFF")
    elif "linux" in os_version:
        command = "uname -a; lscpu; free -h; df -h"
        client_interface.append_output("Getting Linux system information...", color="#00FFFF")
    else:
        # Default/fallback command
        command = "systeminfo"
        client_interface.append_output("Getting generic system information...", color="#FFCC00")
    
    # Send the command
    client_interface.send_command(client_id, "execute", command)
```

## Adding New Command Categories

To add a completely new command category:

1. Create a new directory under `commands/`
2. Add your command files
3. Create a `commands.json` file
4. Restart the application

The command loader will automatically discover the new category and commands.

## Implementing Advanced Commands

### Commands with Interactive Elements

For commands that require interaction with the user:

```python
# commands/interactive/prompt_user.py

def prompt_user(client_interface, client_id, message=None):
    """Display a prompt to the user on the client system"""
    if not message:
        message = "User input required"
    
    # Create a PowerShell script to show a prompt
    ps_script = f"""
    Add-Type -AssemblyName System.Windows.Forms
    $result = [System.Windows.Forms.MessageBox]::Show(
        "{message}", 
        "KCM Prompt", 
        [System.Windows.Forms.MessageBoxButtons]::OKCancel, 
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    return $result
    """
    
    # Send the command
    client_interface.append_output(f"Displaying prompt to user: {message}", color="#00FFFF")
    client_interface.send_command(client_id, "execute", ps_script)
```

### File Operations Commands

For commands that handle file uploads or downloads:

```python
# commands/files/download_file.py

def download_file(client_interface, client_id, remote_path=None):
    """Download a file from the client to the server"""
    if not remote_path:
        client_interface.append_output("Error: Missing file path", color="#FF0000")
        client_interface.append_output("Usage: download_file [remote_path]", color="#FFCC00")
        return
    
    # Create a PowerShell command to read the file
    ps_command = f"Download-File -FilePath '{remote_path}'"
    
    # Log the action
    client_interface.append_output(f"Downloading file: {remote_path}", color="#00FFFF")
    
    # Send the command
    client_interface.send_command(client_id, "execute", ps_command)
```

## Testing Your Commands

To test your new commands:

1. Start or restart the KCM application
2. Navigate to the "Client Management" tab
3. Select a client
4. Open the "Interaction" tab
5. Your new commands should appear in their respective categories
6. Click on a command to execute it, or type it in the console

## Command Best Practices

For reliable, secure commands:

1. **Input Validation**: Always validate parameters
2. **Error Handling**: Provide useful error messages
3. **User Feedback**: Display status information
4. **OPSEC Considerations**: Tag commands appropriately for operational security
5. **Documentation**: Include detailed help and description

## Troubleshooting

Common issues and solutions:

| Issue | Possible Causes | Solutions |
|-------|----------------|-----------|
| Command not appearing | commands.json issue | Check syntax and formatting |
| Function not found | Function name mismatch | Ensure function name matches JSON entry |
| Command execution error | Syntax or logic issue | Test the command locally first |
| Platform incompatibility | OS-specific features | Add platform checking code |

## Examples

### System Information Command

```python
# commands/system/advanced_info.py

def get_advanced_info(client_interface, client_id):
    """Get advanced system information including hardware details"""
    # PowerShell command to gather detailed information
    ps_command = """
    $info = @{
        ComputerName = $env:COMPUTERNAME
        OS = [System.Environment]::OSVersion.VersionString
        ProcessorCount = [System.Environment]::ProcessorCount
        TotalMemory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
        Username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Domain = (Get-CimInstance Win32_ComputerSystem).Domain
        Drives = Get-Volume | Where-Object {$_.DriveLetter} | Select-Object DriveLetter, FileSystemLabel, Size, SizeRemaining
        NetworkAdapters = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object Name, InterfaceDescription, MacAddress, LinkSpeed
        InstalledSoftware = Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | 
                            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
                            Where-Object {$_.DisplayName} | 
                            Select-Object -First 20
    }
    return $info | ConvertTo-Json -Depth 3
    """
    
    # Send the command
    client_interface.append_output("Gathering advanced system information...", color="#00FFFF")
    client_interface.send_command(client_id, "execute", ps_command)
```

### Network Scanning Command

```python
# commands/network/port_scan.py

def port_scan(client_interface, client_id, target=None, ports=None):
    """Scan a target for open ports"""
    if not target:
        client_interface.append_output("Error: Missing target", color="#FF0000")
        client_interface.append_output("Usage: port_scan [target] [ports]", color="#FFCC00")
        return
    
    if not ports:
        ports = "22,80,443,3389,445,139,135"
    
    # PowerShell command for port scanning
    ps_command = f"""
    $target = "{target}"
    $ports = @({ports})
    $results = @()
    
    foreach ($port in $ports) {{
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connection = $tcp.BeginConnect($target, $port, $null, $null)
        $wait = $connection.AsyncWaitHandle.WaitOne(100, $false)
        
        if ($wait) {{
            $tcp.EndConnect($connection)
            $results += [PSCustomObject]@{{
                Target = $target
                Port = $port
                Status = "Open"
            }}
        }} else {{
            $results += [PSCustomObject]@{{
                Target = $target
                Port = $port
                Status = "Closed"
            }}
        }}
        $tcp.Close()
    }}
    
    return $results | ConvertTo-Json
    """
    
    # Send the command
    client_interface.append_output(f"Scanning {target} on ports {ports}...", color="#00FFFF")
    client_interface.send_command(client_id, "execute", ps_command)
```

---

*Note: This framework is intended for authorized security testing only. Always ensure proper authorization before deployment in any environment.*
