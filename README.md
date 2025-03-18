# Kinetic Compliance Matrix - C2 Framework

## Project Overview

Kinetic Compliance Matrix (KCM) is a modular and extensible command and control (C2) framework designed for security testing and assessment purposes. This Python-based framework provides a graphical user interface for managing campaigns, configuring agents, and controlling remote client systems.

### Key Features

- **GUI-based operation**: Full graphical interface for campaign management
- **Modular plugin architecture**: Extensible framework for adding new agent types
- **Dynamic path rotation**: Evades detection by rotating communication paths
- **Secure encryption**: Asymmetric encryption with RSA for key exchange and AES-256 for communications
- **Client verification**: System for validating client identities across sessions
- **File operations**: Built-in file upload and download capabilities
- **Certificate management**: Built-in SSL/TLS certificate generation for HTTPS communications

## Architecture Overview

The framework consists of several main components:

1. **Core Components**:
   - `app.py`: Main GUI application
   - `server.py`: HTTP/HTTPS server handling client communications
   - `client.py`: Client management
   - `crypto.py`: Encryption and key management
   - `logging.py`: Logging and event tracking

2. **UI Components**:
   - `campaign_tab.py`: Campaign configuration
   - `agent_config_tab.py`: Agent configuration
   - `agent_tab.py`: Agent generation
   - `client_tab.py`: Client management
   - `certificate_tab.py`: Certificate management

3. **Handlers and Utilities**:
   - `c2_handler.py`: Main HTTP request handler
   - `operation_router.py`: Routes operations based on payload content
   - `path_routing.py`: Manages URL path routing and rotation
   - Various handlers for beacons, file operations, etc.

4. **Plugin System**:
   - `plugin_manager.py`: Manages agent generation plugins
   - `agent_plugin_interface.py`: Interface for creating new agent types

## Getting Started

### Prerequisites

- Python 3.6+
- Required Python packages: tkinter, cryptography

### Running the Application

1. Execute the main script:
   ```bash
   python main.py
   ```

2. Configure a campaign in the "Campaign Config" tab
3. Configure the agent in the "Agent Config" tab
4. Generate agents in the "Agent Generation" tab
5. Manage clients in the "Client Management" tab

## Extending the Framework

### 1. Creating a Plugin

Plugins in KCM allow you to add new agent types. Follow these steps to create a new agent plugin:

1. **Create a new Python file** in the `plugins/agent_plugins` directory
   ```
   plugins/agent_plugins/my_agent_plugin.py
   ```

2. **Implement the AgentPluginInterface**:
   ```python
   from plugins.agent_plugin_interface import AgentPluginInterface

   class MyCustomAgent(AgentPluginInterface):
       @classmethod
       def get_name(cls) -> str:
           """Return the name of this agent type for UI display"""
           return "MyAgent"
       
       @classmethod
       def get_description(cls) -> str:
           """Return a description of this agent type"""
           return "My custom agent implementation"
       
       @classmethod
       def get_options(cls) -> Dict[str, Dict[str, Any]]:
           """Return configuration options for this agent"""
           return {
               "beacon_period": {
                   "type": "int",
                   "default": 5,
                   "description": "Beacon interval in seconds",
                   "required": True
               },
               # Add more configuration options
           }
       
       @classmethod
       def get_agent_capabilities(cls) -> List[str]:
           """Return capabilities supported by this agent"""
           return [
               "file_operations", 
               "dynamic_path_rotation", 
               "secure_key_exchange"
           ]
       
       @classmethod
       def get_supported_platforms(cls) -> List[str]:
           """Return platforms supported by this agent"""
           return ["windows"]
       
       @classmethod
       def generate(cls, config: Dict[str, Any], campaign_settings: Dict[str, Any]) -> Dict[str, Any]:
           """Generate the agent code"""
           # Implement your agent generation logic here
           agent_code = "# Your agent code here"
           
           return {
               "code": agent_code,
               "files": [],  # List of file paths generated
               "instructions": "Instructions for using the agent",
               "summary": "Summary of what was generated"
           }
   ```

3. **Register your plugin** by adding it to the initialization in `plugins/__init__.py`:
   ```python
   def initialize_plugin_system():
       from plugins.plugin_manager import get_plugin_manager
       from plugins.agent_plugins.powershell_agent_v2 import PowerShellAgentV2
       from plugins.agent_plugins.my_agent_plugin import MyCustomAgent  # Add your plugin
       
       plugin_manager = get_plugin_manager()
       plugin_manager.register_plugin(PowerShellAgentV2)
       plugin_manager.register_plugin(MyCustomAgent)  # Register your plugin
       # ...
   ```

### 2. Adding a Command

To add a new command to the framework, follow these steps:

1. **Create a new Python file** in the `commands` directory or add to an existing category file:
   ```
   commands/my_category/my_command.py
   ```

2. **Define your command function**:
   ```python
   def my_command(client_interface, client_id, **kwargs):
       """
       My custom command
       
       Usage: my_command [arg1] [arg2]
       Description: Performs a custom action
       """
       # Implement your command logic here
       # This will be executed when the command is triggered from the UI
       
       # Example: Send a command to the client
       client_interface.send_command("execute", f"Custom-Command -Arg1 Value1 -Arg2 Value2")
       
       # The result will be processed asynchronously when the client responds
   ```

3. **Register your command** by creating a JSON file in the `commands` directory:
   ```
   commands/my_category/commands.json
   ```

4. **Define the command metadata** in the JSON file:
   ```json
   {
       "my_command": {
           "function": "my_command",
           "description": "Performs a custom action",
           "help": "Usage: my_command [arg1] [arg2]",
           "tags": {
               "opsec_safe": true,
               "requires_admin": false,
               "windows": true,
               "linux": false,
               "powershell": true,
               "cmd": false
           }
       }
   }
   ```

5. **Make sure the command loader can find your command** by updating the imports in the command loader.

### 3. Changing the Link Structure

The link structure in KCM determines the URL patterns used for communication. To modify the link structure:

1. **Edit the link pattern files**:
   - `helpers/links/links.txt`: Contains URL patterns (e.g., web_app, api, cdn)
   - `helpers/links/links2.txt`: Contains URL components (e.g., status, ping, resources)

2. **Modify links.txt** to add new URL patterns:
   ```
   web_app
   api
   cdn
   blog
   custom
   my_new_pattern  # Add your new pattern
   ```

3. **Modify links2.txt** to add new URL components:
   ```
   status
   ping
   monitor
   health
   check
   js
   scripts
   resources
   my_new_component  # Add your new component
   ```

4. **Save the files** and restart the application

5. **The path rotation mechanism** will now incorporate your new patterns and components when generating paths for client-server communication.

## Security Considerations

- This framework is intended for legitimate security testing with proper authorization
- It includes strong encryption to protect communications
- Client verification helps prevent unauthorized access
- Implement certificate pinning in production environments

## Troubleshooting

### Common Issues

1. **Key Registration Fails**:
   - Check the server's encryption service is properly initialized
   - Ensure RSA key exchange is working correctly

2. **Path Rotation Issues**:
   - Verify the path pool size is adequate
   - Check the rotation interval settings

3. **Plugin Loading Problems**:
   - Ensure your plugin class properly implements all required methods
   - Check for Python syntax or import errors

## License and Legal

This framework is intended for authorized security testing only. Use responsibly and ensure you have proper permission before deploying in any environment.
