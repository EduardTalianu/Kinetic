# Kinetic Compliance Matrix - Plugin Development Guide

## Introduction

This guide provides comprehensive instructions for developing plugins for the Kinetic Compliance Matrix (KCM) framework. KCM uses a modular plugin architecture that allows you to extend its functionality with new agent types, commands, and features.

## Table of Contents

1. [Plugin Architecture Overview](#plugin-architecture-overview)
2. [Creating Agent Plugins](#creating-agent-plugins)
3. [Adding Custom Commands](#adding-custom-commands)
4. [Modifying Link Structure](#modifying-link-structure)
5. [Testing and Debugging Plugins](#testing-and-debugging-plugins)
6. [Advanced Plugin Development](#advanced-plugin-development)

## Plugin Architecture Overview

The KCM plugin system consists of several key components:

1. **Plugin Manager**: Located in `plugins/plugin_manager.py`, handles loading and managing plugins
2. **Agent Plugin Interface**: Located in `plugins/agent_plugin_interface.py`, defines the interface for agent plugins
3. **Command Loader**: Handles loading and executing custom commands
4. **Path Rotation System**: Manages dynamic URL paths for communication

### Plugin Types

KCM supports several types of plugins:

1. **Agent Plugins**: Generate agent code in different languages and with different capabilities
2. **Command Plugins**: Add new commands that can be executed on client systems
3. **Link Pattern Plugins**: Modify URL patterns used for communication

## Creating Agent Plugins

Agent plugins allow you to create new types of agents with different languages, platforms, or capabilities.

### Step 1: Create Plugin File

Create a new Python file in the `plugins/agent_plugins` directory, e.g., `my_agent_plugin.py`:

```python
from plugins.agent_plugin_interface import AgentPluginInterface
from typing import Dict, Any, List, Optional

class MyAgentPlugin(AgentPluginInterface):
    """My custom agent plugin implementation"""
    
    @classmethod
    def get_name(cls) -> str:
        """Return the name of this agent type for UI display"""
        return "MyAgent"
    
    @classmethod
    def get_description(cls) -> str:
        """Return a description of this agent type"""
        return "A custom agent implementation with specific features"
    
    @classmethod
    def get_options(cls) -> Dict[str, Dict[str, Any]]:
        """
        Return a dictionary of configuration options for this agent type
        
        Format:
        {
            "option_name": {
                "type": "string|int|bool|list",
                "default": default_value,
                "description": "Human-readable description",
                "required": True|False,
                "values": [list, of, possible, values]  # Optional, for list type
            },
            ...
        }
        """
        return {
            "beacon_period": {
                "type": "int",
                "default": 5,
                "description": "Beacon interval in seconds",
                "required": True
            },
            "jitter_percentage": {
                "type": "int",
                "default": 20,
                "description": "Random variation in beacon timing (percentage)",
                "required": True
            },
            "random_sleep_enabled": {
                "type": "bool",
                "default": False,
                "description": "Enable random sleep between operations for OPSEC",
                "required": False
            },
            # Add more configuration options
        }
    
    @classmethod
    def get_agent_capabilities(cls) -> List[str]:
        """Return a list of capabilities this agent type supports"""
        return [
            "file_operations", 
            "dynamic_path_rotation", 
            "secure_key_exchange"
        ]
    
    @classmethod
    def get_supported_platforms(cls) -> List[str]:
        """Return a list of platforms supported by this agent type"""
        return ["windows", "linux"]
    
    @classmethod
    def generate(cls, config: Dict[str, Any], campaign_settings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate the agent using the provided configuration
        
        Args:
            config: Dictionary containing plugin-specific configuration
            campaign_settings: Dictionary containing campaign-wide settings
            
        Returns:
            Dictionary containing:
                "code": Generated agent code
                "files": List of file paths generated (if any)
                "instructions": User instructions (if any)
                "summary": Short summary of what was generated
        """
        # Extract configuration options
        beacon_period = config.get("beacon_period", 5)
        jitter_percentage = config.get("jitter_percentage", 20)
        random_sleep_enabled = config.get("random_sleep_enabled", False)
        output_format = config.get("format", "ps1")
        
        # Extract campaign settings
        server_address = campaign_settings.get("server_address", "")
        rotation_info = campaign_settings.get("rotation_info", None)
        
        # Generate the agent code
        agent_code = cls._generate_agent_code(config, campaign_settings)
        
        # Process output format
        if output_format == "base64":
            encoded_code = cls._encode_to_base64(agent_code)
            result_code = encoded_code
        else:
            result_code = agent_code
        
        # Return the result
        return {
            "code": result_code,
            "files": [],  # List of file paths if multiple files were generated
            "instructions": "Execute this agent on the target system",
            "summary": f"Custom agent for {server_address} with {beacon_period}s beacon interval"
        }
    
    @classmethod
    def _generate_agent_code(cls, config: Dict[str, Any], campaign_settings: Dict[str, Any]) -> str:
        """
        Generate agent code based on configuration
        
        Args:
            config: Plugin-specific configuration
            campaign_settings: Campaign-wide settings
            
        Returns:
            Generated agent code
        """
        # Get template
        template = cls._get_agent_template()
        
        # Extract settings
        server_address = campaign_settings.get("server_address", "")
        beacon_period = config.get("beacon_period", 5)
        jitter_percentage = config.get("jitter_percentage", 20)
        
        # Fill in template placeholders
        agent_code = template.replace("{{SERVER_ADDRESS}}", server_address)
        agent_code = agent_code.replace("{{BEACON_PERIOD}}", str(beacon_period))
        agent_code = agent_code.replace("{{JITTER_PERCENTAGE}}", str(jitter_percentage))
        
        return agent_code
    
    @classmethod
    def _get_agent_template(cls) -> str:
        """Return the embedded agent template"""
        return """
        # My Custom Agent Template
        # Generated by KCM
        
        SERVER_ADDRESS = "{{SERVER_ADDRESS}}"
        BEACON_PERIOD = {{BEACON_PERIOD}}
        JITTER_PERCENTAGE = {{JITTER_PERCENTAGE}}
        
        def main():
            # Agent implementation goes here
            print(f"Connecting to {SERVER_ADDRESS}")
            print(f"Beacon period: {BEACON_PERIOD}s")
            print(f"Jitter: {JITTER_PERCENTAGE}%")
        
        if __name__ == "__main__":
            main()
        """
    
    @classmethod
    def _encode_to_base64(cls, code: str) -> str:
        """Encode code to base64"""
        import base64
        return base64.b64encode(code.encode("utf-8")).decode("utf-8")
```

### Step 2: Register Your Plugin

Update the plugin initialization in `plugins/__init__.py`:

```python
def initialize_plugin_system():
    """Initialize the plugin system by loading all available plugins"""
    # Import the plugin manager
    try:
        from plugins.plugin_manager import get_plugin_manager
        from plugins.agent_plugins.powershell_agent_v2 import PowerShellAgentV2
        from plugins.agent_plugins.my_agent_plugin import MyAgentPlugin  # Import your plugin
        
        # Get the plugin manager instance
        plugin_manager = get_plugin_manager()
        
        # Register the PowerShellAgentV2 plugin
        plugin_manager.register_plugin(PowerShellAgentV2)
        plugin_manager.register_plugin(MyAgentPlugin)  # Register your plugin
        
        # Discover all available plugins
        plugin_manager.discover_plugins()
        
        return True
    except Exception as e:
        logger.error(f"Error initializing plugin system: {e}")
        return False
```

### Step 3: Test Your Plugin

Once registered, your plugin should appear in the Agent Config tab of the KCM GUI. To test it:

1. Launch the KCM application
2. Navigate to "Agent Config" tab
3. Select your agent type from the dropdown
4. Configure the options
5. Save the configuration
6. Navigate to "Agent Generation" tab
7. Generate the agent and verify the output

## Adding Custom Commands

You can extend KCM with custom commands that can be executed on client systems.

### Step 1: Create Command Module

Create a new Python file in the appropriate commands directory (or create a new category):

```python
# commands/my_category/my_command.py

def execute_my_command(client_interface, client_id, args=None):
    """
    Execute my custom command on the client
    
    Args:
        client_interface: Interface for interacting with the client
        client_id: ID of the client to execute on
        args: Command arguments
    """
    # Format the command for the client agent
    command = f"My-CustomCommand -Param1 Value1"
    if args:
        command += f" -CustomArgs {args}"
    
    # Send the command to the client
    client_interface.send_command(client_id, "execute", command)
    
    # Log the action
    client_interface.log_message(f"Sent custom command to client {client_id}: {command}")
```

### Step 2: Create Command Definition

Create or update a JSON file to define your command metadata:

```json
// commands/my_category/commands.json
{
    "my_command": {
        "function": "execute_my_command",
        "description": "Execute a custom command on the client",
        "help": "Usage: my_command [args]",
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

### Step 3: Register Your Command

To ensure your command is loaded correctly, follow these options:

**Option 1**: Place it in an existing command category directory
**Option 2**: Create a new category directory and update the command loader

If creating a new category, you may need to update the command loader:

```python
# commands/command_loader.py
def get_categories(self):
    """Get all available command categories"""
    categories = [
        "system",
        "network",
        "files",
        "my_category"  # Add your new category
    ]
    return categories
```

## Modifying Link Structure

The link structure determines the URL patterns used for communication. Here's how to modify it:

### Step 1: Locate the Link Files

The link structure is defined in two files:
- `helpers/links/links.txt`: URL patterns (e.g., web_app, api, cdn)
- `helpers/links/links2.txt`: URL components (e.g., status, ping, resources)

### Step 2: Modify URL Patterns

Edit `helpers/links/links.txt` to add new URL patterns:

```
web_app
api
cdn
blog
custom
my_new_pattern  # Add your custom pattern
```

### Step 3: Modify URL Components

Edit `helpers/links/links2.txt` to add new URL components:

```
status
ping
monitor
health
check
js
scripts
resources
my_new_component  # Add your custom component
```

### Step 4: Testing

After modifying the link files:

1. Restart the KCM application
2. Create a new campaign or start an existing one
3. Check the logs for path generation activity
4. Monitor how the new patterns and components are being used

### Understanding Path Generation

KCM generates paths by combining patterns and components with random elements. For example:

```
/{pattern}/{component}/{random_string}
```

Where:
- `{pattern}` is chosen from links.txt
- `{component}` is chosen from links2.txt
- `{random_string}` is generated dynamically

Example path: `/web_app/resources/a7f3e9b2`

## Testing and Debugging Plugins

### Plugin Testing

1. **Basic Testing**:
   - Verify the plugin appears in the UI
   - Check configuration options are displayed correctly
   - Generate an agent and examine the output

2. **Agent Testing**:
   - Deploy the generated agent in a controlled environment
   - Verify it connects to the C2 server
   - Test the implemented capabilities

3. **Debugging Techniques**:
   - Add debug logging in your plugin
   - Check the KCM application logs
   - Use a local test server for initial testing

### Common Issues and Solutions

| Issue | Possible Causes | Solutions |
|-------|----------------|-----------|
| Plugin not appearing | Registration failed | Check the initialization code |
| Configuration options not showing | Interface implementation error | Verify get_options() implementation |
| Agent generation fails | Template or code generation error | Add error handling and logging |
| Agent fails to connect | Communication protocol issues | Test network connectivity and protocol |

## Advanced Plugin Development

### Template Generation Techniques

For complex agents, consider these approaches:

1. **Modular Templates**: Break your agent into functional components
   ```python
   def _get_agent_template(cls):
       communication_module = cls._get_communication_template()
       command_module = cls._get_command_template()
       security_module = cls._get_security_template()
       
       return f"""
       # Main agent code
       {communication_module}
       
       {command_module}
       
       {security_module}
       
       # Main execution loop
       main()
       """
   ```

2. **Dynamic Feature Selection**: Generate code based on selected features
   ```python
   def _generate_agent_code(cls, config, campaign_settings):
       template = cls._get_agent_template()
       
       # Conditionally include features
       if config.get("file_operations_enabled", False):
           file_ops_code = cls._get_file_operations_template()
           template += f"\n{file_ops_code}"
       
       if config.get("screenshot_enabled", False):
           screenshot_code = cls._get_screenshot_template()
           template += f"\n{screenshot_code}"
       
       # Fill in placeholders
       # ...
       
       return template
   ```

### Extending the Plugin Interface

You can create more advanced plugins by extending the base plugin interface:

```python
class ExtendedAgentPlugin(AgentPluginInterface):
    @classmethod
    def get_advanced_options(cls):
        """Add custom advanced options"""
        return {
            "custom_option": "value"
        }
    
    @classmethod
    def get_platform_specific_options(cls, platform):
        """Return platform-specific options"""
        if platform == "windows":
            return {
                # Windows-specific options
            }
        elif platform == "linux":
            return {
                # Linux-specific options
            }
        return {}
```

### Creating Multi-Stage Agents

For more complex agents that require multiple stages:

```python
def generate(cls, config, campaign_settings):
    # Generate first stage (stager)
    stager_code = cls._generate_stager(config, campaign_settings)
    
    # Generate second stage (full agent)
    agent_code = cls._generate_agent_code(config, campaign_settings)
    
    # Return both components
    return {
        "code": stager_code,  # First stage for delivery
        "files": [
            {"name": "stage1.txt", "content": stager_code},
            {"name": "stage2.txt", "content": agent_code}
        ],
        "instructions": "Deploy the first stage, which will download and execute the second stage.",
        "summary": "Multi-stage agent generated"
    }
```

---

*Note: This framework is intended for authorized security testing only. Always ensure proper authorization before deployment in any environment.*
