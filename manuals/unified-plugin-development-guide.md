# Kinetic Compliance Matrix - Unified Plugin Development Guide

## Introduction

This guide provides comprehensive instructions for developing plugins for the Kinetic Compliance Matrix (KCM) framework. KCM uses a modular plugin architecture that allows you to extend its functionality with new agent types, commands, and features.

## Table of Contents

1. [Plugin Architecture Overview](#plugin-architecture-overview)
2. [Creating Agent Plugins](#creating-agent-plugins)
3. [Communication Protocol](#communication-protocol)
4. [Agent Plugin Implementation](#agent-plugin-implementation)
5. [Testing and Debugging](#testing-and-debugging)
6. [Advanced Plugin Development](#advanced-plugin-development)

## Plugin Architecture Overview

The KCM plugin system consists of several key components:

1. **Plugin Manager**: Located in `plugins/plugin_manager.py`, handles loading and managing plugins
2. **Agent Plugin Interface**: Located in `plugins/agent_plugin_interface.py`, defines the interface for agent plugins
3. **Base Agent Plugin**: Located in `plugins/base_agent_plugin.py`, provides common functionality for agent plugins
4. **Path Rotation System**: Manages dynamic URL paths for communication

### Plugin Types

KCM primarily focuses on agent plugins, which generate agent code in different languages and with different capabilities.

## Creating Agent Plugins

There are two main approaches to creating a new agent plugin:

1. **Using the BaseAgentPlugin** (Recommended): Inherit from `BaseAgentPlugin` which provides common functionality
2. **Custom Implementation**: Implement the `AgentPluginInterface` directly for more control

### Using BaseAgentPlugin (Recommended)

The `BaseAgentPlugin` class provides a standardized implementation of common functionality. This simplifies plugin development by allowing you to focus on the agent-specific code.

```python
from plugins.base_agent_plugin import BaseAgentPlugin
import os
import base64
import json

class YourAgentPlugin(BaseAgentPlugin):
    """Your Agent plugin description"""
    
    @classmethod
    def get_name(cls) -> str:
        """Return the name of this agent type for UI display"""
        return "YourAgentName"
    
    @classmethod
    def get_description(cls) -> str:
        """Return a description of this agent type"""
        return "Description of your agent and its capabilities"
    
    @classmethod
    def get_options(cls) -> dict:
        """Return configuration options for this agent type"""
        return {
            "beacon_period": {
                "type": "int",
                "default": 30,
                "description": "Beacon interval in seconds",
                "required": True
            },
            "jitter_percentage": {
                "type": "int",
                "default": 20,
                "description": "Random variation in beacon timing (percentage)",
                "required": True
            },
            # Add your custom options
        }
    
    @classmethod
    def get_agent_capabilities(cls) -> list:
        """Return capabilities supported by this agent"""
        return [
            "dynamic_path_rotation", 
            "secure_key_exchange",
            "command_execution",
            # Add any custom capabilities
        ]
    
    @classmethod
    def get_supported_platforms(cls) -> list:
        """Return platforms supported by this agent"""
        return ["windows", "linux", "macos"]  # Update as needed
    
    @classmethod
    def get_file_extension(cls) -> str:
        """Get the file extension for this agent type"""
        return "js"  # Update as needed
    
    @classmethod
    def get_template_code(cls, config: dict, campaign_settings: dict) -> str:
        """Return the template code for this agent with placeholders"""
        return """
// Your agent code here with placeholders:
// {{SERVER_ADDRESS}} - Will be replaced with the server address
// {{PROTOCOL}} - Will be replaced with http/https
// {{PATH_POOL}} - Will be replaced with the path pool JSON
// {{ROTATION_ID}} - Will be replaced with current rotation ID
// {{NEXT_ROTATION_TIME}} - Will be replaced with next rotation time
// {{ROTATION_INTERVAL}} - Will be replaced with rotation interval
// {{BEACON_PERIOD}} - Will be replaced with beacon period from config
// {{JITTER_PERCENTAGE}} - Will be replaced with jitter percentage from config
"""
```

### Custom Implementation

For more advanced scenarios, you can implement the `AgentPluginInterface` directly:

```python
from plugins.agent_plugin_interface import AgentPluginInterface
from typing import Dict, Any, List, Optional

class MyCustomAgentPlugin(AgentPluginInterface):
    """My completely custom agent plugin implementation"""
    
    @classmethod
    def get_name(cls) -> str:
        """Return the name of this agent type for UI display"""
        return "MyCustomAgent"
    
    @classmethod
    def get_description(cls) -> str:
        """Return a description of this agent type"""
        return "A completely custom agent implementation"
    
    @classmethod
    def get_options(cls) -> Dict[str, Dict[str, Any]]:
        """Return configuration options for this agent"""
        return {
            # Define your options
        }
    
    @classmethod
    def get_agent_capabilities(cls) -> List[str]:
        """Return capabilities supported by this agent"""
        return [
            # Define your capabilities
        ]
    
    @classmethod
    def get_supported_platforms(cls) -> List[str]:
        """Return platforms supported by this agent"""
        return [
            # Define your supported platforms
        ]
    
    @classmethod
    def generate(cls, config: Dict[str, Any], campaign_settings: Dict[str, Any]) -> Dict[str, Any]:
        """Generate the agent using the provided configuration"""
        # Implement your custom generation logic
        return {
            "code": "your_generated_code",
            "files": [],
            "instructions": "instructions_for_user",
            "summary": "summary_of_agent"
        }
```

## Communication Protocol

The communication protocol between KCM agents and the server is critical for proper operation. All agents must implement this protocol correctly.

### Key Protocol Elements

1. **First Contact Protocol**:
   - First beacon must include the `f: true` flag (short for "first_contact")
   - Server will respond with its RSA public key
   - Client generates an AES key, encrypts it with the server's public key
   - Client registers the key at `/client/service/registration`

2. **Standard Operation**:
   - Use the path pool for all communication (not fixed paths)
   - Encrypt operation data using the established AES key
   - Include random token padding for OPSEC

3. **Message Field Naming**:
   - Use short field names for OPSEC: `d` for data, `t` for token, etc.
   - Wrap operations in `op_type` and `payload` fields

4. **Path Rotation**:
   - Store and use the path pool for communication
   - Update paths when a path_rotation command is received

### Request Format

First Contact Request:
```json
{
  "c": "client_id",   
  "f": true,
  "d": "{system_info_json}",
  "t": "random_token_padding"
}
```

Standard Operation Request:
```json
{
  "d": "encrypted_operation_json",
  "t": "random_token_padding"
}
```

Where the operation before encryption would be:
```json
{
  "op_type": "beacon",
  "payload": {system_info_object}
}
```

### Response Format

First Contact Response:
```json
{
  "com": [{command_objects}],
  "f": true,
  "c": "assigned_client_id",
  "pubkey": "server_rsa_public_key_base64",
  "r": {
    "cid": current_rotation_id,
    "nrt": next_rotation_time
  },
  "t": "random_token_padding"
}
```

Standard Operation Response:
```json
{
  "com": "encrypted_commands_json",
  "e": true,
  "r": {
    "cid": current_rotation_id,
    "nrt": next_rotation_time
  },
  "t": "random_token_padding"
}
```

### Key Registration

Key registration request (to `/client/service/registration`):
```json
{
  "encrypted_key": "rsa_encrypted_aes_key_base64",
  "client_id": "client_id",
  "nonce": "random_nonce"
}
```

## Agent Plugin Implementation

Follow these steps to create a complete agent plugin:

### Step 1: Create Plugin File

Create a new Python file in the `plugins/agent_plugins` directory.

### Step 2: Decide on Base Class

Determine whether to extend `BaseAgentPlugin` (recommended) or implement `AgentPluginInterface` directly.

### Step 3: Implement Required Methods

Implement all required methods for your chosen base class:

- `get_name()`: Return the display name of your agent
- `get_description()`: Return a human-readable description
- `get_options()`: Define configuration options
- `get_agent_capabilities()`: List supported capabilities
- `get_supported_platforms()`: List supported platforms

If using `BaseAgentPlugin`, also implement:
- `get_template_code()`: Return your agent template with placeholders
- `get_file_extension()`: Return the appropriate file extension

If implementing `AgentPluginInterface` directly, you must also implement:
- `generate()`: Generate the agent code and return a result dictionary

### Step 4: Create Agent Template

Create a template for your agent in the language of your choice (PowerShell, JavaScript, Python, etc.). Ensure it properly implements the communication protocol described above.

The template should handle:
- Secure key exchange
- Path rotation
- Command execution
- Proper communication format

### Step 5: Test Your Plugin

Once implemented, test your plugin via the KCM interface:
1. Restart KCM to load your plugin
2. Go to the Agent tab
3. Select your agent type
4. Configure options
5. Generate and test the agent

## Testing and Debugging

### Testing Approach

1. **Load Testing**: Verify your plugin loads correctly:
   ```
   INFO: Loaded plugin: YourAgentName from your_agent_plugin.py
   ```

2. **UI Testing**: Verify your plugin appears in the UI with correct options

3. **Generation Testing**: Test agent generation:
   - Configuration handling
   - Template substitution
   - Proper output format

4. **Connectivity Testing**: Test agent communication:
   - First contact protocol
   - Key exchange
   - Command execution
   - Path rotation

### Common Issues and Solutions

| Issue | Possible Causes | Solutions |
|-------|----------------|-----------|
| Plugin not loading | Import error, syntax error | Check Python syntax, file location |
| Options not showing | Incorrect `get_options()` implementation | Verify dictionary format |
| Agent generation fails | Template placeholders missing | Check template placeholders |
| Agent fails to connect | Protocol implementation issues | Verify communication protocol |
| Decryption fails | Key exchange issues | Test key registration process |

### Debugging Approach

1. Add extensive logging in your plugin:
   ```python
   import logging
   logger = logging.getLogger(__name__)
   logger.info("Debugging message")
   ```

2. Use the KCM logging system in the UI to monitor agent activity

3. Test specific components separately:
   - Test template generation
   - Test placeholder replacement
   - Test encryption/decryption

## Advanced Plugin Development

### Modular Template Design

For complex agents, break your template into functional modules:

```python
@classmethod
def get_template_code(cls, config, campaign_settings):
    comm_module = cls._get_communication_module()
    file_ops_module = cls._get_file_operations_module()
    command_module = cls._get_command_module()
    
    template = f"""
    // Main agent code
    {comm_module}
    
    // File operations
    {file_ops_module}
    
    // Command execution
    {command_module}
    
    // Main loop
    init();
    """
    
    return template
```

### Conditional Features

Add conditional features based on configuration:

```python
@classmethod
def _generate_agent_code(cls, config, campaign_settings):
    template = cls.get_template_code(config, campaign_settings)
    
    # Add features based on configuration
    if config.get("file_operations_enabled", False):
        template = template.replace("{{FILE_OPERATIONS}}", cls._get_file_operations_code())
    else:
        template = template.replace("{{FILE_OPERATIONS}}", "// File operations disabled")
    
    # Process other placeholders
    # ...
    
    return template
```

### Multi-Stage Agents

For agents that require multiple stages (e.g., stager and main payload):

```python
@classmethod
def generate(cls, config, campaign_settings):
    # Generate stager
    stager_code = cls._generate_stager(config, campaign_settings)
    
    # Generate main agent
    agent_code = cls._generate_agent_code(config, campaign_settings)
    
    # Save to files if campaign folder provided
    files = []
    if "campaign_folder" in campaign_settings:
        # Save stager
        stager_path = os.path.join(campaign_settings["campaign_folder"], "stager.js")
        with open(stager_path, 'w') as f:
            f.write(stager_code)
        files.append(stager_path)
        
        # Save main agent
        agent_path = os.path.join(campaign_settings["campaign_folder"], "agent.js")
        with open(agent_path, 'w') as f:
            f.write(agent_code)
        files.append(agent_path)
    
    # Return result
    return {
        "code": stager_code,  # Return stager as primary code
        "files": files,
        "instructions": "Deploy the stager first, which will download and execute the main agent.",
        "summary": "Multi-stage agent generated"
    }
```

### Obfuscation Techniques

Add obfuscation for improved OPSEC:

```python
@classmethod
def _obfuscate_javascript(cls, js_code):
    """Basic JavaScript obfuscation"""
    # Replace function names
    js_code = js_code.replace("getSystemInfo", "_gsi")
    js_code = js_code.replace("sendBeacon", "_sb")
    
    # Encode strings
    import base64
    strings = re.findall(r'"([^"]*)"', js_code)
    for s in strings:
        encoded = base64.b64encode(s.encode()).decode()
        js_code = js_code.replace(f'"{s}"', f'atob("{encoded}")')
    
    return js_code
```

## Example Reference Implementation

The PowerShell agent plugin (`powershell_agent_v2.py`) serves as a reference implementation. Key elements to study include:

1. Plugin structure and class methods
2. Template organization
3. Configuration handling
4. Communication protocol implementation
5. Proper encryption/decryption
6. Path rotation handling
7. Command execution

By studying this reference implementation and following this guide, you should be able to create your own fully functional agent plugins for the KCM framework.

---

*Note: This framework is intended for authorized security testing only. Always ensure proper authorization before deployment in any environment.*
