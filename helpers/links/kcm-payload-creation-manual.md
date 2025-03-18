# Kinetic Compliance Matrix - Payload Creation Manual

## Introduction

This manual provides comprehensive guidance on creating, configuring, and deploying payloads using the Kinetic Compliance Matrix (KCM) framework. The guide covers both using the built-in payload generation features and developing custom payload plugins.

## Table of Contents

1. [Understanding KCM Payloads](#understanding-kcm-payloads)
2. [Using the GUI Payload Generator](#using-the-gui-payload-generator)
3. [Payload Configuration Options](#payload-configuration-options)
4. [Custom Payload Plugin Development](#custom-payload-plugin-development)
5. [Payload Testing and Troubleshooting](#payload-testing-and-troubleshooting)
6. [Advanced Techniques](#advanced-techniques)
7. [OPSEC Considerations](#opsec-considerations)

## Understanding KCM Payloads

### Payload Architecture

KCM payloads consist of three main components:

1. **Communication Component**: Handles network communication, including protocol implementation, encryption, and path rotation.
2. **Execution Component**: Processes and executes commands received from the C2 server.
3. **Security Component**: Implements encryption, key exchange, and security features.

### Available Payload Types

The default installation includes:

- **PowerShell**: Full-featured PowerShell-based agent with secure key exchange, dynamic path rotation, and file operations.
- Custom payloads can be added via the plugin system.

### Payload Lifecycle

1. **Initial Execution**: Payload establishes first contact with C2 server
2. **Key Exchange**: Secure encrypted channel established
3. **Beaconing**: Regular check-ins with the server for new commands
4. **Command Execution**: Processing and executing received commands
5. **Termination**: Based on kill date or explicit termination command

## Using the GUI Payload Generator

### Step 1: Configure Campaign

1. Launch the KCM application
2. Navigate to "Campaign Config" tab
3. Enter campaign details:
   - Campaign Name
   - C&C IP and Port
   - SSL settings (optional)
4. Click "Start Campaign"

### Step 2: Configure Agent

1. Navigate to "Agent Config" tab
2. Select agent type (PowerShell, etc.)
3. Configure settings:
   - Beacon Period (seconds)
   - Jitter Percentage (randomization factor)
   - Kill Date
   - Advanced options as needed
4. Click "Save Configuration"

### Step 3: Generate Agent

1. Navigate to "Agent Generation" tab
2. Select output format:
   - Raw Agent Code
   - Base64 Encoded
   - PowerShell Command
3. Click "Generate Agent"
4. Copy or save the generated payload

## Payload Configuration Options

### Common Configuration Parameters

| Parameter | Description | Typical Values |
|-----------|-------------|----------------|
| `beacon_period` | Time between check-ins (seconds) | 5-3600 |
| `jitter_percentage` | Randomization of beacon timing | 0-50 |
| `random_sleep_enabled` | Enable sleep between operations | true/false |
| `max_sleep_time` | Maximum sleep time (seconds) | 0-60 |
| `max_failures` | Failures before using fallback | 3-10 |
| `user_agent` | HTTP User-Agent header | Browser-like string |
| `proxy_enabled` | Enable proxy support | true/false |
| `proxy_type` | Type of proxy to use | system/http/socks4/socks5 |

### PowerShell Agent Specific Options

| Parameter | Description | Typical Values |
|-----------|-------------|----------------|
| `max_backoff_time` | Maximum time between reconnection attempts | 10-300 |
| `random_sleep_enabled` | Implement random sleeps for OPSEC | true/false |

### Output Formats

1. **Raw Agent Code**: Full source code of the agent
2. **Base64 Encoded**: Base64 encoded agent for command line execution
3. **PowerShell Command**: One-liner command for execution
4. **Custom Format**: Specified in custom plugins

## Custom Payload Plugin Development

### Step 1: Implement the Plugin Interface

Create a new Python file in the `plugins/agent_plugins` directory:

```python
from plugins.agent_plugin_interface import AgentPluginInterface
from typing import Dict, Any, List

class MyCustomPayload(AgentPluginInterface):
    @classmethod
    def get_name(cls) -> str:
        """Return the name of this agent type for UI display"""
        return "MyCustomPayload"
    
    @classmethod
    def get_description(cls) -> str:
        """Return a description of this agent type"""
        return "My custom payload implementation with specific capabilities"
    
    @classmethod
    def get_options(cls) -> Dict[str, Dict[str, Any]]:
        """Return configuration options for the agent"""
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
            # Add more configuration options as needed
        }
    
    @classmethod
    def get_agent_capabilities(cls) -> List[str]:
        """Return agent capabilities"""
        return [
            "file_operations", 
            "dynamic_path_rotation", 
            "secure_key_exchange"
        ]
    
    @classmethod
    def get_supported_platforms(cls) -> List[str]:
        """Return supported platforms"""
        return ["windows", "linux"]
    
    @classmethod
    def generate(cls, config: Dict[str, Any], campaign_settings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate the agent code
        
        Args:
            config: Configuration options
            campaign_settings: Campaign-wide settings
            
        Returns:
            Dictionary containing generated agent
        """
        # Extract configuration options
        beacon_interval = config.get("beacon_period", 5)
        jitter_percentage = config.get("jitter_percentage", 20)
        
        # Extract campaign settings
        server_address = campaign_settings.get("server_address", "")
        rotation_info = campaign_settings.get("rotation_info", None)
        
        # Generate your payload code here
        # This is where you implement your agent's functionality
        payload_code = f"""
        # Custom payload for {server_address}
        # Auto-generated by KCM
        
        function Connect-ToC2 {{
            # Your connection logic here
            # Implement beacon with {beacon_interval} seconds interval
            # Implement jitter of {jitter_percentage}%
        }}
        
        # Main code would go here
        """
        
        # Return the result
        return {
            "code": payload_code,
            "files": [],  # List of file paths if multiple files were generated
            "instructions": "Execute this payload on the target system",
            "summary": f"Custom payload for {server_address} with {beacon_interval}s beacon interval"
        }
```

### Step 2: Register Your Plugin

Update the plugin initialization in `plugins/__init__.py`:

```python
def initialize_plugin_system():
    from plugins.plugin_manager import get_plugin_manager
    from plugins.agent_plugins.powershell_agent_v2 import PowerShellAgentV2
    from plugins.agent_plugins.my_custom_payload import MyCustomPayload  # Import your plugin
    
    plugin_manager = get_plugin_manager()
    plugin_manager.register_plugin(PowerShellAgentV2)
    plugin_manager.register_plugin(MyCustomPayload)  # Register your plugin
    
    # Discover other plugins
    plugin_manager.discover_plugins()
```

### Step 3: Implement the Payload Template

Design your payload with these key components:

1. **Communication Protocol**: Implement the HTTP/HTTPS communication with the C2 server
2. **Encryption**: Implement AES-256-CBC encryption and RSA key exchange
3. **Command Processing**: Parse and execute commands from the server
4. **Path Rotation**: Handle dynamic path rotation for evasion
5. **Error Handling**: Implement robust error handling and recovery

For the actual payload code, use the embedded template mechanism:

```python
def _get_agent_template(cls) -> str:
    """Return the embedded agent template"""
    return """
    # Your full agent code template here
    # Use {{PLACEHOLDER}} syntax for variables to be replaced
    # For example:
    
    $serverAddress = '{{SERVER_ADDRESS}}'
    $beaconInterval = {{BEACON_INTERVAL}}
    $jitterPercentage = {{JITTER_PERCENTAGE}}
    
    # Rest of your agent code
    """
```

## Payload Testing and Troubleshooting

### Testing Process

1. **Local Testing**:
   - Generate the payload
   - Execute in a controlled environment
   - Verify connection to C2 server
   - Test basic command execution

2. **Debugging Tips**:
   - Enable debug mode in the agent configuration
   - Check server logs for connection attempts
   - Verify encryption and key exchange are working
   - Test path rotation by forcing rotation events

3. **Common Issues**:

| Issue | Possible Causes | Solutions |
|-------|----------------|-----------|
| Failed first contact | Network/firewall issues | Check connectivity, verify IP/port |
| Key exchange failure | RSA configuration issue | Verify public key availability |
| Command execution fails | Permission issues | Check agent execution context |
| Path rotation fails | Configuration or timing | Verify rotation interval settings |

## Advanced Techniques

### Custom Communication Channels

The default HTTP/HTTPS channels can be extended with:

1. **DNS Tunneling**: Implement DNS queries for data exfiltration
2. **Custom Protocol Handlers**: Create custom URI schemes
3. **Domain Fronting**: Route traffic through trusted domains

Example code snippet for implementing an alternative channel:

```python
def implement_dns_channel(domain, data):
    # Encode data into DNS queries
    chunks = [data[i:i+30] for i in range(0, len(data), 30)]
    results = []
    
    for i, chunk in enumerate(chunks):
        # Encode chunk into DNS-safe base32
        encoded = base64.b32encode(chunk.encode()).decode().lower()
        
        # Create DNS query format
        query = f"{i}.{encoded}.{domain}"
        
        # Perform DNS query and capture response
        # Code for DNS resolution goes here
        
        # Process response
        # Code for response handling goes here
        
    return results
```

### Persistence Mechanisms

Implement persistence with techniques like:

1. **Registry Keys**: For Windows payloads
2. **Scheduled Tasks/Cron Jobs**: For timed execution
3. **Service Installation**: Run as a system service
4. **WMI Event Subscriptions**: For advanced Windows persistence

### Anti-Detection Features

Enhance OPSEC with:

1. **Process Injection**: Execute within trusted processes
2. **Memory-Only Execution**: Avoid writing to disk
3. **API Unhooking**: Bypass EDR hooks
4. **AMSI Bypass**: Circumvent antimalware scanning
5. **Sandbox Detection**: Identify testing environments

## OPSEC Considerations

Always consider these operational security aspects:

1. **Network Signatures**: Minimize distinctive traffic patterns
2. **Host Artifacts**: Reduce forensic evidence on disk and in memory
3. **Detection Evasion**: Implement techniques to avoid security solutions
4. **Operational Workflow**: Follow secure procedures for deployment

### Beacon OPSEC Recommendations

| Setting | Recommended Value | Rationale |
|---------|-------------------|-----------|
| Beacon Period | >60 seconds | Reduce network signature |
| Jitter | 20-50% | Prevent timing analysis |
| Random Sleep | Enabled | Avoid detection patterns |
| User-Agent | Common browser | Blend with normal traffic |
| Kill Date | Set reasonable timeframe | Ensure limited lifetime |

## Additional Resources

- Refer to the PowerShellAgentV2 implementation for a complete example
- Study the core protocol and encryption implementations in the source code
- Explore the path rotation mechanism for evasion techniques
- Review the client identification and verification systems

---

*Note: This framework is intended for authorized security testing only. Always ensure proper authorization before deployment in any environment.*
