# Kinetic

## Command and Control Framework for Security Testing

Kinetic is a modular and extensible command and control (C2) framework designed for security testing and assessment purposes. This tool provides a comprehensive platform for managing client connections, executing commands, and gathering system information during authorized security assessments.

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.6+-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)

## Features

### Core Functionality
- **Modular C2 Architecture**: Extensible design with separate handlers for different endpoints
- **GUI Interface**: Clean Tkinter-based interface for ease of use
- **PowerShell Agents**: Generates obfuscated PowerShell agents with customizable parameters
- **Client Management**: Robust tracking and management of connected clients
- **Command Execution**: Execute and monitor commands on connected systems
- **File Operations**: Upload and download capabilities between server and clients

### Security Features
- **AES-256 Encryption**: All communications encrypted using AES-256-CBC
- **Key Rotation**: Periodic or on-demand cryptographic key rotation
- **Client Verification**: Multifactor verification of client identity
- **Path Rotation**: Dynamic URL path rotation to evade detection
- **SSL Support**: Optional SSL/TLS encryption for secure communications
- **Self-Signed Certificates**: Built-in certificate generation for secure communications

### Web Traffic Features
- **JPEG Headers**: Communications disguised as image traffic
- **Variable Padding**: Random content size to avoid pattern detection
- **Common Web Patterns**: URL paths follow common web application patterns
- **Legitimate Headers**: Web requests use legitimate browser headers
- **HTTP/HTTPS**: Support for both HTTP and HTTPS communications

### Operational Security
- **Campaign Management**: Organize operations into separate campaigns
- **Logs and Events**: Comprehensive logging of all actions and events
- **Kill Date**: Automatic disabling of agents after specified date
- **Beacon Jitter**: Variable timing to avoid detection
- **Connection Recovery**: Automatic recovery from lost connections

## Installation

### Requirements
- Python 3.6+
- Required Python packages:
  - cryptography
  - tkinter (usually included with Python)
  - pathlib

### Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/kinetic-compliance-matrix.git
   cd kinetic-compliance-matrix
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python3 main.py
   ```

## Usage Guide

### Campaign Configuration

1. **Create a Campaign**:
   - In the "Campaign Config" tab, enter a campaign name or use the "Generate Name" button
   - Set the C&C server IP and port
   - Configure URL paths (randomized by default)
   - Enable/disable path rotation and set rotation interval
   - Enable SSL if desired and provide certificate/key paths

2. **Configure Agent Parameters** (Agent Config tab):
   - Set beacon period (how often clients check in)
   - Configure jitter percentage for timing randomization
   - Set kill date for automatic agent expiration
   - Configure connection failure handling parameters

3. **Start Campaign**:
   - Click "Start Campaign" to initialize the C2 server
   - The server will start listening for connections on the specified IP and port

### Agent Generation

1. **Generate Agent**:
   - In the "Agent Generation" tab, select the desired agent type
   - Click "Generate Agents" to create agent code
   - The generated PowerShell Base64 agent can be executed on target systems

2. **Deployment Methods**:
   - Execute the Base64 command directly in PowerShell
   - Use the command in scripts, scheduled tasks, or other execution methods

### Client Management

1. **Monitoring Clients**:
   - The "Client Management" tab displays all connected clients
   - View client details including hostname, IP, OS version, and verification status

2. **Client Interaction**:
   - Double-click a client to open detailed view
   - Use the "Interaction" tab to send commands
   - Use quick command buttons or enter custom commands
   - View command history and results

3. **File Operations**:
   - In the client's "Files" tab, upload files to the client
   - Download files from the client system
   - Browse directories on the client system

### Certificate Management

1. **Generate Certificates**:
   - Use the "Certificate Management" tab to create self-signed certificates
   - Set certificate parameters including validity period and organization details
   - Use generated certificates for SSL/TLS connections

## Architecture

### Core Components

- **MainGUI (app.py)**: Main application GUI and initialization
- **ClientManager (client.py)**: Tracks and manages client connections
- **C2RequestHandler (c2_handler.py)**: HTTP request handler for C2 communications
- **CryptoManager & CryptoHelper (crypto.py, crypto_operations.py)**: Handles encryption/decryption
- **LogManager (logging.py)**: Manages logging and event tracking
- **PathRotationManager (path_rotation.py)**: Manages dynamic URL path rotation

### Handler Components

- **BeaconHandler**: Processes beacon requests from clients
- **AgentHandler**: Delivers agent code to clients
- **ResultHandler**: Processes command results from clients
- **FileHandler**: Manages file uploads from clients
- **FileDownloadHandler**: Manages file downloads to clients

### Client-Side Components

- **PowerShell Agent**: Communicates with C2 server, executes commands, handles encryption
- **Path Rotation**: Client-side handling of dynamic paths
- **System Identification**: Gathers and reports system information
- **Command Execution**: Executes commands and returns results

## Security Considerations

- **Authorization**: Only use this tool on systems you are authorized to test
- **Legal Compliance**: Ensure compliance with all applicable laws and regulations
- **Operational Security**: Be aware of network monitoring and detection capabilities
- **Data Protection**: Protect collected data according to organizational policies
- **Attribution**: The tool may not completely prevent attribution of activities

## File Structure

```
kinetic-compliance-matrix/
├── core/
│   ├── app.py              # Main application
│   ├── campaign.py         # Campaign management
│   ├── client.py           # Client management
│   ├── cmd.py              # Command execution
│   ├── config.py           # Configuration management
│   ├── crypto.py           # Cryptography operations
│   ├── crypto_operations.py # Helper crypto functions
│   ├── logging.py          # Logging functionality
│   ├── path_routing.py     # URL path routing
│   └── server.py           # Web server implementation
├── handlers/
│   ├── agent_handler.py    # Agent delivery handler
│   ├── base_handler.py     # Base request handler
│   ├── beacon_handler.py   # Client beacon handler
│   ├── file_download_handler.py # File download handler
│   ├── file_handler.py     # File upload handler
│   └── result_handler.py   # Command result handler
├── helpers/
│   ├── links/              # URL pattern configuration
│   └── powershell/         # PowerShell templates
├── ui/
│   ├── agent_config_tab.py # Agent configuration UI
│   ├── agent_tab.py        # Agent generation UI
│   ├── campaign_tab.py     # Campaign configuration UI
│   ├── certificate_tab.py  # Certificate management UI
│   ├── client_details.py   # Client details UI
│   ├── client_files.py     # Client file operations UI
│   ├── client_interaction.py # Client command UI
│   ├── client_list.py      # Client listing UI
│   └── client_tab.py       # Client management UI
├── utils/
│   ├── agent_generator.py  # Agent code generator
│   ├── certificate_generator.py # Certificate generator
│   ├── client_identity.py  # Client identification
│   ├── c2_handler.py       # C2 request handler
│   └── path_rotation.py    # Path rotation management
├── main.py                 # Application entry point
└── README.md               # This file
```

## Development

### Extending Functionality

1. **Adding New Agent Types**:
   - Create a new template in the `helpers/` directory
   - Add agent generation function in `utils/agent_generator.py`
   - Update UI in `ui/agent_tab.py` to include the new agent type

2. **Adding New Command Types**:
   - Implement command handling in the PowerShell agent template
   - Add command processing in the relevant handler (usually `result_handler.py`)
   - Update UI as needed to expose the new command

3. **Adding New Features**:
   - Follow the modular design pattern when adding new functionality
   - Ensure proper handling of encryption and client identification
   - Update UI components to expose new features

### Coding Standards

- Follow PEP 8 style guidelines for Python code
- Use meaningful variable and function names
- Document code with docstrings
- Handle exceptions appropriately
- Validate input and sanitize output

## Troubleshooting

### Common Issues

1. **Connection Problems**:
   - Verify server IP and port configuration
   - Check firewall settings on both server and client
   - Ensure network connectivity between server and client

2. **SSL Certificate Issues**:
   - Verify certificate and key paths
   - Generate new certificates if necessary
   - Ensure certificate validation is properly configured

3. **Agent Execution Errors**:
   - Check PowerShell execution policy on client
   - Verify network connectivity to C2 server
   - Check for security software blocking execution

4. **GUI Issues**:
   - Verify Tkinter is properly installed
   - Check for Python version compatibility
   - Look for errors in application logs

## License

This software is provided under the MIT License. See the LICENSE file for details.

## Disclaimer

This tool is designed for legitimate security testing and assessment purposes only. Use only on systems and networks you are authorized to test. Unauthorized use of this tool against systems without explicit permission is illegal and unethical.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Acknowledgments

- This project is created for educational and professional security testing purposes
- Inspired by various open-source security tools and frameworks
- Thanks to all contributors and the security research community

---

© 2025 Kinetic Compliance Matrix Contributors
