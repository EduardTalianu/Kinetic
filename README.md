# Kinetic Compliance Matrix

Kinetic Compliance Matrix (KCM) is a modular and extensible command and control (C2) framework designed for security testing and assessment purposes.

## Overview

KCM provides a flexible platform for managing client-server communications during security assessments, with features designed to improve stealth, reliability, and ease of use.

![KCM Logo](https://via.placeholder.com/150x150.png "Kinetic Compliance Matrix")

## Key Features

- **Graphical User Interface**: Intuitive interface for managing campaigns, clients, and operations
- **Dynamic Path Rotation**: Automatically rotates URL paths to evade detection
- **Secure Communications**: AES-256-CBC encryption with dynamic key rotation
- **Client Verification**: Multi-factor verification of client identities
- **Modular Architecture**: Easily extensible with new command modules
- **File Operations**: Built-in file upload and download capabilities
- **Certificate Management**: Generate and manage SSL/TLS certificates
- **Configurable Agents**: Customizable PowerShell agents with various connection options

## Installation

### Prerequisites

- Python 3.8 or higher
- Required Python packages:
  - cryptography
  - tkinter (usually comes with Python)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/your-username/kinetic-compliance-matrix.git
cd kinetic-compliance-matrix
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python main.py
```

## Quick Start Guide

### Creating a Campaign

1. Launch the application
2. In the "Campaign Config" tab:
   - Enter a campaign name or use the "Generate Name" button
   - Configure C&C IP and port
   - Enable SSL if desired
   - Configure path rotation settings
   - Click "Start Campaign"

### Configuring Agent Options

1. Navigate to the "Agent Config" tab
2. Configure the following settings:
   - Beacon Period: How often the agent checks in
   - Jitter Percentage: Random variation in timing
   - Kill Date: When the agent will stop functioning
   - Fallback & Recovery options
   - Proxy settings (if needed)
   - Click "Save Configuration"

### Generating Agents

1. Navigate to the "Agent Generation" tab
2. Select the desired agent type (PowerShell Base64)
3. Click "Generate Agents"
4. Copy the generated agent code to use on target systems

### Managing Clients

1. In the "Client Management" tab:
   - View connected clients
   - Double-click on a client to view details
   - Execute commands through the "Interaction" tab
   - Verify client identity in the "Verification" tab
   - Manage file transfers in the "Files" tab

## Architecture

KCM follows a modular design with the following components:

- **Core Modules**: Basic functionality for campaign management, client tracking, and communications
- **Handlers**: Process different types of client requests
- **Utils**: Utility functions for cryptography, path rotation, and other helper tasks
- **UI**: User interface components for the graphical application

## Security Considerations

KCM is designed for authorized security testing only. Misuse of this tool may violate applicable laws and regulations. Users are responsible for:

- Obtaining proper authorization before testing
- Complying with all relevant laws and regulations
- Using the tool responsibly and ethically

## Advanced Configuration

### Custom URL Patterns

You can customize URL patterns by modifying the files in the `helpers/links` directory:
- `links.txt`: Contains URL patterns
- `links2.txt`: Contains URL components

### Agent Customization

The agent behavior can be further customized by modifying templates in `helpers/powershell` directory:
- `agent.template.ps1`: Main agent template
- `path_rotation.template.ps1`: Path rotation mechanism
- `file_operations.template.ps1`: File transfer capabilities


## Disclaimer

This tool is provided for educational and legitimate security testing purposes only. The authors are not responsible for any misuse or damage caused by this program.
