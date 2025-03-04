# Kinetic Compliance Matrix

A modular and extensible command and control (C2) framework for security testing and assessment purposes.

## Overview

Kinetic Compliance Matrix is a powerful yet user-friendly C2 framework designed for security professionals conducting authorized security assessments. The application provides a complete solution for creating, managing, and monitoring client connections within a campaign-based structure.

## Key Features

- **Intuitive GUI Interface**: Easy-to-use interface for campaign management and client interaction
- **Dynamic Path Rotation**: Automatic URL path rotation to evade detection
- **Client Identity Verification**: Sophisticated client verification using multiple system identifiers
- **Per-Client Encryption Keys**: Enhanced security with unique encryption keys per verified client
- **PowerShell Agent Generation**: Built-in PowerShell agent creation with customizable options
- **Interactive Command Console**: Real-time interaction with connected clients
- **Campaign Management**: Create, save, and load campaigns with comprehensive settings
- **TLS/SSL Support**: Optional secure communications with custom certificates
- **Comprehensive Logging**: Detailed event logging for all client activities

## Components

- **Campaign Configuration**: Set up campaign parameters including C2 server details, paths, and security options
- **Agent Generation**: Create customized agents with proper encryption and communication settings
- **Client Management**: Monitor connected clients with detailed system information
- **Interactive Console**: Execute commands and view results in real-time
- **Client Verification**: Monitor trust levels and manage per-client encryption

## Getting Started

1. Launch the application
2. Configure a new campaign with desired settings
3. Start the campaign to initialize the C2 server
4. Generate client agents using the Agent Generation tab
5. Deploy agents to target systems (for authorized testing only)
6. Manage and interact with connected clients through the Client Management tab

## Security Features

- **AES-256-CBC Encryption**: All communications are encrypted using industry-standard encryption
- **Identity Verification**: Clients are verified using multiple system identifiers to prevent session hijacking
- **Dynamic Path Rotation**: Paths change at configurable intervals to evade detection
- **Per-Client Key Rotation**: Verified clients receive unique encryption keys for enhanced security

## Important Note

This tool is designed for legitimate security testing purposes only. Always ensure you have proper authorization before deploying agents in any environment. Unauthorized use may violate local laws and regulations.

## Requirements

- Python 3.6+
- Required packages:
  - tkinter
  - cryptography
  - socket
  - datetime
  - json

## Usage

Run `python main.py` to start the application. Command-line options:

```
--headless       Run in headless mode (no GUI)
--campaign       Campaign name to automatically load
--config         Path to config file
--debug          Enable debug logging
```

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this software. Always obtain proper authorization before conducting security assessments.
