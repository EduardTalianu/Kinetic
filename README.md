# Kinetic Compliance Matrix

A modular Command & Control (C2) platform designed for security professionals to simulate adversarial operations in controlled environments.

![Kinetic Compliance Matrix](https://via.placeholder.com/800x400?text=Kinetic+Compliance+Matrix)

## Overview

Kinetic Compliance Matrix is a Python-based C2 framework that provides a graphical interface for managing simulated cyber operations. It allows security teams to generate various agent payloads, manage client connections, and execute commands across multiple systems to test defensive controls and response procedures.

## Features

- **Campaign Management**: Create, configure, and monitor security testing campaigns
- **Multiple Agent Types**: Generate various payload types including PowerShell, HTA, and Office macros
- **Real-time Command Execution**: Execute commands on connected clients and view results in real-time
- **Centralized Logging**: Comprehensive logging system for tracking all events and command executions
- **Client Management**: Track and interact with multiple connected clients through an intuitive interface

## Installation

### Prerequisites

- Python 3.6+
- tkinter (usually included with Python)

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/kinetic-compliance-matrix.git
   cd kinetic-compliance-matrix
   ```

2. Install required packages:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python gui.py
   ```

## Usage

### Creating a Campaign

1. Launch the application
2. In the **Campaign Config** tab, configure:
   - Campaign Name
   - Command & Control IP
   - Port for C2 communication
   - Beacon period for agents
   - Kill date for campaign expiration
3. Click "Start Campaign" to initialize the C2 server

### Generating Agents

1. Navigate to the **Agent Generation** tab
2. Select the desired agent types
3. Click "Generate Agents"
4. Agents will be saved in the campaign folder for deployment

### Managing Clients

1. After clients connect to your C2 server, they will appear in the **Client Management** tab
2. Right-click on a client to:
   - Execute commands
   - View client details
   - Add custom commands

### Command Execution

1. Select a client from the client list
2. Right-click and select "Add Custom Command" or use one of the predefined commands
3. View command results in the client details tab

## Project Structure

```
kinetic-compliance-matrix/
├── core/
│   ├── agent_generation.py   # Agent payload generation
│   ├── campaign_config.py    # Campaign configuration management
│   ├── client_management.py  # Client tracking and command management
│   ├── cmd.py               # Command execution engine
│   ├── log_management.py    # Centralized logging system
│   └── webserver.py         # C2 server implementation
├── gui.py                   # Main application and UI controller
└── requirements.txt         # Project dependencies
```

## Logging

All operations, commands, and responses are logged in:
- The main GUI event viewer
- Campaign-specific log files in `[campaign_name]_campaign/logs/`
- Client-specific log files for tracking individual client activities

## Security Notice

This tool is designed for legitimate security testing by authorized security professionals. Only use in environments where you have explicit permission to conduct security testing.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- This tool was developed for educational and professional security testing purposes
- Inspired by various open-source C2 frameworks in the security community
