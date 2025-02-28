# Kinetic Compliance Matrix

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.6%2B-brightgreen)

Kinetic Compliance Matrix is a lightweight, modular command and control (C2) framework designed for security assessments and red team operations. It features a GUI interface for campaign management, multiple agent generation options, and a simple yet effective client management system.

## Features

- **User-friendly GUI Interface**: Manage your operations through an intuitive graphical interface
- **Flexible Campaign Configuration**: Customize C2 communication settings with options for SSL/TLS
- **Multiple Agent Types**: Generate various agent types for different use cases:
  - HTA Agents
  - PowerShell-based Agents (Job, File, SCT, Base64, Base52)
  - Microsoft Office Macro Agents (Word, Excel)
  - Shellcode-based Agents
  - Follina exploit Agent
- **Client Management**: Track connected clients, issue commands, and view command history
- **Modular Design**: Easy to extend with additional modules and capabilities

## Screenshots

*[Add screenshots of the GUI interface here]*

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/kinetic-compliance-matrix.git
cd kinetic-compliance-matrix
```

2. Install required dependencies:

```bash
pip install -r requirements.txt
```

3. Run the application:

```bash
python gui.py
```

## Usage Guide

### Campaign Configuration

1. In the "Campaign Config" tab, enter your campaign details:
   - Campaign Name
   - C2 IP Address (select from dropdown or enter manually)
   - Port
   - Beacon Period (in seconds)
   - Kill Date (DD/MM/YYYY format)
   - SSL options (if applicable)

2. Click "Start Campaign" to create a campaign folder and start the C2 server.

### Agent Generation

1. Navigate to the "Agent Generation" tab
2. Select the agent types you want to generate
3. Click "Generate Agents" to create the selected agents
4. Agent command strings and files will be generated in your campaign folder

### Client Management

1. The "Client Management" tab shows connected clients
2. Select a client to view its command history
3. Add new commands to specific clients:
   - Execute: Run PowerShell commands
   - Upload: Transfer files to the client

## Agent Types

### PowerShell Agents

- **PowerShell Job**: Runs the agent in a background job
- **PowerShell File**: Creates a file-based agent
- **PowerShell SCT**: Generates a COM Scriptlet-based agent
- **PowerShell Base64/Base52**: Obfuscated payload variations

### Application Specific

- **HTA Agent**: HTML Application for phishing scenarios
- **Word/Excel Macro**: Office macro-based agents
- **Follina Agent**: Exploits MS-MSDT vulnerability

### Native Code

- **CMD Shellcode**: Shellcode execution agents (x86/x64)

## Architecture

The framework consists of several core components:

- **GUI Module**: Main interface built with Tkinter
- **Campaign Config**: Manages campaign settings and webserver
- **Client Management**: Tracks clients and handles command issuing
- **Agent Generation**: Produces various agent types
- **Webserver**: Handles C2 communication with agents

## Security Considerations

This tool is designed for legitimate security testing with proper authorization. Unauthorized use against systems you don't own or have permission to test is illegal and unethical.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This software is provided for educational and legitimate security testing purposes only. The authors are not responsible for any misuse or damage caused by this program. Always ensure you have explicit permission before testing any system.
